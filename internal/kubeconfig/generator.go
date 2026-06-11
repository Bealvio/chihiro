package kubeconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/Bealvio/chihiro/internal/capi"
	"github.com/Bealvio/chihiro/internal/watcher"
)

type Generator struct {
	client   dynamic.Interface
	resolver *capi.Resolver
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	CAData       string
	Username     string
	Groups       []string
}

type KubeconfigData struct {
	ClusterName     string
	ServerURL       string
	CertificateData string
	OIDCConfig      *OIDCConfig
}

func NewGenerator(client dynamic.Interface, resolver *capi.Resolver) *Generator {
	slog.Info("Initializing kubeconfig generator")
	return &Generator{
		client:   client,
		resolver: resolver,
	}
}

func (g *Generator) GenerateKubeconfig(
	ctx context.Context,
	cluster *watcher.ClusterInfo,
	username string,
	userGroups []string,
) (string, error) {
	slog.Info(
		"Generating kubeconfig",
		"cluster_name",
		cluster.Name,
		"namespace",
		cluster.Namespace,
		"username",
		username,
		"user_groups",
		userGroups,
	)

	// Get control plane information (provider-agnostic, resolved from the
	// Cluster's controlPlaneRef).
	controlPlane, err := g.getControlPlane(ctx, cluster)
	if err != nil {
		slog.Error("Failed to get control plane", "cluster_name", cluster.Name, "namespace", cluster.Namespace, "error", err)
		return "", fmt.Errorf("failed to generate kubeconfig")
	}

	// Extract OIDC configuration from the control plane
	oidcConfig, err := g.extractOIDCConfig(controlPlane)
	if err != nil {
		slog.Error("Failed to extract OIDC config", "cluster_name", cluster.Name, "error", err)
		return "", fmt.Errorf("failed to generate kubeconfig")
	}

	// Get cluster endpoint from cluster spec
	serverURL, err := g.getClusterEndpoint(cluster)
	if err != nil {
		slog.Error("Failed to get cluster endpoint", "cluster_name", cluster.Name, "error", err)
		return "", fmt.Errorf("failed to generate kubeconfig")
	}

	// Skip CA data - using insecure-skip-tls-verify instead
	caData := ""

	kubeconfigData := &KubeconfigData{
		ClusterName:     cluster.Name,
		ServerURL:       serverURL,
		CertificateData: caData,
		OIDCConfig: &OIDCConfig{
			IssuerURL:    oidcConfig.IssuerURL,
			ClientID:     oidcConfig.ClientID,
			ClientSecret: oidcConfig.ClientSecret,
			Username:     username,
			Groups:       userGroups,
		},
	}

	kubeconfigContent := g.renderKubeconfig(kubeconfigData)
	slog.Info(
		"Successfully generated kubeconfig",
		"cluster_name",
		cluster.Name,
		"username",
		username,
		"server_url",
		serverURL,
		"issuer_url",
		oidcConfig.IssuerURL,
		"size_bytes",
		len(kubeconfigContent),
	)

	return kubeconfigContent, nil
}

// getControlPlane resolves and fetches the control plane object referenced by
// the Cluster's spec.controlPlaneRef. The control plane kind is read from the
// ref and the GVR is resolved via discovery (using apiVersion when present),
// so chihiro does not depend on any particular control plane provider (Kamaji,
// kubeadm, etc.).
func (g *Generator) getControlPlane(ctx context.Context, cluster *watcher.ClusterInfo) (*unstructured.Unstructured, error) {
	slog.Debug("Getting control plane for cluster", "cluster_name", cluster.Name, "namespace", cluster.Namespace)

	// Fetch the cluster object fresh and read controlPlaneRef from its spec.
	// The control plane reference lives in spec (not status), so kubeconfig
	// generation does not depend on the cluster's status being populated.
	gvr, err := g.resolver.ClusterGVR()
	if err != nil {
		slog.Error("Failed to resolve Cluster API version", "cluster_name", cluster.Name, "error", err)
		return nil, fmt.Errorf("failed to resolve Cluster API version: %v", err)
	}

	clusterObj, err := g.client.Resource(gvr).Namespace(cluster.Namespace).Get(ctx, cluster.Name, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster object", "cluster_name", cluster.Name, "namespace", cluster.Namespace, "error", err)
		return nil, fmt.Errorf("failed to get cluster object: %v", err)
	}

	spec, ok := clusterObj.Object["spec"].(map[string]interface{})
	if !ok {
		slog.Error("Cluster spec not found or invalid", "cluster_name", cluster.Name)
		return nil, fmt.Errorf("cluster spec not found")
	}

	controlPlaneRef, ok := spec["controlPlaneRef"].(map[string]interface{})
	if !ok {
		slog.Error("Control plane reference not found in cluster spec", "cluster_name", cluster.Name)
		return nil, fmt.Errorf("controlPlaneRef not found in cluster spec")
	}

	cpName, ok := controlPlaneRef["name"].(string)
	if !ok {
		slog.Error("Control plane name not found", "cluster_name", cluster.Name)
		return nil, fmt.Errorf("control plane name not found")
	}

	cpKind, ok := controlPlaneRef["kind"].(string)
	if !ok || cpKind == "" {
		slog.Error("Control plane kind not found in controlPlaneRef", "cluster_name", cluster.Name)
		return nil, fmt.Errorf("control plane kind not found in controlPlaneRef")
	}

	cpNamespace, ok := controlPlaneRef["namespace"].(string)
	if !ok {
		cpNamespace = cluster.Namespace // Use cluster namespace as fallback
		slog.Debug("Using cluster namespace for control plane", "cluster_name", cluster.Name, "namespace", cpNamespace)
	} else {
		slog.Debug("Found control plane namespace", "cluster_name", cluster.Name, "cp_name", cpName, "cp_namespace", cpNamespace)
	}

	// Resolve the control plane GVR. If apiVersion is present in the ref, use
	// it directly. Otherwise discover the version from the CAPI control plane
	// group using only the kind — some CAPI configurations omit apiVersion.
	cpAPIVersion, _ := controlPlaneRef["apiVersion"].(string)

	var cpGVR schema.GroupVersionResource
	if cpAPIVersion != "" {
		cpGVR, err = g.resolver.GVRForKind(cpAPIVersion, cpKind)
	} else {
		cpGVR, err = g.resolver.GVRForControlPlaneKind(cpKind)
	}
	if err != nil {
		slog.Error("Failed to resolve control plane resource", "cluster_name", cluster.Name, "cp_kind", cpKind, "cp_api_version", cpAPIVersion, "error", err)
		return nil, fmt.Errorf("failed to resolve control plane resource: %v", err)
	}

	controlPlane, err := g.client.Resource(cpGVR).Namespace(cpNamespace).Get(ctx, cpName, metav1.GetOptions{})
	if err != nil {
		slog.Error(
			"Failed to get control plane resource",
			"cluster_name",
			cluster.Name,
			"cp_name",
			cpName,
			"cp_namespace",
			cpNamespace,
			"cp_kind",
			cpKind,
			"error",
			err,
		)
		return nil, fmt.Errorf("failed to get control plane: %v", err)
	}

	slog.Debug("Successfully retrieved control plane", "cluster_name", cluster.Name, "cp_name", cpName, "cp_namespace", cpNamespace, "cp_kind", cpKind)
	return controlPlane, nil
}

func (g *Generator) extractOIDCConfig(controlPlane *unstructured.Unstructured) (*OIDCConfig, error) {
	// Debug: log the entire control plane structure
	cpBytes, _ := json.MarshalIndent(controlPlane.Object, "", "  ")
	slog.Debug(
		"Control plane structure",
		"cluster",
		controlPlane.GetName(),
		"namespace",
		controlPlane.GetNamespace(),
		"kind",
		controlPlane.GetKind(),
		"structure",
		string(cpBytes),
	)

	spec, ok := controlPlane.Object["spec"].(map[string]interface{})
	if !ok {
		slog.Error("Control plane spec not found or invalid", "cluster", controlPlane.GetName())
		return nil, fmt.Errorf("control plane spec not found")
	}

	slog.Debug("Control plane spec keys", "cluster", controlPlane.GetName(), "keys", getKeys(spec))

	oidcConfig := &OIDCConfig{}

	// Try multiple paths to find OIDC configuration
	// Path 1: Direct OIDC configuration in spec
	if oidc, ok := spec["oidc"].(map[string]interface{}); ok {
		if issuerURL, ok := oidc["issuerURL"].(string); ok {
			oidcConfig.IssuerURL = issuerURL
		}
		if clientID, ok := oidc["clientID"].(string); ok {
			oidcConfig.ClientID = clientID
		}
		if clientSecret, ok := oidc["clientSecret"].(string); ok {
			oidcConfig.ClientSecret = clientSecret
		}
	}

	// Path 2: API server extra args (array of strings)
	if apiServer, ok := spec["apiServer"].(map[string]interface{}); ok {
		slog.Debug("Found API server config", "cluster", controlPlane.GetName(), "keys", getKeys(apiServer))
		if extraArgs, ok := apiServer["extraArgs"].([]interface{}); ok {
			slog.Debug("Found API server extra args", "cluster", controlPlane.GetName(), "count", len(extraArgs))
			for i, arg := range extraArgs {
				if argStr, ok := arg.(string); ok {
					slog.Debug("Processing API server arg", "cluster", controlPlane.GetName(), "index", i, "arg", argStr)
					// Parse arguments like "--oidc-issuer-url=https://zitadel.bealv.io"
					if after, ok0 := strings.CutPrefix(argStr, "--oidc-issuer-url="); ok0 {
						oidcConfig.IssuerURL = after
						slog.Debug("Found OIDC issuer URL", "cluster", controlPlane.GetName(), "issuer_url", oidcConfig.IssuerURL)
					} else if after0, ok1 := strings.CutPrefix(argStr, "--oidc-client-id="); ok1 {
						oidcConfig.ClientID = after0
						slog.Debug("Found OIDC client ID", "cluster", controlPlane.GetName(), "client_id", oidcConfig.ClientID)
					} else if after1, ok2 := strings.CutPrefix(argStr, "--oidc-client-secret="); ok2 {
						oidcConfig.ClientSecret = after1
						slog.Debug("Found OIDC client secret", "cluster", controlPlane.GetName())
					}
				} else if argMap, ok := arg.(map[string]interface{}); ok {
					// Fallback: handle object format
					if name, ok := argMap["name"].(string); ok {
						if value, ok := argMap["value"].(string); ok {
							switch name {
							case "oidc-issuer-url":
								oidcConfig.IssuerURL = value
							case "oidc-client-id":
								oidcConfig.ClientID = value
							case "oidc-client-secret":
								oidcConfig.ClientSecret = value
							}
						}
					}
				}
			}
		}

		// Path 3: API server extraArgs as map
		if extraArgsMap, ok := apiServer["extraArgs"].(map[string]interface{}); ok {
			if issuerURL, ok := extraArgsMap["oidc-issuer-url"].(string); ok {
				oidcConfig.IssuerURL = issuerURL
			}
			if clientID, ok := extraArgsMap["oidc-client-id"].(string); ok {
				oidcConfig.ClientID = clientID
			}
			if clientSecret, ok := extraArgsMap["oidc-client-secret"].(string); ok {
				oidcConfig.ClientSecret = clientSecret
			}
		}
	}

	// Path 4: Check status for OIDC configuration
	if status, ok := controlPlane.Object["status"].(map[string]interface{}); ok {
		if oidc, ok := status["oidc"].(map[string]interface{}); ok {
			if issuerURL, ok := oidc["issuerURL"].(string); ok && oidcConfig.IssuerURL == "" {
				oidcConfig.IssuerURL = issuerURL
			}
			if clientID, ok := oidc["clientID"].(string); ok && oidcConfig.ClientID == "" {
				oidcConfig.ClientID = clientID
			}
			if clientSecret, ok := oidc["clientSecret"].(string); ok && oidcConfig.ClientSecret == "" {
				oidcConfig.ClientSecret = clientSecret
			}
		}
	}

	// Validate required OIDC fields
	if oidcConfig.IssuerURL == "" || oidcConfig.ClientID == "" {
		slog.Error(
			"Required OIDC configuration missing",
			"cluster",
			controlPlane.GetName(),
			"issuer_url",
			oidcConfig.IssuerURL,
			"client_id",
			oidcConfig.ClientID,
		)
		return nil, fmt.Errorf(
			"required OIDC configuration not found (issuerURL: %q, clientID: %q)",
			oidcConfig.IssuerURL,
			oidcConfig.ClientID,
		)
	}

	slog.Info(
		"Successfully extracted OIDC configuration",
		"cluster",
		controlPlane.GetName(),
		"issuer_url",
		oidcConfig.IssuerURL,
		"client_id",
		oidcConfig.ClientID,
	)
	return oidcConfig, nil
}

func (g *Generator) getClusterEndpoint(cluster *watcher.ClusterInfo) (string, error) {
	slog.Debug("Getting cluster endpoint", "cluster_name", cluster.Name)

	// Use the external API server endpoint advertised by CAPI. chihiro does not
	// construct or guess the host: the control plane endpoint is the source of
	// truth, populated once the infrastructure provider exposes it.
	if cluster.APIEndpoint != "" {
		slog.Debug("Using cluster API endpoint", "cluster_name", cluster.Name, "endpoint", cluster.APIEndpoint)
		return cluster.APIEndpoint, nil
	}

	if cluster.Status != nil {
		if controlPlaneEndpoint, ok := cluster.Status["controlPlaneEndpoint"].(map[string]interface{}); ok {
			if host, ok := controlPlaneEndpoint["host"].(string); ok && host != "" {
				if port, ok := controlPlaneEndpoint["port"].(float64); ok {
					endpoint := fmt.Sprintf("https://%s:%.0f", host, port)
					slog.Debug("Found endpoint from cluster status", "cluster_name", cluster.Name, "endpoint", endpoint)
					return endpoint, nil
				}
			}
		}
	}

	slog.Error("No control plane endpoint available for cluster", "cluster_name", cluster.Name)
	return "", fmt.Errorf("control plane endpoint not available for cluster %q", cluster.Name)
}

func (g *Generator) renderKubeconfig(data *KubeconfigData) string {
	// Build cluster configuration - using public CA, no need for custom certificate-authority-data
	clusterConfig := fmt.Sprintf("    server: %s", data.ServerURL)

	// SECURITY: Do NOT expose the client secret in generated kubeconfig files
	// Users should configure their client secret locally or use PKCE flow
	template := `apiVersion: v1
kind: Config
clusters:
- cluster:
    %s
  name: %s
contexts:
- context:
    cluster: %s
    namespace: %s
    user: %s
  name: %s
current-context: %s
users:
- name: %s
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url=%s
      - --oidc-client-id=%s
      - --oidc-extra-scope=email
      - --oidc-extra-scope=profile
      - --oidc-extra-scope=groups
      # IMPORTANT: Set OIDC_CLIENT_SECRET environment variable or use --oidc-client-secret flag
      # DO NOT hardcode secrets in kubeconfig files
`

	contextName := data.ClusterName
	userName := fmt.Sprintf("%s-oidc", data.OIDCConfig.Username)
	namespace := fmt.Sprintf("%s-kube-user-default", data.ClusterName)

	return fmt.Sprintf(template,
		clusterConfig,             // cluster configuration
		data.ClusterName,          // cluster name
		data.ClusterName,          // context cluster
		namespace,                 // context namespace
		userName,                  // context user
		contextName,               // context name
		contextName,               // current-context
		userName,                  // user name
		data.OIDCConfig.IssuerURL, // oidc-issuer-url
		data.OIDCConfig.ClientID,  // oidc-client-id
	)
}

func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

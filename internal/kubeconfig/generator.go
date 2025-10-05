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

	"github.com/Bealvio/chihiro/internal/watcher"
)

type Generator struct {
	client dynamic.Interface
}

type OIDCConfig struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	CAData        string
	Username      string
	Groups        []string
}

type KubeconfigData struct {
	ClusterName     string
	ServerURL       string
	CertificateData string
	OIDCConfig      *OIDCConfig
}

func NewGenerator(client dynamic.Interface) *Generator {
	slog.Info("Initializing kubeconfig generator")
	return &Generator{
		client: client,
	}
}

func (g *Generator) GenerateKubeconfig(ctx context.Context, cluster *watcher.ClusterInfo, username string, userGroups []string) (string, error) {
	slog.Info("Generating kubeconfig", "cluster_name", cluster.Name, "namespace", cluster.Namespace, "username", username, "user_groups", userGroups)

	// Get Kamaji control plane information
	kamajiCP, err := g.getKamajiControlPlane(ctx, cluster)
	if err != nil {
		slog.Error("Failed to get Kamaji control plane", "cluster_name", cluster.Name, "namespace", cluster.Namespace, "error", err)
		return "", fmt.Errorf("failed to generate kubeconfig")
	}

	// Extract OIDC configuration from Kamaji control plane
	oidcConfig, err := g.extractOIDCConfig(kamajiCP)
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
	slog.Info("Successfully generated kubeconfig", "cluster_name", cluster.Name, "username", username, "server_url", serverURL, "issuer_url", oidcConfig.IssuerURL, "size_bytes", len(kubeconfigContent))

	return kubeconfigContent, nil
}

func (g *Generator) getKamajiControlPlane(ctx context.Context, cluster *watcher.ClusterInfo) (*unstructured.Unstructured, error) {
	slog.Debug("Getting Kamaji control plane for cluster", "cluster_name", cluster.Name, "namespace", cluster.Namespace)

	// Get the control plane reference from cluster spec
	if cluster.Status == nil {
		slog.Error("Cluster status is nil", "cluster_name", cluster.Name)
		return nil, fmt.Errorf("cluster status is nil")
	}

	// Look for controlPlaneRef in cluster spec via the stored cluster object
	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
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

	cpNamespace, ok := controlPlaneRef["namespace"].(string)
	if !ok {
		cpNamespace = cluster.Namespace // Use cluster namespace as fallback
		slog.Debug("Using cluster namespace for control plane", "cluster_name", cluster.Name, "namespace", cpNamespace)
	} else {
		slog.Debug("Found control plane namespace", "cluster_name", cluster.Name, "cp_name", cpName, "cp_namespace", cpNamespace)
	}

	// Get Kamaji control plane
	kamajiGVR := schema.GroupVersionResource{
		Group:    "controlplane.cluster.x-k8s.io",
		Version:  "v1alpha1",
		Resource: "kamajicontrolplanes",
	}

	kamajiCP, err := g.client.Resource(kamajiGVR).Namespace(cpNamespace).Get(ctx, cpName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get Kamaji control plane resource", "cluster_name", cluster.Name, "cp_name", cpName, "cp_namespace", cpNamespace, "error", err)
		return nil, fmt.Errorf("failed to get Kamaji control plane: %v", err)
	}

	slog.Debug("Successfully retrieved Kamaji control plane", "cluster_name", cluster.Name, "cp_name", cpName, "cp_namespace", cpNamespace)
	return kamajiCP, nil
}

func (g *Generator) extractOIDCConfig(kamajiCP *unstructured.Unstructured) (*OIDCConfig, error) {
	// Debug: log the entire Kamaji control plane structure
	cpBytes, _ := json.MarshalIndent(kamajiCP.Object, "", "  ")
	slog.Debug("Kamaji control plane structure", "cluster", kamajiCP.GetName(), "namespace", kamajiCP.GetNamespace(), "structure", string(cpBytes))

	spec, ok := kamajiCP.Object["spec"].(map[string]interface{})
	if !ok {
		slog.Error("Kamaji control plane spec not found or invalid", "cluster", kamajiCP.GetName())
		return nil, fmt.Errorf("Kamaji control plane spec not found")
	}

	slog.Debug("Kamaji control plane spec keys", "cluster", kamajiCP.GetName(), "keys", getKeys(spec))

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
		slog.Debug("Found API server config", "cluster", kamajiCP.GetName(), "keys", getKeys(apiServer))
		if extraArgs, ok := apiServer["extraArgs"].([]interface{}); ok {
			slog.Debug("Found API server extra args", "cluster", kamajiCP.GetName(), "count", len(extraArgs))
			for i, arg := range extraArgs {
				if argStr, ok := arg.(string); ok {
					slog.Debug("Processing API server arg", "cluster", kamajiCP.GetName(), "index", i, "arg", argStr)
					// Parse arguments like "--oidc-issuer-url=https://zitadel.bealv.io"
					if strings.HasPrefix(argStr, "--oidc-issuer-url=") {
						oidcConfig.IssuerURL = strings.TrimPrefix(argStr, "--oidc-issuer-url=")
						slog.Debug("Found OIDC issuer URL", "cluster", kamajiCP.GetName(), "issuer_url", oidcConfig.IssuerURL)
					} else if strings.HasPrefix(argStr, "--oidc-client-id=") {
						oidcConfig.ClientID = strings.TrimPrefix(argStr, "--oidc-client-id=")
						slog.Debug("Found OIDC client ID", "cluster", kamajiCP.GetName(), "client_id", oidcConfig.ClientID)
					} else if strings.HasPrefix(argStr, "--oidc-client-secret=") {
						oidcConfig.ClientSecret = strings.TrimPrefix(argStr, "--oidc-client-secret=")
						slog.Debug("Found OIDC client secret", "cluster", kamajiCP.GetName())
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
	if status, ok := kamajiCP.Object["status"].(map[string]interface{}); ok {
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
		slog.Error("Required OIDC configuration missing", "cluster", kamajiCP.GetName(), "issuer_url", oidcConfig.IssuerURL, "client_id", oidcConfig.ClientID)
		return nil, fmt.Errorf("required OIDC configuration not found (issuerURL: %q, clientID: %q)", oidcConfig.IssuerURL, oidcConfig.ClientID)
	}

	slog.Info("Successfully extracted OIDC configuration", "cluster", kamajiCP.GetName(), "issuer_url", oidcConfig.IssuerURL, "client_id", oidcConfig.ClientID)
	return oidcConfig, nil
}

func (g *Generator) getClusterEndpoint(cluster *watcher.ClusterInfo) (string, error) {
	slog.Debug("Getting cluster endpoint", "cluster_name", cluster.Name)

	// First try to extract endpoint from cluster status
	if cluster.Status != nil {
		if controlPlaneEndpoint, ok := cluster.Status["controlPlaneEndpoint"].(map[string]interface{}); ok {
			if host, ok := controlPlaneEndpoint["host"].(string); ok {
				if port, ok := controlPlaneEndpoint["port"].(float64); ok {
					endpoint := fmt.Sprintf("https://%s:%.0f", host, port)
					slog.Debug("Found endpoint from cluster status", "cluster_name", cluster.Name, "endpoint", endpoint)
					return endpoint, nil
				}
			}
		}
	}

	slog.Debug("No endpoint found in cluster status, using constructed endpoint", "cluster_name", cluster.Name)

	// Fallback: construct endpoint using cluster name pattern
	// TODO: Make domain configurable via CLI flags or environment variable
	domain := "bealv.io" // Default domain - should be configurable
	port := 443          // Default port - should be configurable

	endpoint := fmt.Sprintf("https://kube.%s.%s:%d", cluster.Name, domain, port)
	slog.Debug("Using constructed cluster endpoint", "cluster", cluster.Name, "endpoint", endpoint, "domain", domain, "port", port)

	return endpoint, nil
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

	return fmt.Sprintf(template,
		clusterConfig,                           // cluster configuration
		data.ClusterName,                        // cluster name
		data.ClusterName,                        // context cluster
		userName,                                // context user
		contextName,                             // context name
		contextName,                             // current-context
		userName,                                // user name
		data.OIDCConfig.IssuerURL,               // oidc-issuer-url
		data.OIDCConfig.ClientID,                // oidc-client-id
	)
}

func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
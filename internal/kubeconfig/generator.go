package kubeconfig

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

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

	clusterGVR, err := g.resolver.ClusterGVR()
	if err != nil {
		slog.Error("Failed to resolve Cluster API version", "cluster_name", cluster.Name, "error", err)
		return "", fmt.Errorf("failed to resolve Cluster API version: %v", err)
	}

	clusterObj, err := g.client.Resource(clusterGVR).Namespace(cluster.Namespace).Get(ctx, cluster.Name, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster object", "cluster_name", cluster.Name, "namespace", cluster.Namespace, "error", err)
		return "", fmt.Errorf("failed to get cluster object: %v", err)
	}

	// Get control plane information (provider-agnostic, resolved from the
	// Cluster's controlPlaneRef).
	controlPlane, err := g.getControlPlane(ctx, clusterObj)
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

	clusterSpec, _ := clusterObj.Object["spec"].(map[string]interface{})

	// Retry fetching the cluster object until spec.controlPlaneEndpoint is
	// available. CAPI populates this field after the infrastructure provider
	// provisions the load balancer, which may take some time.
	retryCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		if endpoint, ok := clusterSpec["controlPlaneEndpoint"].(map[string]interface{}); ok {
			if host, _ := endpoint["host"].(string); host != "" {
				break
			}
		}
		select {
		case <-retryCtx.Done():
			slog.Error("Timed out waiting for control plane endpoint", "cluster_name", cluster.Name)
			return "", fmt.Errorf("failed to generate kubeconfig: control plane endpoint not available for cluster %q", cluster.Name)
		case <-time.After(3 * time.Second):
			slog.Info("Control plane endpoint not yet available, retrying...", "cluster_name", cluster.Name)
		}
		clusterObj, err = g.client.Resource(clusterGVR).Namespace(cluster.Namespace).Get(retryCtx, cluster.Name, metav1.GetOptions{})
		if err != nil {
			slog.Error("Failed to re-fetch cluster object", "cluster_name", cluster.Name, "error", err)
			return "", fmt.Errorf("failed to generate kubeconfig")
		}
		clusterSpec, _ = clusterObj.Object["spec"].(map[string]interface{})
	}

	// Get cluster endpoint from cluster spec
	serverURL, err := g.getClusterEndpoint(cluster, clusterSpec, controlPlane)
	if err != nil {
		slog.Error("Failed to get cluster endpoint", "cluster_name", cluster.Name, "error", err)
		return "", fmt.Errorf("failed to generate kubeconfig")
	}

	// Retrieve the cluster CA certificate from the CAPI-managed CA secret so
	// the kubeconfig can verify the API server's TLS certificate. This is a
	// public CA certificate, not a secret, so it is safe to embed. If it
	// cannot be retrieved, fall back to omitting it (the exec plugin/host
	// trust store handles verification in that case).
	caData := g.getClusterCAData(ctx, cluster)

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

// ProbeOIDCReady reports whether a usable kubeconfig can currently be
// reconstituted for the cluster. It resolves the cluster's control plane CR
// (provider-agnostic: KamajiControlPlane/"kcp", TenantControlPlane/"tcp",
// KubeadmControlPlane, etc.) and verifies that the kube-apiserver OIDC flags
// (oidc-issuer-url + oidc-client-id) are present, either as a direct spec.oidc
// node or in any apiServer extraArgs set.
//
// The control plane CR and its apiserver flags are populated asynchronously by
// the CAPI controllers after the Cluster is applied, so this returns false
// until the OIDC configuration is actually observable. It never returns an
// error: any failure to resolve or fetch the control plane simply means "not
// ready yet" from the caller's perspective.
func (g *Generator) ProbeOIDCReady(ctx context.Context, cluster *watcher.ClusterInfo) bool {
	clusterGVR, err := g.resolver.ClusterGVR()
	if err != nil {
		slog.Debug("OIDC probe: failed to resolve Cluster API version", "cluster_name", cluster.Name, "error", err)
		return false
	}

	clusterObj, err := g.client.Resource(clusterGVR).Namespace(cluster.Namespace).Get(ctx, cluster.Name, metav1.GetOptions{})
	if err != nil {
		slog.Debug("OIDC probe: failed to get cluster object", "cluster_name", cluster.Name, "namespace", cluster.Namespace, "error", err)
		return false
	}

	controlPlane, err := g.getControlPlane(ctx, clusterObj)
	if err != nil {
		slog.Debug("OIDC probe: control plane not available yet", "cluster_name", cluster.Name, "error", err)
		return false
	}

	if _, err := g.extractOIDCConfig(controlPlane); err != nil {
		slog.Debug("OIDC probe: OIDC config not available on control plane yet", "cluster_name", cluster.Name, "error", err)
		return false
	}

	slog.Debug("OIDC probe: kubeconfig reconstitution ready", "cluster_name", cluster.Name)
	return true
}

// getControlPlane resolves and fetches the control plane object referenced by
// the Cluster's spec.controlPlaneRef. The control plane kind is read from the
// ref and the GVR is resolved via discovery (using apiVersion when present),
// so chihiro does not depend on any particular control plane provider (Kamaji,
// kubeadm, etc.).
func (g *Generator) getControlPlane(ctx context.Context, clusterObj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	slog.Debug("Getting control plane for cluster", "cluster_name", clusterObj.GetName(), "namespace", clusterObj.GetNamespace())

	spec, ok := clusterObj.Object["spec"].(map[string]interface{})
	if !ok {
		slog.Error("Cluster spec not found or invalid", "cluster_name", clusterObj.GetName())
		return nil, fmt.Errorf("cluster spec not found")
	}

	controlPlaneRef, ok := spec["controlPlaneRef"].(map[string]interface{})
	if !ok {
		slog.Error("Control plane reference not found in cluster spec", "cluster_name", clusterObj.GetName())
		return nil, fmt.Errorf("controlPlaneRef not found in cluster spec")
	}

	cpName, ok := controlPlaneRef["name"].(string)
	if !ok {
		slog.Error("Control plane name not found", "cluster_name", clusterObj.GetName())
		return nil, fmt.Errorf("control plane name not found")
	}

	cpKind, ok := controlPlaneRef["kind"].(string)
	if !ok || cpKind == "" {
		slog.Error("Control plane kind not found in controlPlaneRef", "cluster_name", clusterObj.GetName())
		return nil, fmt.Errorf("control plane kind not found in controlPlaneRef")
	}

	cpNamespace, ok := controlPlaneRef["namespace"].(string)
	if !ok {
		cpNamespace = clusterObj.GetNamespace() // Use cluster namespace as fallback
		slog.Debug("Using cluster namespace for control plane", "cluster_name", clusterObj.GetName(), "namespace", cpNamespace)
	} else {
		slog.Debug("Found control plane namespace", "cluster_name", clusterObj.GetName(), "cp_name", cpName, "cp_namespace", cpNamespace)
	}

	// Resolve the control plane GVR. If apiVersion is present in the ref, use
	// it directly. Otherwise discover the version from the CAPI control plane
	// group using only the kind — some CAPI configurations omit apiVersion.
	cpAPIVersion, _ := controlPlaneRef["apiVersion"].(string)

	var (
		cpGVR schema.GroupVersionResource
		err   error
	)
	if cpAPIVersion != "" {
		cpGVR, err = g.resolver.GVRForKind(cpAPIVersion, cpKind)
	} else {
		cpGVR, err = g.resolver.GVRForControlPlaneKind(cpKind)
	}
	if err != nil {
		slog.Error("Failed to resolve control plane resource", "cluster_name", clusterObj.GetName(), "cp_kind", cpKind, "cp_api_version", cpAPIVersion, "error", err)
		return nil, fmt.Errorf("failed to resolve control plane resource: %v", err)
	}

	controlPlane, err := g.client.Resource(cpGVR).Namespace(cpNamespace).Get(ctx, cpName, metav1.GetOptions{})
	if err != nil {
		slog.Error(
			"Failed to get control plane resource",
			"cluster_name",
			clusterObj.GetName(),
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

	slog.Debug("Successfully retrieved control plane", "cluster_name", clusterObj.GetName(), "cp_name", cpName, "cp_namespace", cpNamespace, "cp_kind", cpKind)
	return controlPlane, nil
}

func (g *Generator) extractOIDCConfig(controlPlane *unstructured.Unstructured) (*OIDCConfig, error) {
	// NOTE: Do NOT dump the full control plane object here. Control plane specs
	// can carry sensitive material (e.g. oidc-client-secret in apiServer
	// extraArgs), and this runs at debug level which would leak secrets into
	// logs. Log only non-sensitive identifying metadata.
	slog.Debug(
		"Extracting OIDC config from control plane",
		"cluster",
		controlPlane.GetName(),
		"namespace",
		controlPlane.GetNamespace(),
		"kind",
		controlPlane.GetKind(),
	)

	spec, ok := controlPlane.Object["spec"].(map[string]interface{})
	if !ok {
		slog.Error("Control plane spec not found or invalid", "cluster", controlPlane.GetName())
		return nil, fmt.Errorf("control plane spec not found")
	}

	slog.Debug("Control plane spec keys", "cluster", controlPlane.GetName(), "keys", getKeys(spec))

	oidcConfig := &OIDCConfig{}

	// Path 1: Direct OIDC configuration in spec (some providers expose this).
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

	// Path 2: kube-apiserver --oidc-* flags. These live in an "apiServer"
	// (or "apiServerExtraArgs") node somewhere in the spec tree, and the
	// location differs by provider:
	//   - Kamaji:  spec.apiServer.extraArgs
	//   - Kubeadm: spec.kubeadmConfigSpec.clusterConfiguration.apiServer.extraArgs
	// extraArgs itself may be encoded as a list of "--flag=val" strings, a
	// list of {name,value} objects, or a map[flag]val. We search recursively
	// and parse whichever encoding we find so chihiro stays provider-agnostic.
	applyAPIServerOIDCArgs(spec, oidcConfig)

	// Path 3: Check status for OIDC configuration.
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

func (g *Generator) getClusterEndpoint(cluster *watcher.ClusterInfo, clusterSpec map[string]interface{}, controlPlane *unstructured.Unstructured) (string, error) {
	slog.Debug("Getting cluster endpoint", "cluster_name", cluster.Name)

	// 1. Check the watcher's APIEndpoint (populated from status.controlPlaneEndpoint in parseCluster).
	if cluster.APIEndpoint != "" {
		slog.Debug("Using cluster API endpoint from watcher", "cluster_name", cluster.Name, "endpoint", cluster.APIEndpoint)
		return cluster.APIEndpoint, nil
	}

	// 2. Check cluster.Status directly (same data as above, but a fresh fetch
	//    may have populated it since the watcher last synced).
	if cluster.Status != nil {
		if controlPlaneEndpoint, ok := cluster.Status["controlPlaneEndpoint"].(map[string]interface{}); ok {
			if host, ok := controlPlaneEndpoint["host"].(string); ok && host != "" {
				if port := toInt(controlPlaneEndpoint["port"]); port > 0 {
					endpoint := fmt.Sprintf("https://%s:%d", host, port)
					slog.Info("Found endpoint from cluster status", "cluster_name", cluster.Name, "endpoint", endpoint)
					return endpoint, nil
				}
			}
		}
	}

	// 3. Check spec.controlPlaneEndpoint. CAPI sets this field on the Cluster
	//    spec when the endpoint is known at creation time.
	if clusterSpec != nil {
		if controlPlaneEndpoint, ok := clusterSpec["controlPlaneEndpoint"].(map[string]interface{}); ok {
			if host, ok := controlPlaneEndpoint["host"].(string); ok && host != "" {
				if port := toInt(controlPlaneEndpoint["port"]); port > 0 {
					endpoint := fmt.Sprintf("https://%s:%d", host, port)
					slog.Info("Found endpoint from cluster spec", "cluster_name", cluster.Name, "endpoint", endpoint)
					return endpoint, nil
				}
			}
		}
	}

	// 4. Check the control plane object's status. Some providers (e.g. Kamaji)
	//    expose the controlPlaneEndpoint on the control plane resource directly.
	if controlPlane != nil {
		if status, ok := controlPlane.Object["status"].(map[string]interface{}); ok {
			if controlPlaneEndpoint, ok := status["controlPlaneEndpoint"].(map[string]interface{}); ok {
				if host, ok := controlPlaneEndpoint["host"].(string); ok && host != "" {
					if port := toInt(controlPlaneEndpoint["port"]); port > 0 {
						endpoint := fmt.Sprintf("https://%s:%d", host, port)
						slog.Info("Found endpoint from control plane status", "cluster_name", cluster.Name, "endpoint", endpoint)
						return endpoint, nil
					}
				}
			}
		}
	}

	slog.Error("No control plane endpoint available for cluster", "cluster_name", cluster.Name)
	return "", fmt.Errorf("control plane endpoint not available for cluster %q", cluster.Name)
}

// getClusterCAData fetches the cluster CA certificate from the CAPI-managed
// secret. CAPI control plane providers store the cluster CA in a Secret named
// "<cluster-name>-ca" in the cluster's namespace, with the CA certificate under
// the "tls.crt" key (base64-encoded by Kubernetes in the Secret's data map).
//
// The returned value is the base64-encoded certificate suitable for direct use
// as certificate-authority-data in a kubeconfig. On any error the empty string
// is returned and verification is left to the exec plugin / host trust store,
// so kubeconfig generation never fails solely because the CA could not be read.
func (g *Generator) getClusterCAData(ctx context.Context, cluster *watcher.ClusterInfo) string {
	secretGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	secretName := fmt.Sprintf("%s-ca", cluster.Name)

	secret, err := g.client.Resource(secretGVR).Namespace(cluster.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		slog.Warn(
			"Could not retrieve cluster CA secret; kubeconfig will omit certificate-authority-data",
			"cluster_name", cluster.Name,
			"namespace", cluster.Namespace,
			"secret_name", secretName,
			"error", err,
		)
		return ""
	}

	data, ok := secret.Object["data"].(map[string]interface{})
	if !ok {
		slog.Warn("Cluster CA secret has no data field", "cluster_name", cluster.Name, "secret_name", secretName)
		return ""
	}

	// Values in a Secret's data map are already base64-encoded strings, which
	// is exactly the encoding certificate-authority-data expects.
	caData, ok := data["tls.crt"].(string)
	if !ok || caData == "" {
		slog.Warn("Cluster CA secret missing tls.crt key", "cluster_name", cluster.Name, "secret_name", secretName)
		return ""
	}

	slog.Info("Retrieved cluster CA certificate", "cluster_name", cluster.Name, "secret_name", secretName)
	return caData
}

func (g *Generator) renderKubeconfig(data *KubeconfigData) string {
	// Build cluster configuration. Embed the cluster CA certificate when it was
	// retrieved so clients can verify the API server's TLS certificate; if it
	// is unavailable, fall back to the server entry alone and let the exec
	// plugin / host trust store handle verification.
	// The template indents the first line of this block with 4 spaces, so the
	// "server" line must NOT carry its own leading spaces; continuation lines
	// supply their own 4-space indent to align under "- cluster:".
	clusterConfig := fmt.Sprintf("server: %s", data.ServerURL)
	if data.CertificateData != "" {
		clusterConfig = fmt.Sprintf("server: %s\n    certificate-authority-data: %s", data.ServerURL, data.CertificateData)
	}

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

// applyAPIServerOIDCArgs walks the spec tree looking for any "apiServer" node
// that carries kube-apiserver extraArgs, then parses OIDC flags from them.
// Only fields not already set are filled, so earlier paths take precedence.
func applyAPIServerOIDCArgs(node interface{}, oidc *OIDCConfig) {
	switch v := node.(type) {
	case map[string]interface{}:
		// An apiServer node may carry extraArgs directly.
		if apiServer, ok := v["apiServer"].(map[string]interface{}); ok {
			if ea, ok := apiServer["extraArgs"]; ok {
				parseOIDCExtraArgs(ea, oidc)
			}
		}
		// Some providers flatten this to "apiServerExtraArgs".
		if ea, ok := v["apiServerExtraArgs"]; ok {
			parseOIDCExtraArgs(ea, oidc)
		}
		// Recurse into all children to stay agnostic to nesting depth.
		for _, child := range v {
			applyAPIServerOIDCArgs(child, oidc)
		}
	case []interface{}:
		for _, child := range v {
			applyAPIServerOIDCArgs(child, oidc)
		}
	}
}

// parseOIDCExtraArgs extracts --oidc-* values from kube-apiserver extraArgs in
// any of the three known encodings: a list of "--flag=val" / "flag=val"
// strings, a list of {name,value} objects, or a map[flag]val.
func parseOIDCExtraArgs(extraArgs interface{}, oidc *OIDCConfig) {
	set := func(flag, value string) {
		switch flag {
		case "oidc-issuer-url":
			if oidc.IssuerURL == "" {
				oidc.IssuerURL = value
			}
		case "oidc-client-id":
			if oidc.ClientID == "" {
				oidc.ClientID = value
			}
		case "oidc-client-secret":
			if oidc.ClientSecret == "" {
				oidc.ClientSecret = value
			}
		}
	}

	switch ea := extraArgs.(type) {
	case []interface{}:
		for _, arg := range ea {
			switch a := arg.(type) {
			case string:
				// "--oidc-issuer-url=https://..." or "oidc-issuer-url=https://..."
				flag, value, found := strings.Cut(strings.TrimPrefix(a, "--"), "=")
				if found {
					set(flag, value)
				}
			case map[string]interface{}:
				// { name: "oidc-issuer-url", value: "https://..." }
				name, _ := a["name"].(string)
				value, _ := a["value"].(string)
				set(strings.TrimPrefix(name, "--"), value)
			}
		}
	case map[string]interface{}:
		// { "oidc-issuer-url": "https://..." }
		for name, raw := range ea {
			if value, ok := raw.(string); ok {
				set(strings.TrimPrefix(name, "--"), value)
			}
		}
	}
}

// toInt extracts an integer from an interface{} that may be float64, int,
// int64, or json.Number. Returns 0 if the value cannot be converted.
func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case int32:
		return int(n)
	}
	return 0
}

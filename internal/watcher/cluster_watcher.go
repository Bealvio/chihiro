package watcher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bealvio/chihiro/internal/capi"
	"github.com/Bealvio/chihiro/internal/cluster"
	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// checkWebSocketOrigin validates the WebSocket Origin header to prevent
// cross-site WebSocket hijacking (CSRF). It uses exact host comparison rather
// than substring matching, so values like "http://localhost:8080.evil.com"
// are rejected. An origin is allowed when:
//   - its host (host:port) exactly equals the request Host (same-origin), or
//   - it exactly equals a localhost development origin, or
//   - it exactly equals one of the configured allowed_origins entries.
func checkWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false // Reject if no origin header
	}

	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host == "" {
		slog.Warn("WebSocket connection rejected due to unparseable origin", "origin", origin, "remote_addr", r.RemoteAddr)
		return false
	}

	// Same-origin: the Origin's host:port must exactly match the request Host.
	if originURL.Host == r.Host {
		return true
	}

	// Exact-match allow list: full origin URLs (scheme + host).
	allowedOrigins := []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
	}
	if configOrigins := viper.GetString("allowed_origins"); configOrigins != "" {
		for _, o := range strings.Split(configOrigins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				allowedOrigins = append(allowedOrigins, trimmed)
			}
		}
	}

	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}

	slog.Warn("WebSocket connection rejected due to invalid origin", "origin", origin, "remote_addr", r.RemoteAddr)
	return false
}

type ClusterNetwork struct {
	PodCIDRs      []string `json:"podCIDRs"`
	ServiceCIDRs  []string `json:"serviceCIDRs"`
	ServiceDomain string   `json:"serviceDomain"`
}

type ClusterInfo struct {
	Name                 string                 `json:"name"`
	Namespace            string                 `json:"namespace"`
	Phase                string                 `json:"phase"`
	Ready                bool                   `json:"ready"`
	Available            bool                   `json:"available"`
	Version              string                 `json:"version"`
	Nodes                int32                  `json:"nodes"`
	ControlPlaneReplicas int32                  `json:"controlPlaneReplicas"`
	CreatedAt            time.Time              `json:"createdAt"`
	Status               map[string]interface{} `json:"status"`
	InfraReady           bool                   `json:"infraReady"`
	ControlPlane         bool                   `json:"controlPlane"`
	Network              *ClusterNetwork        `json:"network"`
	Labels               map[string]interface{} `json:"labels"`
	Annotations          map[string]interface{} `json:"annotations"`
	APIEndpoint          string                 `json:"apiEndpoint"`
	Groups               []string               `json:"groups"`
	Creator              string                 `json:"creator"`
	Domain               string                 `json:"domain"`
	Parameters           map[string]string      `json:"parameters"`
	WorkerGroups         []cluster.WorkerGroup  `json:"workerGroups"`
	// KubeconfigReady reports whether a kubeconfig can currently be
	// reconstituted for the cluster, i.e. the control plane CR (kcp/tcp) is
	// present and exposes the kube-apiserver OIDC flags. The CAPI controllers
	// populate these asynchronously after creation, so this stays false until
	// the OIDC configuration is observable. The UI greys out the kubeconfig
	// download until both APIEndpoint and KubeconfigReady are set.
	KubeconfigReady bool `json:"kubeconfigReady"`
}

// OIDCProber reports whether a kubeconfig (with its OIDC apiserver flags) can
// currently be reconstituted for a cluster. It is satisfied by
// *kubeconfig.Generator. The watcher takes it as an interface to avoid an
// import cycle (the kubeconfig package imports this package).
type OIDCProber interface {
	ProbeOIDCReady(ctx context.Context, cluster *ClusterInfo) bool
}

type ClusterWatcher struct {
	client      dynamic.Interface
	resolver    *capi.Resolver
	clusterGVR  schema.GroupVersionResource
	clusters    map[string]*ClusterInfo
	mutex       sync.RWMutex
	clients     map[*websocket.Conn]*UserWebSocketClient
	upgrader    websocket.Upgrader
	adminGroups []string
	// oidcProber probes whether a kubeconfig can be reconstituted (control
	// plane OIDC flags present). Set after construction via SetOIDCProber to
	// avoid an import cycle with the kubeconfig package. May be nil, in which
	// case readiness probing is skipped and KubeconfigReady stays false.
	oidcProber OIDCProber
}

// SetOIDCProber registers the prober used to determine whether each cluster's
// kubeconfig can be reconstituted yet. Safe to call once during setup, before
// Start.
func (cw *ClusterWatcher) SetOIDCProber(p OIDCProber) {
	cw.mutex.Lock()
	cw.oidcProber = p
	cw.mutex.Unlock()
}

// WebSocket keepalive/timeout tuning. Writes are bounded so a stuck client
// cannot block a broadcast goroutine indefinitely; the read deadline (refreshed
// on every pong) reaps dead connections that would otherwise leak a goroutine
// and a map entry.
const (
	wsWriteWait  = 10 * time.Second
	wsPongWait   = 60 * time.Second
	wsPingPeriod = (wsPongWait * 9) / 10
)

// WSPongWait is the maximum time to wait for a pong before a connection is
// considered dead. Exposed for the HTTP handler that owns the read loop.
func WSPongWait() time.Duration { return wsPongWait }

// WSPingPeriod is the interval at which the server pings each client. It is
// shorter than WSPongWait so a pong is expected before the read deadline lapses.
func WSPingPeriod() time.Duration { return wsPingPeriod }

type UserWebSocketClient struct {
	Conn   *websocket.Conn
	Groups []string
	// writeMu serializes writes to Conn. gorilla/websocket permits only one
	// concurrent writer per connection, and multiple goroutines (the watch
	// loop, readiness monitor, and manual refreshes) can broadcast at once.
	writeMu sync.Mutex
}

// writeMessage serializes writes to the underlying connection so concurrent
// broadcasts never write to the same socket at the same time. A bounded write
// deadline prevents a slow/dead client from stalling the broadcaster.
func (c *UserWebSocketClient) writeMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.Conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	return c.Conn.WriteMessage(messageType, data)
}

// PingClient sends a WebSocket ping through the serialized writer. It returns an
// error if the connection is unknown or the write fails, so the caller can tear
// the connection down.
func (cw *ClusterWatcher) PingClient(conn *websocket.Conn) error {
	cw.mutex.RLock()
	client := cw.clients[conn]
	cw.mutex.RUnlock()
	if client == nil {
		return fmt.Errorf("websocket client not registered")
	}
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	return conn.WriteMessage(websocket.PingMessage, nil)
}

func NewClusterWatcher(kubeconfig string) (*ClusterWatcher, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes config: %v", err)
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %v", err)
	}

	// Resolve the served Cluster API version via discovery so we don't break
	// when the management cluster's CAPI is upgraded (e.g. v1beta1 -> v1beta2).
	resolver, err := capi.NewResolver(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create CAPI version resolver: %v", err)
	}

	clusterGVR, err := resolver.ClusterGVR()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Cluster API version: %v", err)
	}

	// Load admin groups from config
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		slog.Warn("No admin groups configured, using default")
		adminGroups = []string{"cluster-admin"}
	}

	slog.Info("Initialized cluster watcher", "admin_groups", adminGroups)

	return &ClusterWatcher{
		client:      client,
		resolver:    resolver,
		clusterGVR:  clusterGVR,
		clusters:    make(map[string]*ClusterInfo),
		clients:     make(map[*websocket.Conn]*UserWebSocketClient),
		adminGroups: adminGroups,
		upgrader: websocket.Upgrader{
			CheckOrigin: checkWebSocketOrigin,
		},
	}, nil
}

func (cw *ClusterWatcher) Start(ctx context.Context) {
	go cw.watchClusters(ctx)
	go cw.loadInitialClusters(ctx)
	go cw.monitorClusterReadiness(ctx)
}

func (cw *ClusterWatcher) loadInitialClusters(ctx context.Context) {
	gvr := cw.clusterGVR

	// Load clusters managed by chihiro
	list, err := cw.client.Resource(gvr).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=chihiro",
	})
	if err != nil {
		slog.Error("Failed to load initial clusters", "error", err)
		return
	}

	slog.Info("Loaded initial clusters", "count", len(list.Items))

	cw.mutex.Lock()
	for _, item := range list.Items {
		clusterInfo := cw.parseCluster(&item)
		cw.clusters[clusterInfo.Name] = clusterInfo
	}
	cw.mutex.Unlock()

	cw.broadcastUpdate()

	// Probe kubeconfig/endpoint readiness immediately so clusters that already
	// existed before this restart reflect their true state right away, rather
	// than waiting for the first periodic monitor tick.
	cw.checkAllClustersReadiness()
}

func (cw *ClusterWatcher) watchClusters(ctx context.Context) {
	gvr := cw.clusterGVR

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Watch clusters managed by chihiro
			watcher, err := cw.client.Resource(gvr).Watch(ctx, metav1.ListOptions{
				LabelSelector: "app.kubernetes.io/managed-by=chihiro",
			})
			if err != nil {
				slog.Error("Failed to create cluster watcher", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for event := range watcher.ResultChan() {
				if event.Type == watch.Error {
					slog.Error("Watch error received", "object", event.Object)
					break
				}

				obj, ok := event.Object.(*unstructured.Unstructured)
				if !ok {
					slog.Warn("Unexpected object type in watch event", "type", fmt.Sprintf("%T", event.Object))
					continue
				}

				clusterInfo := cw.parseCluster(obj)

				cw.mutex.Lock()
				switch event.Type {
				case watch.Added, watch.Modified:
					// Preserve the last-probed kubeconfig readiness so a re-parse
					// from a watch event doesn't flip the UI button off until the
					// next periodic probe re-confirms it.
					if prev, ok := cw.clusters[clusterInfo.Name]; ok {
						clusterInfo.KubeconfigReady = prev.KubeconfigReady
					}
					cw.clusters[clusterInfo.Name] = clusterInfo
				case watch.Deleted:
					delete(cw.clusters, clusterInfo.Name)
				}
				cw.mutex.Unlock()

				cw.broadcastUpdate()
			}
			watcher.Stop()
		}
	}
}

func (cw *ClusterWatcher) parseCluster(obj *unstructured.Unstructured) *ClusterInfo {
	spec, _ := obj.Object["spec"].(map[string]interface{})
	status, _ := obj.Object["status"].(map[string]interface{})

	// Convert labels to map[string]interface{}
	labels := make(map[string]interface{})
	for k, v := range obj.GetLabels() {
		labels[k] = v
	}

	annotations := make(map[string]interface{})
	for k, v := range obj.GetAnnotations() {
		annotations[k] = v
	}

	clusterInfo := &ClusterInfo{
		Name:        obj.GetName(),
		Namespace:   obj.GetNamespace(),
		CreatedAt:   obj.GetCreationTimestamp().Time,
		Status:      status,
		Labels:      labels,
		Annotations: annotations,
	}

	slog.Debug("Parsing cluster", "name", obj.GetName(), "namespace", obj.GetNamespace())
	slog.Info("Raw cluster status", "name", obj.GetName(), "status", status)
	if spec != nil {
		slog.Debug("Found cluster spec", "name", obj.GetName(), "spec_keys", getKeys(spec))
		if topology, ok := spec["topology"].(map[string]interface{}); ok {
			slog.Debug("Found cluster topology", "name", obj.GetName(), "topology_keys", getKeys(topology))
			if workers, ok := topology["workers"].(map[string]interface{}); ok {
				slog.Debug("Found cluster workers config", "name", obj.GetName(), "workers_keys", getKeys(workers))
			}
		}
	}

	if phase, ok := status["phase"].(string); ok {
		clusterInfo.Phase = phase
	}

	// Parse control plane endpoint from status (populated by the
	// infrastructure provider once the load balancer is provisioned).
	if controlPlaneEndpoint, ok := status["controlPlaneEndpoint"].(map[string]interface{}); ok {
		slog.Debug("Found controlPlaneEndpoint in status", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
		if host, ok := controlPlaneEndpoint["host"].(string); ok && host != "" {
			port := toInt(controlPlaneEndpoint["port"])
			if port > 0 {
				clusterInfo.APIEndpoint = fmt.Sprintf("https://%s:%d", host, port)
				slog.Info("Parsed cluster API endpoint from status", "cluster", clusterInfo.Name, "endpoint", clusterInfo.APIEndpoint)
			} else {
				slog.Warn("controlPlaneEndpoint missing port", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
			}
		} else {
			slog.Warn("controlPlaneEndpoint missing host", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
		}
	}

	// Fallback: parse control plane endpoint from spec. CAPI sets
	// spec.controlPlaneEndpoint at creation time when the endpoint is
	// already known, before the infrastructure provider reports it in status.
	if clusterInfo.APIEndpoint == "" && spec != nil {
		if controlPlaneEndpoint, ok := spec["controlPlaneEndpoint"].(map[string]interface{}); ok {
			slog.Debug("Found controlPlaneEndpoint in spec", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
			if host, ok := controlPlaneEndpoint["host"].(string); ok && host != "" {
				port := toInt(controlPlaneEndpoint["port"])
				if port > 0 {
					clusterInfo.APIEndpoint = fmt.Sprintf("https://%s:%d", host, port)
					slog.Info("Parsed cluster API endpoint from spec", "cluster", clusterInfo.Name, "endpoint", clusterInfo.APIEndpoint)
				} else {
					slog.Warn("controlPlaneEndpoint missing port in spec", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
				}
			} else {
				slog.Warn("controlPlaneEndpoint missing host in spec", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
			}
		}
	}

	// Get domain for cluster from config. No hardcoded fallback: the domain is
	// deployment-specific and a stale default would be misleading.
	clusterInfo.Domain = viper.GetString("cluster.domain")

	if conditions, ok := status["conditions"].([]interface{}); ok {
		for _, condition := range conditions {
			if condMap, ok := condition.(map[string]interface{}); ok {
				if condType, ok := condMap["type"].(string); ok && condType == "InfrastructureReady" {
					if condStatus, ok := condMap["status"].(string); ok {
						clusterInfo.InfraReady = condStatus == "True"
					}
				}
				if condType, ok := condMap["type"].(string); ok && condType == "ControlPlaneReady" {
					if condStatus, ok := condMap["status"].(string); ok {
						clusterInfo.ControlPlane = condStatus == "True"
					}
				}
				if condType, ok := condMap["type"].(string); ok && condType == "Available" {
					if condStatus, ok := condMap["status"].(string); ok {
						clusterInfo.Available = condStatus == "True"
					}
				}
			}
		}
	}

	// Check for Available field in status (provider-specific).
	// Only set if not already determined from conditions.
	if !clusterInfo.Available {
		if available, ok := status["available"].(bool); ok {
			clusterInfo.Available = available
		}
	}

	if spec != nil {
		// Try different paths for version
		if controlPlaneRef, ok := spec["controlPlaneRef"].(map[string]interface{}); ok {
			if version, ok := controlPlaneRef["version"].(string); ok {
				clusterInfo.Version = version
			}
		}
		// Also check for topology version
		if topology, ok := spec["topology"].(map[string]interface{}); ok {
			if version, ok := topology["version"].(string); ok {
				clusterInfo.Version = version
			}

			// Read control plane replicas from the topology
			if controlPlane, ok := topology["controlPlane"].(map[string]interface{}); ok {
				clusterInfo.ControlPlaneReplicas = int32(toInt(controlPlane["replicas"]))
			}

			// Calculate total nodes from machineDeployments
			if workers, ok := topology["workers"].(map[string]interface{}); ok {
				if machineDeployments, ok := workers["machineDeployments"].([]interface{}); ok {
					slog.Debug("Found machine deployments", "name", obj.GetName(), "count", len(machineDeployments))
					totalReplicas := int32(0)
					for i, deployment := range machineDeployments {
						if depMap, ok := deployment.(map[string]interface{}); ok {
							slog.Debug("Processing machine deployment", "name", obj.GetName(), "deployment_index", i, "keys", getKeys(depMap))
							if replicas, ok := depMap["replicas"].(int64); ok {
								slog.Debug("Found replicas count", "name", obj.GetName(), "deployment_index", i, "replicas", replicas, "type", "int64")
								totalReplicas += int32(replicas)
							} else if replicas, ok := depMap["replicas"].(float64); ok {
								slog.Debug("Found replicas count", "name", obj.GetName(), "deployment_index", i, "replicas", replicas, "type", "float64")
								totalReplicas += int32(replicas)
							} else if replicas, ok := depMap["replicas"].(int32); ok {
								slog.Debug("Found replicas count", "name", obj.GetName(), "deployment_index", i, "replicas", replicas, "type", "int32")
								totalReplicas += replicas
							} else if replicas, ok := depMap["replicas"].(int); ok {
								slog.Debug("Found replicas count", "name", obj.GetName(), "deployment_index", i, "replicas", replicas, "type", "int")
								totalReplicas += int32(replicas)
							} else {
								slog.Warn("Machine deployment missing or invalid replicas field", "name", obj.GetName(), "deployment_index", i)
								if replicas, exists := depMap["replicas"]; exists {
									slog.Debug("Unexpected replicas type", "name", obj.GetName(), "deployment_index", i, "type", fmt.Sprintf("%T", replicas), "value", replicas)
								}
							}
						}
					}
					slog.Debug("Calculated total worker replicas", "name", obj.GetName(), "total_replicas", totalReplicas)
					clusterInfo.Nodes = totalReplicas
				} else {
					slog.Warn("Machine deployments field has unexpected type", "name", obj.GetName())
				}
			} else {
				slog.Warn("Workers field has unexpected type", "name", obj.GetName())
			}

		}
		// Direct version field
		if version, ok := spec["version"].(string); ok {
			clusterInfo.Version = version
		}

		// Parse cluster network information
		if clusterNetwork, ok := spec["clusterNetwork"].(map[string]interface{}); ok {
			network := &ClusterNetwork{}

			// Parse pod CIDRs
			if pods, ok := clusterNetwork["pods"].(map[string]interface{}); ok {
				if cidrBlocks, ok := pods["cidrBlocks"].([]interface{}); ok {
					for _, cidr := range cidrBlocks {
						if cidrStr, ok := cidr.(string); ok {
							network.PodCIDRs = append(network.PodCIDRs, cidrStr)
						}
					}
				}
			}

			// Parse service CIDRs
			if services, ok := clusterNetwork["services"].(map[string]interface{}); ok {
				if cidrBlocks, ok := services["cidrBlocks"].([]interface{}); ok {
					for _, cidr := range cidrBlocks {
						if cidrStr, ok := cidr.(string); ok {
							network.ServiceCIDRs = append(network.ServiceCIDRs, cidrStr)
						}
					}
				}
			}

			// Parse service domain
			if serviceDomain, ok := clusterNetwork["serviceDomain"].(string); ok {
				network.ServiceDomain = serviceDomain
			}

			clusterInfo.Network = network
		}
	}

	if status != nil {
		// Try different paths for node count
		if nodeCount, ok := status["nodeCount"].(float64); ok {
			clusterInfo.Nodes = int32(nodeCount)
		}
		if nodeCount, ok := status["nodeCount"].(int32); ok {
			clusterInfo.Nodes = nodeCount
		}
		if nodeCount, ok := status["nodeCount"].(int); ok {
			clusterInfo.Nodes = int32(nodeCount)
		}
		// Try infrastructure status
		if infra, ok := status["infrastructure"].(map[string]interface{}); ok {
			if ready, ok := infra["ready"].(bool); ok && ready {
				// Infrastructure is ready, we might have node info
				if nodeCount, ok := infra["nodeCount"].(float64); ok {
					clusterInfo.Nodes = int32(nodeCount)
				}
			}
		}
		// Try controlPlane status for node count
		if cp, ok := status["controlPlane"].(map[string]interface{}); ok {
			if nodeCount, ok := cp["replicas"].(float64); ok {
				clusterInfo.Nodes = int32(nodeCount)
			}
			if nodeCount, ok := cp["readyReplicas"].(float64); ok {
				clusterInfo.Nodes = int32(nodeCount)
			}
		}
	}

	// Extract groups from annotations for display
	if groupsValue, exists := clusterInfo.Annotations["chihiro.io/groups"]; exists {
		if groupsStr, ok := groupsValue.(string); ok && groupsStr != "" {
			groups := strings.Split(groupsStr, ",")
			for i, group := range groups {
				groups[i] = strings.TrimSpace(group)
			}
			clusterInfo.Groups = groups
			slog.Debug("Parsed cluster groups", "cluster", clusterInfo.Name, "groups", clusterInfo.Groups)
		}
	}

	// Extract worker groups from annotations for display
	if wgValue, exists := clusterInfo.Annotations["chihiro.io/worker-groups"]; exists {
		if wgStr, ok := wgValue.(string); ok && wgStr != "" {
			var workerGroups []cluster.WorkerGroup
			if err := json.Unmarshal([]byte(wgStr), &workerGroups); err == nil {
				clusterInfo.WorkerGroups = workerGroups
				slog.Debug("Parsed cluster worker groups", "cluster", clusterInfo.Name, "worker_groups", len(workerGroups))
			} else {
				slog.Warn("Failed to parse worker-groups annotation", "cluster", clusterInfo.Name, "error", err)
			}
		}
	}

	// Extract creator from annotations
	if creatorValue, exists := clusterInfo.Annotations["chihiro.io/creator"]; exists {
		if creatorStr, ok := creatorValue.(string); ok {
			clusterInfo.Creator = creatorStr
			slog.Debug("Parsed cluster creator", "cluster", clusterInfo.Name, "creator", clusterInfo.Creator)
		}
	}

	// Extract the parameters set at creation time for display in the UI.
	if paramsValue, exists := clusterInfo.Annotations["chihiro.io/parameters"]; exists {
		if paramsStr, ok := paramsValue.(string); ok && paramsStr != "" {
			params := make(map[string]string)
			if err := json.Unmarshal([]byte(paramsStr), &params); err == nil {
				clusterInfo.Parameters = params
				slog.Debug("Parsed cluster parameters", "cluster", clusterInfo.Name, "param_count", len(params))
			} else {
				slog.Warn("Failed to parse cluster parameters annotation", "cluster", clusterInfo.Name, "error", err)
			}
		}
	}

	// Test API endpoint reachability for readiness check
	if clusterInfo.APIEndpoint != "" {
		clusterInfo.Ready = cw.testAPIEndpointReachability(clusterInfo.APIEndpoint)
		slog.Info("API endpoint reachability test result", "cluster", clusterInfo.Name, "endpoint", clusterInfo.APIEndpoint, "ready", clusterInfo.Ready)
	} else {
		slog.Warn("No API endpoint available for readiness test", "cluster", clusterInfo.Name)
		clusterInfo.Ready = false
	}

	return clusterInfo
}

// sortClusters orders clusters by age, newest first (CreatedAt descending),
// with the cluster name as a stable tie-breaker. The watcher stores clusters in
// a map, whose iteration order is nondeterministic, so every consumer-facing
// slice is sorted here to keep the displayed ordering consistent across
// rebuilds and WebSocket updates.
func sortClusters(clusters []*ClusterInfo) {
	sort.SliceStable(clusters, func(i, j int) bool {
		if !clusters[i].CreatedAt.Equal(clusters[j].CreatedAt) {
			return clusters[i].CreatedAt.After(clusters[j].CreatedAt)
		}
		return clusters[i].Name < clusters[j].Name
	})
}

func (cw *ClusterWatcher) GetClusters() []*ClusterInfo {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()

	clusters := make([]*ClusterInfo, 0, len(cw.clusters))
	for _, cluster := range cw.clusters {
		clusters = append(clusters, cluster)
	}
	sortClusters(clusters)
	return clusters
}

func (cw *ClusterWatcher) GetClustersForUser(userGroups []string) []*ClusterInfo {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()

	clusters := make([]*ClusterInfo, 0)
	for _, cluster := range cw.clusters {
		if cw.canUserAccessCluster(cluster, userGroups) {
			clusters = append(clusters, cluster)
		}
	}
	sortClusters(clusters)
	return clusters
}

func (cw *ClusterWatcher) canUserAccessCluster(cluster *ClusterInfo, userGroups []string) bool {
	// Create user group map for efficient lookup
	userGroupMap := make(map[string]bool)
	for _, group := range userGroups {
		userGroupMap[strings.TrimSpace(group)] = true
	}

	// Check if user is in admin groups first (admin groups can see ALL chihiro-managed clusters)
	for _, adminGroup := range cw.adminGroups {
		if userGroupMap[adminGroup] {
			slog.Debug("User has admin access to all clusters", "user_groups", userGroups, "admin_group", adminGroup, "cluster", cluster.Name)
			return true
		}
	}

	// Non-admin users need group-based access
	// If cluster has no group annotations, deny access (secure by default)
	if cluster.Annotations == nil {
		return false
	}

	groupsValue, exists := cluster.Annotations["chihiro.io/groups"]
	if !exists {
		return false
	}

	groupsStr, ok := groupsValue.(string)
	if !ok || groupsStr == "" {
		return false
	}

	// Parse cluster groups
	clusterGroups := strings.Split(groupsStr, ",")
	for i, group := range clusterGroups {
		clusterGroups[i] = strings.TrimSpace(group)
	}

	// Check if user has any of the required groups
	for _, requiredGroup := range clusterGroups {
		if requiredGroup != "" && userGroupMap[requiredGroup] {
			slog.Debug("User has cluster-specific access", "user_groups", userGroups, "cluster_group", requiredGroup, "cluster", cluster.Name)
			return true
		}
	}

	return false
}

// testAPIEndpointReachability tests if the cluster API endpoint is reachable
func (cw *ClusterWatcher) testAPIEndpointReachability(endpoint string) bool {
	// Create HTTP client with TLS config that skips certificate verification
	// We only care about reachability, not certificate validity
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Test the /api endpoint which should return 200 for a working API server
	testURL := endpoint + "/api"

	slog.Info("Testing API endpoint reachability", "url", testURL)

	resp, err := client.Get(testURL)
	if err != nil {
		slog.Warn("API endpoint unreachable", "url", testURL, "error", err)
		return false
	}
	defer resp.Body.Close()

	// A working API server responds to /api. 200 means anonymous access is
	// allowed; 401/403 mean the server is up and authenticating/authorizing
	// requests (just rejecting this unauthenticated one) — all indicate the
	// endpoint is reachable and ready.
	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden:
		slog.Info("API endpoint reachable and ready", "url", testURL, "status_code", resp.StatusCode)
		return true
	}

	slog.Warn("API endpoint returned unexpected status", "url", testURL, "status_code", resp.StatusCode)
	return false
}

// monitorClusterReadiness periodically checks cluster readiness and updates status
func (cw *ClusterWatcher) monitorClusterReadiness(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	slog.Info("Starting cluster readiness monitoring", "interval", "30s")

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping cluster readiness monitoring")
			return
		case <-ticker.C:
			cw.checkAllClustersReadiness()
		}
	}
}

// checkAllClustersReadiness checks readiness for all clusters and updates their status
func (cw *ClusterWatcher) checkAllClustersReadiness() {
	// Copy cluster list to avoid holding lock during network calls
	cw.mutex.RLock()
	clustersCopy := make([]*ClusterInfo, 0, len(cw.clusters))
	for _, cluster := range cw.clusters {
		clustersCopy = append(clustersCopy, cluster)
	}
	cw.mutex.RUnlock()

	cw.mutex.RLock()
	prober := cw.oidcProber
	cw.mutex.RUnlock()

	// Test reachability and OIDC kubeconfig readiness without holding the lock
	// (both involve API/network calls that can be slow).
	type readinessResult struct {
		cluster     *ClusterInfo
		newReady    bool
		readyChange bool
		newKubecfg  bool
		kubeChange  bool
	}
	results := make([]readinessResult, 0)

	for _, cluster := range clustersCopy {
		res := readinessResult{cluster: cluster}

		if cluster.APIEndpoint != "" {
			newReady := cw.testAPIEndpointReachability(cluster.APIEndpoint)
			if cluster.Ready != newReady {
				slog.Info("Cluster readiness changed", "cluster", cluster.Name, "endpoint", cluster.APIEndpoint, "old_ready", cluster.Ready, "new_ready", newReady)
				res.newReady = newReady
				res.readyChange = true
			}
		}

		// Probe whether the kubeconfig can be reconstituted yet (control plane
		// OIDC flags observable). The CAPI controllers populate the control
		// plane CR (kcp/tcp) and its apiserver flags asynchronously, so this
		// flips to true some time after creation.
		if prober != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			newKubecfg := prober.ProbeOIDCReady(ctx, cluster)
			cancel()
			if cluster.KubeconfigReady != newKubecfg {
				slog.Info("Cluster kubeconfig readiness changed", "cluster", cluster.Name, "old_ready", cluster.KubeconfigReady, "new_ready", newKubecfg)
				res.newKubecfg = newKubecfg
				res.kubeChange = true
			}
		}

		if res.readyChange || res.kubeChange {
			results = append(results, res)
		}
	}

	// Update cluster readiness with lock (fast operation)
	if len(results) > 0 {
		cw.mutex.Lock()
		for _, result := range results {
			if c, exists := cw.clusters[result.cluster.Name]; exists {
				if result.readyChange {
					c.Ready = result.newReady
				}
				if result.kubeChange {
					c.KubeconfigReady = result.newKubecfg
				}
			}
		}
		cw.mutex.Unlock()

		// Broadcast update after releasing lock
		cw.broadcastUpdate()
	}
}

func (cw *ClusterWatcher) broadcastUpdate() {
	// Send user-specific updates to each connected client
	cw.mutex.RLock()
	clientsCopy := make(map[*websocket.Conn]*UserWebSocketClient)
	for conn, client := range cw.clients {
		clientsCopy[conn] = client
	}
	cw.mutex.RUnlock()

	// Now send updates without holding the lock
	var toRemove []*websocket.Conn
	for conn, userClient := range clientsCopy {
		clusters := cw.GetClustersForUser(userClient.Groups)

		// Wrap clusters in an object so frontend can access data.clusters
		message := map[string]interface{}{
			"clusters": clusters,
		}

		data, err := json.Marshal(message)
		if err != nil {
			slog.Error("Failed to marshal clusters for websocket", "error", err)
			continue
		}

		if err := userClient.writeMessage(websocket.TextMessage, data); err != nil {
			conn.Close()
			toRemove = append(toRemove, conn)
		}
	}

	// Remove failed connections
	if len(toRemove) > 0 {
		cw.mutex.Lock()
		for _, conn := range toRemove {
			delete(cw.clients, conn)
		}
		cw.mutex.Unlock()
	}
}

func (cw *ClusterWatcher) AddWebSocketClient(conn *websocket.Conn, userGroups []string) {
	client := &UserWebSocketClient{
		Conn:   conn,
		Groups: userGroups,
	}
	cw.mutex.Lock()
	cw.clients[conn] = client
	cw.mutex.Unlock()

	// Send initial user-specific data in consistent format
	clusters := cw.GetClustersForUser(userGroups)
	message := map[string]interface{}{
		"clusters": clusters,
	}
	data, _ := json.Marshal(message)
	client.writeMessage(websocket.TextMessage, data)
}

func (cw *ClusterWatcher) RemoveWebSocketClient(conn *websocket.Conn) {
	cw.mutex.Lock()
	delete(cw.clients, conn)
	cw.mutex.Unlock()
}

func (cw *ClusterWatcher) GetUpgrader() *websocket.Upgrader {
	return &cw.upgrader
}

func (cw *ClusterWatcher) GetClient() dynamic.Interface {
	return cw.client
}

// GetResolver returns the CAPI version resolver used to discover served API
// versions at runtime.
func (cw *ClusterWatcher) GetResolver() *capi.Resolver {
	return cw.resolver
}

// GetClusterGVR returns the resolved GroupVersionResource for core CAPI clusters.
func (cw *ClusterWatcher) GetClusterGVR() schema.GroupVersionResource {
	return cw.clusterGVR
}

// RefreshAndBroadcast forces an immediate refresh of the cluster list from Kubernetes
// and broadcasts the update to all connected WebSocket clients.
// This is useful after create/delete operations to ensure clients see changes immediately.
func (cw *ClusterWatcher) RefreshAndBroadcast(ctx context.Context) {
	slog.Debug("Forcing cluster list refresh and broadcast")

	gvr := cw.clusterGVR

	// Fetch latest clusters from Kubernetes
	list, err := cw.client.Resource(gvr).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=chihiro",
	})
	if err != nil {
		slog.Error("Failed to refresh clusters", "error", err)
		return
	}

	slog.Debug("Refreshed cluster list", "count", len(list.Items))

	// Update internal cache, preserving last-probed kubeconfig readiness so a
	// refresh doesn't flip the UI button off until the next periodic probe.
	cw.mutex.Lock()
	prevReady := make(map[string]bool, len(cw.clusters))
	for name, c := range cw.clusters {
		prevReady[name] = c.KubeconfigReady
	}
	cw.clusters = make(map[string]*ClusterInfo)
	for _, item := range list.Items {
		clusterInfo := cw.parseCluster(&item)
		if r, ok := prevReady[clusterInfo.Name]; ok {
			clusterInfo.KubeconfigReady = r
		}
		cw.clusters[clusterInfo.Name] = clusterInfo
	}
	cw.mutex.Unlock()

	// Broadcast to all connected clients
	cw.broadcastUpdate()

	// Probe kubeconfig/endpoint readiness immediately so newly listed clusters
	// reflect their true state without waiting for the next periodic tick.
	go cw.checkAllClustersReadiness()

	slog.Debug("Cluster list refreshed and broadcast complete")
}

func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
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

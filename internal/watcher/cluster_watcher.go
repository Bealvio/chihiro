package watcher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Bealvio/chihiro/internal/capi"
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

type ClusterNetwork struct {
	PodCIDRs     []string `json:"podCIDRs"`
	ServiceCIDRs []string `json:"serviceCIDRs"`
	ServiceDomain string  `json:"serviceDomain"`
}

type ClusterInfo struct {
	Name         string                 `json:"name"`
	Namespace    string                 `json:"namespace"`
	Phase        string                 `json:"phase"`
	Ready        bool                   `json:"ready"`
	Version      string                 `json:"version"`
	Nodes        int32                  `json:"nodes"`
	CreatedAt    time.Time              `json:"createdAt"`
	Status       map[string]interface{} `json:"status"`
	InfraReady   bool                   `json:"infraReady"`
	ControlPlane bool                   `json:"controlPlane"`
	Network      *ClusterNetwork        `json:"network"`
	Labels       map[string]interface{} `json:"labels"`
	Annotations  map[string]interface{} `json:"annotations"`
	APIEndpoint  string                 `json:"apiEndpoint"`
	Groups       []string               `json:"groups"`
	Creator      string                 `json:"creator"`
	Domain       string                 `json:"domain"`
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
}

type UserWebSocketClient struct {
	Conn   *websocket.Conn
	Groups []string
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
			CheckOrigin: func(r *http.Request) bool {
				// Validate WebSocket origin to prevent CSRF attacks
				origin := r.Header.Get("Origin")
				if origin == "" {
					return false // Reject if no origin header
				}

				// Allow same-origin and localhost for development
				allowedOrigins := []string{
					"http://localhost:8080",
					"http://127.0.0.1:8080",
					r.Host, // Same origin
				}

				// Add configured allowed origins from environment
				if configOrigins := viper.GetString("allowed_origins"); configOrigins != "" {
					allowedOrigins = append(allowedOrigins, strings.Split(configOrigins, ",")...)
				}

				for _, allowed := range allowedOrigins {
					if strings.Contains(origin, allowed) {
						return true
					}
				}

				slog.Warn("WebSocket connection rejected due to invalid origin", "origin", origin, "remote_addr", r.RemoteAddr)
				return false
			},
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
			if port, ok := controlPlaneEndpoint["port"].(float64); ok {
				clusterInfo.APIEndpoint = fmt.Sprintf("https://%s:%.0f", host, port)
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
				if port, ok := controlPlaneEndpoint["port"].(float64); ok {
					clusterInfo.APIEndpoint = fmt.Sprintf("https://%s:%.0f", host, port)
					slog.Info("Parsed cluster API endpoint from spec", "cluster", clusterInfo.Name, "endpoint", clusterInfo.APIEndpoint)
				} else {
					slog.Warn("controlPlaneEndpoint missing port in spec", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
				}
			} else {
				slog.Warn("controlPlaneEndpoint missing host in spec", "cluster", clusterInfo.Name, "endpoint_data", controlPlaneEndpoint)
			}
		}
	}

	// Get domain for cluster
	domain := viper.GetString("cluster.domain")
	if domain == "" {
		domain = "bealv.io" // Default domain
	}
	clusterInfo.Domain = domain

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
			}
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

	// Extract creator from annotations
	if creatorValue, exists := clusterInfo.Annotations["chihiro.io/creator"]; exists {
		if creatorStr, ok := creatorValue.(string); ok {
			clusterInfo.Creator = creatorStr
			slog.Debug("Parsed cluster creator", "cluster", clusterInfo.Name, "creator", clusterInfo.Creator)
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

func (cw *ClusterWatcher) GetClusters() []*ClusterInfo {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()

	clusters := make([]*ClusterInfo, 0, len(cw.clusters))
	for _, cluster := range cw.clusters {
		clusters = append(clusters, cluster)
	}
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

	// We expect 200 (OK) for the /api endpoint on a working API server
	if resp.StatusCode == http.StatusOK {
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

	// Test reachability without holding lock (network calls can be slow)
	type readinessResult struct {
		cluster  *ClusterInfo
		oldReady bool
		newReady bool
	}
	results := make([]readinessResult, 0)

	for _, cluster := range clustersCopy {
		if cluster.APIEndpoint != "" {
			oldReady := cluster.Ready
			newReady := cw.testAPIEndpointReachability(cluster.APIEndpoint)

			if oldReady != newReady {
				slog.Info("Cluster readiness changed", "cluster", cluster.Name, "endpoint", cluster.APIEndpoint, "old_ready", oldReady, "new_ready", newReady)
				results = append(results, readinessResult{cluster, oldReady, newReady})
			}
		}
	}

	// Update cluster readiness with lock (fast operation)
	if len(results) > 0 {
		cw.mutex.Lock()
		for _, result := range results {
			if c, exists := cw.clusters[result.cluster.Name]; exists {
				c.Ready = result.newReady
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

		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
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
	cw.mutex.Lock()
	cw.clients[conn] = &UserWebSocketClient{
		Conn:   conn,
		Groups: userGroups,
	}
	cw.mutex.Unlock()

	// Send initial user-specific data in consistent format
	clusters := cw.GetClustersForUser(userGroups)
	message := map[string]interface{}{
		"clusters": clusters,
	}
	data, _ := json.Marshal(message)
	conn.WriteMessage(websocket.TextMessage, data)
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

	// Update internal cache
	cw.mutex.Lock()
	cw.clusters = make(map[string]*ClusterInfo)
	for _, item := range list.Items {
		clusterInfo := cw.parseCluster(&item)
		cw.clusters[clusterInfo.Name] = clusterInfo
	}
	cw.mutex.Unlock()

	// Broadcast to all connected clients
	cw.broadcastUpdate()
	slog.Debug("Cluster list refreshed and broadcast complete")
}

func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
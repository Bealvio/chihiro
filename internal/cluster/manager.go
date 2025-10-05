package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

type CreateClusterRequest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Nodes   int32  `json:"nodes"`  // Number of worker nodes
	Groups  string `json:"groups"` // Comma-separated list of groups

	// Auto-generated fields (not from frontend)
	Namespace      string `json:"-"`
	WorkerReplicas int32  `json:"-"`
	PodCIDR        string `json:"-"`
	ServiceCIDR    string `json:"-"`
	ServiceDomain  string `json:"-"`
	Creator        string `json:"-"` // Username of the creator
}

type Manager struct {
	client dynamic.Interface
}

func NewManager(client dynamic.Interface) *Manager {
	slog.Info("Initializing cluster manager")
	return &Manager{
		client: client,
	}
}

func (m *Manager) GetNextAvailableIPRange(ctx context.Context) (string, error) {
	slog.Debug("Looking for next available IP range")

	// Get all existing clusters
	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	list, err := m.client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Error("Failed to list clusters for IP range calculation", "error", err)
		return "", fmt.Errorf("failed to list clusters: %v", err)
	}

	slog.Debug("Found clusters for IP range analysis", "cluster_count", len(list.Items))

	// Track used IP ranges
	usedRanges := make(map[int]bool)

	for _, item := range list.Items {
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if topology, ok := spec["topology"].(map[string]interface{}); ok {
				if variables, ok := topology["variables"].([]interface{}); ok {
					for _, variable := range variables {
						if varMap, ok := variable.(map[string]interface{}); ok {
							if name, ok := varMap["name"].(string); ok && name == "ipv4Config" {
								if value, ok := varMap["value"].(map[string]interface{}); ok {
									if addresses, ok := value["addresses"].([]interface{}); ok && len(addresses) > 0 {
										if addr, ok := addresses[0].(string); ok {
											// Extract range number from address like "10.250.X.0-10.250.X.10"
											if rangeNum := extractRangeNumber(addr); rangeNum != -1 {
												usedRanges[rangeNum] = true
												slog.Debug("Found used IP range", "range_number", rangeNum, "address", addr)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	slog.Debug("Used IP ranges", "count", len(usedRanges), "ranges", getUsedRangeNumbers(usedRanges))

	// Find next available range from 10 to 50
	for i := 10; i <= 50; i++ {
		if !usedRanges[i] {
			ipRange := fmt.Sprintf("10.250.%d.0-10.250.%d.10", i, i)
			slog.Info("Found next available IP range", "range_number", i, "ip_range", ipRange)
			return ipRange, nil
		}
	}

	slog.Error("No available IP ranges found", "checked_range", "10.250.10.0 to 10.250.50.0", "used_count", len(usedRanges))
	return "", fmt.Errorf("no available IP ranges (10.250.10.0 to 10.250.50.0)")
}

func extractRangeNumber(address string) int {
	// Parse address like "10.250.X.0-10.250.X.10" to extract X
	parts := strings.Split(address, "-")
	if len(parts) != 2 {
		return -1
	}

	startIP := strings.Split(parts[0], ".")
	if len(startIP) != 4 || startIP[0] != "10" || startIP[1] != "250" {
		return -1
	}

	rangeNum, err := strconv.Atoi(startIP[2])
	if err != nil {
		return -1
	}

	return rangeNum
}

// ValidateClusterLimits checks if creating a new cluster would exceed configured limits
func (m *Manager) ValidateClusterLimits(ctx context.Context, newClusterNodes int32) error {
	maxClusters := viper.GetInt("cluster.limits.max_clusters")
	maxTotalNodes := viper.GetInt("cluster.limits.max_total_nodes")

	// If limits are not configured or are 0, skip validation
	if maxClusters <= 0 && maxTotalNodes <= 0 {
		slog.Debug("No cluster limits configured, skipping validation")
		return nil
	}

	// Get current cluster count and total nodes (only Chihiro-managed clusters)
	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	// Filter to only Chihiro-managed clusters
	list, err := m.client.Resource(gvr).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=chihiro",
	})
	if err != nil {
		slog.Error("Failed to list Chihiro-managed clusters for limits validation", "error", err)
		return fmt.Errorf("failed to validate cluster limits: %v", err)
	}

	currentClusters := len(list.Items)
	currentTotalNodes := int32(0)

	// Calculate current total nodes from Chihiro-managed clusters only
	for _, item := range list.Items {
		clusterName := item.GetName()
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if topology, ok := spec["topology"].(map[string]interface{}); ok {
				if workers, ok := topology["workers"].(map[string]interface{}); ok {
					if machineDeployments, ok := workers["machineDeployments"].([]interface{}); ok {
						for _, md := range machineDeployments {
							if mdMap, ok := md.(map[string]interface{}); ok {
								// Handle multiple numeric types
								if replicas, ok := mdMap["replicas"].(int64); ok {
									slog.Debug("Counting nodes from cluster", "cluster", clusterName, "replicas", replicas, "type", "int64")
									currentTotalNodes += int32(replicas)
								} else if replicas, ok := mdMap["replicas"].(float64); ok {
									slog.Debug("Counting nodes from cluster", "cluster", clusterName, "replicas", replicas, "type", "float64")
									currentTotalNodes += int32(replicas)
								} else if replicas, ok := mdMap["replicas"].(int32); ok {
									slog.Debug("Counting nodes from cluster", "cluster", clusterName, "replicas", replicas, "type", "int32")
									currentTotalNodes += replicas
								} else if replicas, ok := mdMap["replicas"].(int); ok {
									slog.Debug("Counting nodes from cluster", "cluster", clusterName, "replicas", replicas, "type", "int")
									currentTotalNodes += int32(replicas)
								} else {
									slog.Warn("Could not parse replicas count", "cluster", clusterName, "replicas_value", mdMap["replicas"], "replicas_type", fmt.Sprintf("%T", mdMap["replicas"]))
								}
							}
						}
					}
				}
			}
		}
	}

	slog.Debug("Validating cluster limits (Chihiro-managed only)", "current_clusters", currentClusters, "max_clusters", maxClusters, "current_nodes", currentTotalNodes, "max_nodes", maxTotalNodes, "new_cluster_nodes", newClusterNodes)

	// Check cluster limit
	if maxClusters > 0 && currentClusters >= maxClusters {
		slog.Warn("Cluster creation blocked: cluster limit exceeded", "current_clusters", currentClusters, "max_clusters", maxClusters)
		return fmt.Errorf("cluster limit exceeded: current %d, maximum %d clusters allowed", currentClusters, maxClusters)
	}

	// Check total nodes limit
	totalAfterCreation := currentTotalNodes + newClusterNodes
	if maxTotalNodes > 0 && totalAfterCreation > int32(maxTotalNodes) {
		slog.Warn("Cluster creation blocked: total node limit would be exceeded", "current_nodes", currentTotalNodes, "new_nodes", newClusterNodes, "total_would_be", totalAfterCreation, "max_nodes", maxTotalNodes)
		return fmt.Errorf("total node limit exceeded: current %d nodes, adding %d would result in %d nodes (maximum %d allowed)", currentTotalNodes, newClusterNodes, totalAfterCreation, maxTotalNodes)
	}

	slog.Debug("Cluster limits validation passed")
	return nil
}

func (m *Manager) CreateCluster(ctx context.Context, req CreateClusterRequest) error {
	// Use provided node count or default to 1
	if req.Nodes <= 0 {
		req.Nodes = 1
	}

	// Validate cluster limits before proceeding
	if err := m.ValidateClusterLimits(ctx, req.Nodes); err != nil {
		slog.Error("Cluster creation blocked by limits", "cluster_name", req.Name, "error", err)
		return err
	}

	slog.Debug("Starting cluster creation", "name", req.Name, "nodes", req.Nodes, "version", req.Version)

	// Get next available IP range
	ipRange, err := m.GetNextAvailableIPRange(ctx)
	if err != nil {
		slog.Error("Failed to get IP range for cluster creation", "cluster_name", req.Name, "error", err)
		return fmt.Errorf("failed to get IP range: %v", err)
	}

	// Set default groups if not provided
	groups := req.Groups
	if groups == "" {
		// Use admin groups from config as default
		adminGroups := viper.GetStringSlice("cluster.admin_groups")
		if len(adminGroups) == 0 {
			adminGroups = []string{"cluster-admin"}
		}
		groups = strings.Join(adminGroups, ",")
		slog.Debug("Using admin groups as default for cluster", "cluster_name", req.Name, "groups", groups, "admin_groups", adminGroups)
	} else {
		slog.Debug("Using provided groups for cluster", "cluster_name", req.Name, "groups", groups)
	}

	// Load cluster template from config
	templateStr := viper.GetString("cluster.template")
	if templateStr == "" {
		slog.Error("No cluster template configured")
		return fmt.Errorf("cluster template not configured in config file")
	}

	// Apply replacements to template
	serviceDomain := req.Name + ".local"
	templateStr = strings.ReplaceAll(templateStr, "PLACEHOLDER_NAME", req.Name)
	templateStr = strings.ReplaceAll(templateStr, "PLACEHOLDER_VERSION", req.Version)
	templateStr = strings.ReplaceAll(templateStr, "PLACEHOLDER_GROUPS", groups)
	templateStr = strings.ReplaceAll(templateStr, "PLACEHOLDER_SERVICE_DOMAIN", serviceDomain)
	templateStr = strings.ReplaceAll(templateStr, "PLACEHOLDER_IP_RANGE", ipRange)
	templateStr = strings.ReplaceAll(templateStr, "PLACEHOLDER_NODES", fmt.Sprintf("%d", req.Nodes))

	slog.Debug("Applied template replacements", "cluster_name", req.Name, "nodes", req.Nodes, "ip_range", ipRange)

	// Parse YAML template into unstructured object
	cluster := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(templateStr), &cluster.Object); err != nil {
		slog.Error("Failed to parse cluster template", "error", err)
		return fmt.Errorf("failed to parse cluster template: %v", err)
	}

	// Add Chihiro-specific labels and annotations on top of template
	labels := cluster.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["app.kubernetes.io/managed-by"] = "chihiro"
	labels["cluster.x-k8s.io/cluster-name"] = req.Name
	labels["sveltos-agent"] = "present"
	labels["topology.cluster.x-k8s.io/owned"] = ""
	cluster.SetLabels(labels)

	annotations := cluster.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["chihiro.io/groups"] = groups
	if req.Creator != "" {
		annotations["chihiro.io/creator"] = req.Creator
	}
	cluster.SetAnnotations(annotations)

	slog.Debug("Added Chihiro management labels and annotations", "cluster_name", req.Name)

	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	namespace := cluster.GetNamespace()
	if namespace == "" {
		namespace = "capi-system"
	}

	_, err = m.client.Resource(gvr).Namespace(namespace).Create(ctx, cluster, metav1.CreateOptions{})
	if err != nil {
		slog.Error("Failed to create cluster resource", "cluster_name", req.Name, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to create cluster: %v", err)
	}

	slog.Info("Successfully created cluster", "name", req.Name, "namespace", namespace, "ip_range", ipRange, "nodes", req.Nodes, "version", req.Version, "groups", groups)
	return nil
}

func (m *Manager) DeleteCluster(ctx context.Context, name, namespace string) error {
	slog.Debug("Starting cluster deletion", "cluster_name", name, "namespace", namespace)

	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	err := m.client.Resource(gvr).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		slog.Error("Failed to delete cluster resource", "cluster_name", name, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to delete cluster: %v", err)
	}

	slog.Info("Successfully deleted cluster", "name", name, "namespace", namespace)
	return nil
}

// UpdateClusterGroups updates the groups annotation for a cluster
func (m *Manager) UpdateClusterGroups(ctx context.Context, clusterName, namespace, groups string) error {
	slog.Debug("Updating cluster groups", "cluster", clusterName, "namespace", namespace, "groups", groups)

	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	// Get the current cluster
	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for groups update", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	// Update the annotations
	if cluster.Object["metadata"] == nil {
		cluster.Object["metadata"] = make(map[string]interface{})
	}

	metadata := cluster.Object["metadata"].(map[string]interface{})
	if metadata["annotations"] == nil {
		metadata["annotations"] = make(map[string]interface{})
	}

	annotations := metadata["annotations"].(map[string]interface{})
	annotations["chihiro.io/groups"] = groups

	// Update the cluster
	_, err = m.client.Resource(gvr).Namespace(namespace).Update(ctx, cluster, metav1.UpdateOptions{})
	if err != nil {
		slog.Error("Failed to update cluster groups", "cluster", clusterName, "namespace", namespace, "groups", groups, "error", err)
		return fmt.Errorf("failed to update cluster groups: %v", err)
	}

	slog.Info("Successfully updated cluster groups", "cluster", clusterName, "namespace", namespace, "groups", groups)
	return nil
}

// ValidateNodeCountUpdate checks if updating node count would exceed total node limits
func (m *Manager) ValidateNodeCountUpdate(ctx context.Context, clusterName, namespace string, newNodeCount int32) error {
	maxTotalNodes := viper.GetInt("cluster.limits.max_total_nodes")

	// If no total node limit is configured, skip validation
	if maxTotalNodes <= 0 {
		slog.Debug("No total node limit configured, skipping validation")
		return nil
	}

	// Get current cluster to find its current node count
	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for node count validation", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	// Get current node count for this cluster
	currentClusterNodes := int32(0)
	if spec, ok := cluster.Object["spec"].(map[string]interface{}); ok {
		if topology, ok := spec["topology"].(map[string]interface{}); ok {
			if workers, ok := topology["workers"].(map[string]interface{}); ok {
				if machineDeployments, ok := workers["machineDeployments"].([]interface{}); ok {
					for _, md := range machineDeployments {
						if mdMap, ok := md.(map[string]interface{}); ok {
							if replicas, ok := mdMap["replicas"].(float64); ok {
								currentClusterNodes += int32(replicas)
							}
						}
					}
				}
			}
		}
	}

	// Calculate total nodes across all Chihiro-managed clusters (including this update)
	list, err := m.client.Resource(gvr).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=chihiro",
	})
	if err != nil {
		slog.Error("Failed to list Chihiro-managed clusters for node count validation", "error", err)
		return fmt.Errorf("failed to validate node limits: %v", err)
	}

	totalNodes := int32(0)
	for _, item := range list.Items {
		if item.GetName() == clusterName && item.GetNamespace() == namespace {
			// Use the new node count for this cluster
			totalNodes += newNodeCount
		} else {
			// Use current node count for other clusters
			if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
				if topology, ok := spec["topology"].(map[string]interface{}); ok {
					if workers, ok := topology["workers"].(map[string]interface{}); ok {
						if machineDeployments, ok := workers["machineDeployments"].([]interface{}); ok {
							for _, md := range machineDeployments {
								if mdMap, ok := md.(map[string]interface{}); ok {
									if replicas, ok := mdMap["replicas"].(float64); ok {
										totalNodes += int32(replicas)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	slog.Debug("Validating node count update (Chihiro-managed only)", "cluster", clusterName, "current_nodes", currentClusterNodes, "new_nodes", newNodeCount, "total_nodes_after", totalNodes, "max_nodes", maxTotalNodes)

	if totalNodes > int32(maxTotalNodes) {
		slog.Warn("Node count update blocked: total node limit exceeded", "cluster", clusterName, "current_nodes", currentClusterNodes, "new_nodes", newNodeCount, "total_would_be", totalNodes, "max_nodes", maxTotalNodes)
		return fmt.Errorf("total node limit exceeded: updating cluster %s to %d nodes would result in %d total nodes, maximum %d allowed", clusterName, newNodeCount, totalNodes, maxTotalNodes)
	}

	slog.Debug("Node count update validation passed")
	return nil
}

// UpdateClusterNodeCount updates the number of worker nodes in a cluster
func (m *Manager) UpdateClusterNodeCount(ctx context.Context, clusterName, namespace string, nodeCount int32) error {
	slog.Debug("Updating cluster node count", "cluster", clusterName, "namespace", namespace, "nodes", nodeCount)

	// Validate node count limits
	if err := m.ValidateNodeCountUpdate(ctx, clusterName, namespace, nodeCount); err != nil {
		return err
	}

	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for node count update", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	// Update the machine deployment replicas
	if spec, ok := cluster.Object["spec"].(map[string]interface{}); ok {
		if topology, ok := spec["topology"].(map[string]interface{}); ok {
			if workers, ok := topology["workers"].(map[string]interface{}); ok {
				if machineDeployments, ok := workers["machineDeployments"].([]interface{}); ok {
					for _, md := range machineDeployments {
						if mdMap, ok := md.(map[string]interface{}); ok {
							mdMap["replicas"] = int64(nodeCount)
						}
					}
				}
			}
		}
	}

	_, err = m.client.Resource(gvr).Namespace(namespace).Update(ctx, cluster, metav1.UpdateOptions{})
	if err != nil {
		slog.Error("Failed to update cluster node count", "cluster", clusterName, "namespace", namespace, "nodes", nodeCount, "error", err)
		return fmt.Errorf("failed to update cluster: %v", err)
	}

	slog.Info("Successfully updated cluster node count", "cluster", clusterName, "namespace", namespace, "nodes", nodeCount)
	return nil
}

// ValidateVersionUpgrade checks if the new version is valid and newer than current version
func (m *Manager) ValidateVersionUpgrade(ctx context.Context, clusterName, namespace, newVersion string) error {
	// Get available versions from config
	availableVersions := viper.GetStringSlice("cluster.available_versions")
	if len(availableVersions) == 0 {
		slog.Warn("No available versions configured, skipping validation")
		return nil
	}

	// Check if the new version is in the list of available versions
	versionFound := false
	for _, version := range availableVersions {
		if version == newVersion {
			versionFound = true
			break
		}
	}

	if !versionFound {
		slog.Warn("Requested version not in available versions list", "cluster", clusterName, "requested_version", newVersion, "available_versions", availableVersions)
		return fmt.Errorf("version %s is not available for upgrade. Available versions: %v", newVersion, availableVersions)
	}

	// Get current cluster version
	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for version validation", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	// Extract current version from cluster spec
	currentVersion := ""
	if spec, ok := cluster.Object["spec"].(map[string]interface{}); ok {
		if topology, ok := spec["topology"].(map[string]interface{}); ok {
			if version, ok := topology["version"].(string); ok {
				currentVersion = version
			}
		}
	}

	if currentVersion == "" {
		slog.Debug("No current version found, allowing upgrade", "cluster", clusterName)
		return nil
	}

	// Compare versions to ensure upgrade only
	if !isVersionNewer(newVersion, currentVersion) {
		slog.Warn("Version upgrade blocked: new version is not newer", "cluster", clusterName, "current_version", currentVersion, "requested_version", newVersion)
		return fmt.Errorf("version %s is not newer than current version %s. Only upgrades are allowed", newVersion, currentVersion)
	}

	slog.Debug("Version upgrade validation passed", "cluster", clusterName, "current_version", currentVersion, "new_version", newVersion)
	return nil
}

// isVersionNewer compares two semantic versions and returns true if version1 is newer than version2
func isVersionNewer(version1, version2 string) bool {
	// Simple semantic version comparison (v1.2.3 format)
	if version1 == "" || version2 == "" {
		return version1 != ""
	}

	v1Parts := strings.Split(strings.TrimPrefix(version1, "v"), ".")
	v2Parts := strings.Split(strings.TrimPrefix(version2, "v"), ".")

	// Pad shorter version with zeros
	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for len(v1Parts) < maxLen {
		v1Parts = append(v1Parts, "0")
	}
	for len(v2Parts) < maxLen {
		v2Parts = append(v2Parts, "0")
	}

	for i := 0; i < maxLen; i++ {
		var v1Num, v2Num int
		fmt.Sscanf(v1Parts[i], "%d", &v1Num)
		fmt.Sscanf(v2Parts[i], "%d", &v2Num)

		if v1Num > v2Num {
			return true
		} else if v1Num < v2Num {
			return false
		}
	}

	return false // Versions are equal
}

// UpdateClusterVersion updates the Kubernetes version of a cluster
func (m *Manager) UpdateClusterVersion(ctx context.Context, clusterName, namespace, version string) error {
	slog.Debug("Updating cluster version", "cluster", clusterName, "namespace", namespace, "version", version)

	// Validate version upgrade
	if err := m.ValidateVersionUpgrade(ctx, clusterName, namespace, version); err != nil {
		return err
	}

	gvr := schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for version update", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	// Update the cluster version in the topology
	if spec, ok := cluster.Object["spec"].(map[string]interface{}); ok {
		if topology, ok := spec["topology"].(map[string]interface{}); ok {
			topology["version"] = version
		}
	}

	_, err = m.client.Resource(gvr).Namespace(namespace).Update(ctx, cluster, metav1.UpdateOptions{})
	if err != nil {
		slog.Error("Failed to update cluster version", "cluster", clusterName, "namespace", namespace, "version", version, "error", err)
		return fmt.Errorf("failed to update cluster: %v", err)
	}

	slog.Info("Successfully updated cluster version", "cluster", clusterName, "namespace", namespace, "version", version)
	return nil
}

// Helper function to get a list of used range numbers for logging
func getUsedRangeNumbers(usedRanges map[int]bool) []int {
	var ranges []int
	for rangeNum := range usedRanges {
		ranges = append(ranges, rangeNum)
	}
	return ranges
}

package cluster

import (
	"context"
	"encoding/json"
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

// WorkerGroup describes a group of worker nodes. The named fields below are
// retained for backward compatibility with previously stored annotations and
// the watcher/limit code, but worker groups are otherwise generic: every value
// from the config-driven worker_group_fields schema is captured in Values
// (keyed by field key), so arbitrary fields round-trip through the API and the
// stored annotation.
type WorkerGroup struct {
	Name     string `json:"name"`
	Class    string `json:"class,omitempty"`
	Flavor   string `json:"flavor,omitempty"`
	Replicas int32  `json:"replicas"`

	// Values holds every worker_group_fields value keyed by field key. It is
	// populated from the named fields above and from any extra JSON keys.
	Values map[string]string `json:"-"`
}

// workerGroupAlias avoids infinite recursion in the custom (Un)MarshalJSON.
type workerGroupAlias WorkerGroup

// UnmarshalJSON captures the known fields plus every extra key into Values so
// generic worker_group_fields survive the round-trip from the frontend.
func (w *WorkerGroup) UnmarshalJSON(data []byte) error {
	var alias workerGroupAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*w = WorkerGroup(alias)

	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	if w.Values == nil {
		w.Values = make(map[string]string, len(all))
	}
	for key, rawVal := range all {
		// Decode each value as a string, tolerating numbers/bools.
		var s string
		if err := json.Unmarshal(rawVal, &s); err != nil {
			var n json.Number
			if err2 := json.Unmarshal(rawVal, &n); err2 == nil {
				s = n.String()
			} else {
				var b bool
				if err3 := json.Unmarshal(rawVal, &b); err3 == nil {
					s = strconv.FormatBool(b)
				} else {
					continue
				}
			}
		}
		w.Values[key] = s
	}
	// Keep the named fields and Values in sync for legacy callers.
	w.syncValuesFromNamed()
	return nil
}

// MarshalJSON emits the named fields plus every extra Values key so the stored
// annotation preserves generic fields.
func (w WorkerGroup) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{}, len(w.Values)+4)
	for k, v := range w.Values {
		out[k] = v
	}
	out["name"] = w.Name
	if w.Class != "" {
		out["class"] = w.Class
	}
	if w.Flavor != "" {
		out["flavor"] = w.Flavor
	}
	out["replicas"] = w.Replicas
	return json.Marshal(out)
}

// syncValuesFromNamed ensures the named legacy fields are mirrored into Values
// (Values takes precedence when both are present).
func (w *WorkerGroup) syncValuesFromNamed() {
	if w.Values == nil {
		w.Values = make(map[string]string)
	}
	if _, ok := w.Values["name"]; !ok && w.Name != "" {
		w.Values["name"] = w.Name
	}
	if _, ok := w.Values["class"]; !ok && w.Class != "" {
		w.Values["class"] = w.Class
	}
	if _, ok := w.Values["flavor"]; !ok && w.Flavor != "" {
		w.Values["flavor"] = w.Flavor
	}
	if _, ok := w.Values["replicas"]; !ok && w.Replicas != 0 {
		w.Values["replicas"] = strconv.Itoa(int(w.Replicas))
	}
	// Backfill named fields from Values for legacy consumers.
	if w.Name == "" {
		w.Name = w.Values["name"]
	}
	if w.Class == "" {
		w.Class = w.Values["class"]
	}
	if w.Flavor == "" {
		w.Flavor = w.Values["flavor"]
	}
	if w.Replicas == 0 {
		if r, err := strconv.Atoi(w.Values["replicas"]); err == nil {
			w.Replicas = int32(r)
		}
	}
}

type CreateClusterRequest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Nodes                int32             `json:"nodes"`                // Number of worker nodes (legacy, used when WorkerGroups is empty)
	ControlPlaneReplicas int32             `json:"controlPlaneReplicas"` // Number of control plane replicas
	Groups               string            `json:"groups"`               // Comma-separated list of groups
	WorkerGroups         []WorkerGroup     `json:"workerGroups"`         // Heterogeneous worker groups
	Parameters           map[string]string `json:"parameters"`           // Dynamic template parameters

	// Auto-generated fields (not from frontend)
	Namespace      string `json:"-"`
	WorkerReplicas int32  `json:"-"`
	PodCIDR        string `json:"-"`
	ServiceCIDR    string `json:"-"`
	ServiceDomain  string `json:"-"`
	Creator        string `json:"-"` // Username of the creator
}

type Manager struct {
	client     dynamic.Interface
	clusterGVR schema.GroupVersionResource
}

func NewManager(client dynamic.Interface, clusterGVR schema.GroupVersionResource) *Manager {
	slog.Info("Initializing cluster manager", "clusterGVR", clusterGVR.String())
	return &Manager{
		client:     client,
		clusterGVR: clusterGVR,
	}
}

func (m *Manager) GetNextAvailableIPRange(ctx context.Context) (string, error) {
	slog.Debug("Looking for next available IP range")

	// Get all existing clusters
	gvr := m.clusterGVR

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
func (m *Manager) ValidateClusterLimits(ctx context.Context, newClusterNodes, newClusterCPReplicas int32) error {
	maxClusters := viper.GetInt("cluster.limits.max_clusters")
	maxTotalNodes := viper.GetInt("cluster.limits.max_total_nodes")
	maxTotalCP := viper.GetInt("cluster.limits.max_total_cp")

	// If limits are not configured or are 0, skip validation
	if maxClusters <= 0 && maxTotalNodes <= 0 && maxTotalCP <= 0 {
		slog.Debug("No cluster limits configured, skipping validation")
		return nil
	}

	// Get current cluster count and total nodes (only Chihiro-managed clusters)
	gvr := m.clusterGVR

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
	currentTotalCP := int32(0)

	// Calculate current total nodes from Chihiro-managed clusters only
	for _, item := range list.Items {
		clusterName := item.GetName()
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if topology, ok := spec["topology"].(map[string]interface{}); ok {
				// Count control plane replicas
				if controlPlane, ok := topology["controlPlane"].(map[string]interface{}); ok {
					currentTotalCP += parseReplicas(controlPlane["replicas"], clusterName)
				}
				if workers, ok := topology["workers"].(map[string]interface{}); ok {
					if machineDeployments, ok := workers["machineDeployments"].([]interface{}); ok {
						for _, md := range machineDeployments {
							if mdMap, ok := md.(map[string]interface{}); ok {
								currentTotalNodes += parseReplicas(mdMap["replicas"], clusterName)
							}
						}
					}
				}
			}
		}
	}

	slog.Debug("Validating cluster limits (Chihiro-managed only)", "current_clusters", currentClusters, "max_clusters", maxClusters, "current_nodes", currentTotalNodes, "max_nodes", maxTotalNodes, "current_cp", currentTotalCP, "max_cp", maxTotalCP, "new_cluster_nodes", newClusterNodes, "new_cluster_cp", newClusterCPReplicas)

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

	// Check total control plane replicas limit
	cpAfterCreation := currentTotalCP + newClusterCPReplicas
	if maxTotalCP > 0 && cpAfterCreation > int32(maxTotalCP) {
		slog.Warn("Cluster creation blocked: total control plane limit would be exceeded", "current_cp", currentTotalCP, "new_cp", newClusterCPReplicas, "total_would_be", cpAfterCreation, "max_cp", maxTotalCP)
		return fmt.Errorf("total control plane limit exceeded: current %d control plane replicas, adding %d would result in %d (maximum %d allowed)", currentTotalCP, newClusterCPReplicas, cpAfterCreation, maxTotalCP)
	}

	slog.Debug("Cluster limits validation passed")
	return nil
}

// parseReplicas extracts a replica count from an unstructured field that may be
// any of the numeric types returned by the dynamic client (int64, float64,
// int32, int). Returns 0 if the value is missing or of an unexpected type.
func parseReplicas(value interface{}, clusterName string) int32 {
	switch v := value.(type) {
	case int64:
		return int32(v)
	case float64:
		return int32(v)
	case int32:
		return v
	case int:
		return int32(v)
	case nil:
		return 0
	default:
		slog.Warn("Could not parse replicas count", "cluster", clusterName, "replicas_value", value, "replicas_type", fmt.Sprintf("%T", value))
		return 0
	}
}

// CountControlPlaneReplicas returns the total control plane replicas across all
// Chihiro-managed clusters.
func (m *Manager) CountControlPlaneReplicas(ctx context.Context) (int32, error) {
	list, err := m.client.Resource(m.clusterGVR).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=chihiro",
	})
	if err != nil {
		slog.Error("Failed to list Chihiro-managed clusters for control plane count", "error", err)
		return 0, fmt.Errorf("failed to count control plane replicas: %v", err)
	}

	total := int32(0)
	for _, item := range list.Items {
		clusterName := item.GetName()
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if topology, ok := spec["topology"].(map[string]interface{}); ok {
				if controlPlane, ok := topology["controlPlane"].(map[string]interface{}); ok {
					total += parseReplicas(controlPlane["replicas"], clusterName)
				}
			}
		}
	}

	return total, nil
}

func (m *Manager) CreateCluster(ctx context.Context, req CreateClusterRequest) error {
	// Normalise worker groups: if none supplied, synthesise a single default
	// pool from the worker_group_fields schema defaults and the "nodes" field.
	if len(req.WorkerGroups) == 0 {
		nodes := req.Nodes
		if nodes <= 0 {
			nodes = 1
		}
		values := make(map[string]string)
		for _, f := range LoadWorkerGroupFields() {
			if f.Default != "" {
				values[f.Key] = f.Default
			}
		}
		if values["name"] == "" {
			values["name"] = "worker"
		}
		values["replicas"] = strconv.Itoa(int(nodes))
		wg := WorkerGroup{Values: values}
		wg.syncValuesFromNamed()
		req.WorkerGroups = []WorkerGroup{wg}
	}

	// Compute total worker replicas across all groups, keeping Values in sync.
	totalWorkerReplicas := int32(0)
	for i := range req.WorkerGroups {
		req.WorkerGroups[i].syncValuesFromNamed()
		if req.WorkerGroups[i].Replicas <= 0 {
			req.WorkerGroups[i].Replicas = 1
			req.WorkerGroups[i].Values["replicas"] = "1"
		}
		totalWorkerReplicas += req.WorkerGroups[i].Replicas
	}
	req.Nodes = totalWorkerReplicas

	// Use provided control plane replicas or default to 3
	if req.ControlPlaneReplicas <= 0 {
		req.ControlPlaneReplicas = 3
	}

	// Validate cluster limits before proceeding
	if err := m.ValidateClusterLimits(ctx, req.Nodes, req.ControlPlaneReplicas); err != nil {
		slog.Error("Cluster creation blocked by limits", "cluster_name", req.Name, "error", err)
		return err
	}

	slog.Debug("Starting cluster creation", "name", req.Name, "worker_groups", len(req.WorkerGroups), "total_nodes", req.Nodes, "version", req.Version)

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

	// Built-in values that can be referenced as {{ chihiro.* }} tokens directly
	// in the template, in addition to being injected at configured YAML paths.
	// Keyed by lowercase for case-insensitive matching against the template's
	// original casing.
	builtinTokens := map[string]string{
		"name":                 req.Name,
		"version":              req.Version,
		"groups":               groups,
		"servicedomain":        serviceDomain,
		"iprange":              ipRange,
		"nodes":                strconv.Itoa(int(req.Nodes)),
		"controlplanereplicas": strconv.Itoa(int(req.ControlPlaneReplicas)),
	}

	// Inject user-defined dynamic template parameters — scan template for all
	// {{ chihiro.* }} placeholders and resolve each from req.Parameters first,
	// then fall back to config defaults, then to built-in tokens.
	// Defaults may themselves contain {{ chihiro.* }} references (e.g.
	// "hephaestus-kaas-26.05-{{ chihiro.version }}"), so we loop until all
	// placeholders are resolved or no progress is made.
	if req.Parameters == nil {
		req.Parameters = make(map[string]string)
	}
	defaults := GetParameterDefaults()
	// Resolve boolean parameters up-front to their configured on/off strings.
	// This is kept separate from the string-default path because a boolean's
	// "off" string may legitimately be empty, which the value == "" check below
	// would otherwise treat as unresolved.
	boolResolved := resolveBooleanParameters(req.Parameters)
	resolvedParams := make(map[string]string)
	const maxIterations = 10
	for iter := 0; iter < maxIterations; iter++ {
		matches := chihiroParamRegex.FindAllStringSubmatch(templateStr, -1)
		if len(matches) == 0 {
			break
		}
		replaced := false
		for _, match := range matches {
			key := match[1]
			placeholder := fmt.Sprintf("{{ chihiro.%s }}", key)

			// Already resolved in a previous iteration — skip.
			if strings.Contains(templateStr, placeholder) == false {
				continue
			}

			// Boolean parameters resolve to their on/off string (possibly empty).
			if bv, ok := boolResolved[strings.ToLower(key)]; ok {
				resolvedParams[key] = bv
				slog.Info("Replacing boolean template placeholder", "cluster_name", req.Name, "key", key, "value", bv)
				templateStr = strings.ReplaceAll(templateStr, placeholder, bv)
				replaced = true
				continue
			}

			value := req.Parameters[key]
			if value == "" {
				// Config defaults come from viper which lowercases all keys, so
				// match case-insensitively against the template's original casing.
				if v, ok := defaults[key]; ok {
					value = v
				} else {
					value = defaults[strings.ToLower(key)]
				}
			}
			if value == "" {
				// Fall back to built-in tokens (name, version, nodes, ipRange, …).
				value = builtinTokens[strings.ToLower(key)]
			}
			if value == "" {
				slog.Warn("Template parameter has no value and no default", "cluster_name", req.Name, "key", key)
				continue
			}
			resolvedParams[key] = value
			slog.Info("Replacing template placeholder", "cluster_name", req.Name, "key", key, "placeholder", placeholder, "value", value)
			templateStr = strings.ReplaceAll(templateStr, placeholder, value)
			replaced = true
		}
		if !replaced {
			break
		}
	}

	// Log any remaining unreplaced placeholders
	remainingMatches := chihiroParamRegex.FindAllString(templateStr, -1)
	if len(remainingMatches) > 0 {
		slog.Error("Unreplaced template placeholders remain", "cluster_name", req.Name, "remaining", remainingMatches)
		return fmt.Errorf("unresolved template parameters: %v — provide values in the form or set defaults in cluster.parameters config", remainingMatches)
	}

	// Parse YAML template into unstructured object
	cluster := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(templateStr), &cluster.Object); err != nil {
		slog.Error("Failed to parse cluster template", "error", err)
		return fmt.Errorf("failed to parse cluster template: %v", err)
	}

	// Inject built-in values at configured YAML paths. viper lowercases the
	// injection map keys, so key the builtins map by lowercase too and look up
	// case-insensitively.
	builtins := map[string]interface{}{
		"name":                 req.Name,
		"version":              req.Version,
		"groups":               groups,
		"servicedomain":        serviceDomain,
		"iprange":              ipRange,
		"nodes":                req.Nodes,
		"controlplanereplicas": req.ControlPlaneReplicas,
	}
	for key, inj := range loadInjectionConfig() {
		if inj.Path == "" {
			continue
		}
		if val, ok := builtins[strings.ToLower(key)]; ok {
			setYAMLPath(cluster.Object, inj.Path, val)
		}
	}

	// Build the machineDeployments array from worker groups and inject it
	// into the topology, replacing the single placeholder from the template.
	if err := m.injectWorkerGroups(cluster.Object, req.WorkerGroups); err != nil {
		slog.Error("Failed to inject worker groups", "cluster_name", req.Name, "error", err)
		return fmt.Errorf("failed to inject worker groups: %v", err)
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
	// Persist worker groups as JSON so the UI can display and edit them.
	if wgJSON, err := json.Marshal(req.WorkerGroups); err == nil {
		annotations["chihiro.io/worker-groups"] = string(wgJSON)
	} else {
		slog.Warn("Failed to marshal worker groups annotation", "cluster_name", req.Name, "error", err)
	}
	// Persist the resolved template parameters so the UI can display exactly
	// what was set for this cluster.
	if len(resolvedParams) > 0 {
		if paramsJSON, err := json.Marshal(resolvedParams); err == nil {
			annotations["chihiro.io/parameters"] = string(paramsJSON)
		} else {
			slog.Warn("Failed to marshal resolved parameters annotation", "cluster_name", req.Name, "error", err)
		}
	}
	cluster.SetAnnotations(annotations)

	slog.Debug("Added Chihiro management labels and annotations", "cluster_name", req.Name)

	gvr := m.clusterGVR

	// Force the apiVersion to the version the API server actually serves so the
	// request body matches the REST endpoint (the template may pin an older
	// version such as v1beta1 that the cluster no longer serves).
	cluster.SetAPIVersion(gvr.GroupVersion().String())
	cluster.SetKind("Cluster")

	namespace := cluster.GetNamespace()
	if namespace == "" {
		namespace = "capi-system"
	}

	_, err = m.client.Resource(gvr).Namespace(namespace).Create(ctx, cluster, metav1.CreateOptions{})
	if err != nil {
		slog.Error("Failed to create cluster resource", "cluster_name", req.Name, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to create cluster: %v", err)
	}

	slog.Info("Successfully created cluster", "name", req.Name, "namespace", namespace, "ip_range", ipRange, "nodes", req.Nodes, "control_plane_replicas", req.ControlPlaneReplicas, "version", req.Version, "groups", groups)
	return nil
}

func (m *Manager) DeleteCluster(ctx context.Context, name, namespace string) error {
	slog.Debug("Starting cluster deletion", "cluster_name", name, "namespace", namespace)

	gvr := m.clusterGVR

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

	gvr := m.clusterGVR

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
	gvr := m.clusterGVR

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

	gvr := m.clusterGVR

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

// ValidateControlPlaneUpdate checks that the requested control plane replica
// count is within the configured per-field min/max bounds and does not push the
// total control plane replicas across all Chihiro-managed clusters over the
// configured max_total_cp limit.
func (m *Manager) ValidateControlPlaneUpdate(ctx context.Context, clusterName, namespace string, newReplicas int32) error {
	// Enforce configured min/max bounds for the controlPlaneReplicas field.
	if field, ok := GetEditableField(viper.GetString("cluster.template"), "controlPlaneReplicas"); ok {
		if field.Min != nil && int(newReplicas) < *field.Min {
			return fmt.Errorf("control plane replicas must be at least %d", *field.Min)
		}
		if field.Max != nil && int(newReplicas) > *field.Max {
			return fmt.Errorf("control plane replicas must be at most %d", *field.Max)
		}
	}

	maxTotalCP := viper.GetInt("cluster.limits.max_total_cp")
	if maxTotalCP <= 0 {
		slog.Debug("No total control plane limit configured, skipping limit validation")
		return nil
	}

	gvr := m.clusterGVR

	list, err := m.client.Resource(gvr).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=chihiro",
	})
	if err != nil {
		slog.Error("Failed to list Chihiro-managed clusters for control plane validation", "error", err)
		return fmt.Errorf("failed to validate control plane limits: %v", err)
	}

	totalCP := int32(0)
	for _, item := range list.Items {
		if item.GetName() == clusterName && item.GetNamespace() == namespace {
			totalCP += newReplicas
			continue
		}
		name := item.GetName()
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if topology, ok := spec["topology"].(map[string]interface{}); ok {
				if controlPlane, ok := topology["controlPlane"].(map[string]interface{}); ok {
					totalCP += parseReplicas(controlPlane["replicas"], name)
				}
			}
		}
	}

	slog.Debug("Validating control plane update (Chihiro-managed only)", "cluster", clusterName, "new_cp", newReplicas, "total_cp_after", totalCP, "max_cp", maxTotalCP)

	if totalCP > int32(maxTotalCP) {
		slog.Warn("Control plane update blocked: total control plane limit exceeded", "cluster", clusterName, "new_cp", newReplicas, "total_would_be", totalCP, "max_cp", maxTotalCP)
		return fmt.Errorf("total control plane limit exceeded: updating cluster %s to %d control plane replicas would result in %d total, maximum %d allowed", clusterName, newReplicas, totalCP, maxTotalCP)
	}

	slog.Debug("Control plane update validation passed")
	return nil
}

// UpdateClusterControlPlaneReplicas updates the number of control plane
// replicas in a cluster's topology.
func (m *Manager) UpdateClusterControlPlaneReplicas(ctx context.Context, clusterName, namespace string, replicas int32) error {
	slog.Debug("Updating cluster control plane replicas", "cluster", clusterName, "namespace", namespace, "replicas", replicas)

	if err := m.ValidateControlPlaneUpdate(ctx, clusterName, namespace, replicas); err != nil {
		return err
	}

	gvr := m.clusterGVR

	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for control plane update", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	// Update the control plane replicas in the topology.
	spec, ok := cluster.Object["spec"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("cluster %s has no spec", clusterName)
	}
	topology, ok := spec["topology"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("cluster %s has no topology", clusterName)
	}
	controlPlane, ok := topology["controlPlane"].(map[string]interface{})
	if !ok {
		controlPlane = make(map[string]interface{})
		topology["controlPlane"] = controlPlane
	}
	controlPlane["replicas"] = int64(replicas)

	_, err = m.client.Resource(gvr).Namespace(namespace).Update(ctx, cluster, metav1.UpdateOptions{})
	if err != nil {
		slog.Error("Failed to update cluster control plane replicas", "cluster", clusterName, "namespace", namespace, "replicas", replicas, "error", err)
		return fmt.Errorf("failed to update cluster: %v", err)
	}

	slog.Info("Successfully updated cluster control plane replicas", "cluster", clusterName, "namespace", namespace, "replicas", replicas)
	return nil
}

// UpdateClusterParameter writes an editable template parameter's value to the
// live cluster object at its configured YAML path and records the raw state in
// the chihiro.io/parameters annotation. For boolean parameters, rawState is the
// "true"/"false" toggle state and the configured on/off string is written at
// the path. The parameter must be editable and have a path configured.
func (m *Manager) UpdateClusterParameter(ctx context.Context, clusterName, namespace, key, rawState string) error {
	slog.Debug("Updating cluster parameter", "cluster", clusterName, "namespace", namespace, "key", key)

	ef, ok := GetEditableField(viper.GetString("cluster.template"), key)
	if !ok || !ef.Enabled {
		return fmt.Errorf("parameter %q is not editable", key)
	}
	if ef.Path == "" {
		return fmt.Errorf("parameter %q has no configured path and cannot be edited", key)
	}

	// Compute the value written to the object and the state stored in the
	// annotation (so the UI can re-render the control correctly).
	var writeValue interface{}
	storedState := rawState
	switch ef.Type {
	case "boolean":
		if isTruthy(rawState) {
			writeValue = ef.TrueValue
			storedState = "true"
		} else {
			writeValue = ef.FalseValue
			storedState = "false"
		}
	case "number":
		if n, err := strconv.Atoi(strings.TrimSpace(rawState)); err == nil {
			writeValue = int64(n)
		} else {
			return fmt.Errorf("parameter %q expects a number", key)
		}
	default:
		writeValue = rawState
	}

	gvr := m.clusterGVR
	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for parameter update", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	setYAMLPath(cluster.Object, ef.Path, writeValue)

	// Update the persisted parameters annotation so the value round-trips.
	annotations := cluster.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	params := map[string]string{}
	if existing, ok := annotations["chihiro.io/parameters"]; ok && existing != "" {
		if err := json.Unmarshal([]byte(existing), &params); err != nil {
			slog.Warn("Failed to parse existing parameters annotation; recreating", "cluster", clusterName, "error", err)
			params = map[string]string{}
		}
	}
	params[key] = storedState
	if paramsJSON, err := json.Marshal(params); err == nil {
		annotations["chihiro.io/parameters"] = string(paramsJSON)
		cluster.SetAnnotations(annotations)
	} else {
		slog.Warn("Failed to marshal parameters annotation", "cluster", clusterName, "error", err)
	}

	if _, err := m.client.Resource(gvr).Namespace(namespace).Update(ctx, cluster, metav1.UpdateOptions{}); err != nil {
		slog.Error("Failed to update cluster parameter", "cluster", clusterName, "namespace", namespace, "key", key, "error", err)
		return fmt.Errorf("failed to update cluster: %v", err)
	}

	slog.Info("Successfully updated cluster parameter", "cluster", clusterName, "namespace", namespace, "key", key)
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
	gvr := m.clusterGVR

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

	gvr := m.clusterGVR

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

// injectWorkerGroups replaces the machineDeployments array in the cluster
// topology with entries generated from the supplied worker groups.
func (m *Manager) injectWorkerGroups(obj map[string]interface{}, groups []WorkerGroup) error {
	// Determine the injection path from config; fall back to the default
	// topology path.
	injPath := "spec.topology.workers.machineDeployments"
	for _, inj := range loadInjectionConfig() {
		if inj.Path != "" && strings.Contains(inj.Path, "machineDeployments") {
			injPath = inj.Path
			break
		}
	}

	fields := LoadWorkerGroupFields()
	builtins := workerGroupBuiltins(obj)

	machineDeployments := make([]interface{}, 0, len(groups))
	for _, wg := range groups {
		md, err := renderWorkerGroupMachineDeployment(wg, fields, builtins)
		if err != nil {
			return err
		}
		machineDeployments = append(machineDeployments, md)
	}

	setYAMLPath(obj, injPath, machineDeployments)
	return nil
}

// workerGroupBuiltins collects the {{ chihiro.* }} built-in tokens available to
// the worker_group_template from the already-rendered cluster object (name and
// version are the useful ones at injection time).
func workerGroupBuiltins(obj map[string]interface{}) map[string]string {
	builtins := map[string]string{}
	if meta, ok := obj["metadata"].(map[string]interface{}); ok {
		if name, ok := meta["name"].(string); ok {
			builtins["name"] = name
		}
	}
	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if topology, ok := spec["topology"].(map[string]interface{}); ok {
			if v, ok := topology["version"].(string); ok {
				builtins["version"] = v
			}
		}
	}
	return builtins
}

// GetWorkerGroups extracts the worker groups from a cluster's annotations.
// Returns nil if no annotation is present.
func GetWorkerGroups(cluster map[string]interface{}) []WorkerGroup {
	annotations, _ := cluster["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})
	raw, ok := annotations["chihiro.io/worker-groups"]
	if !ok {
		return nil
	}
	var groups []WorkerGroup
	if err := json.Unmarshal([]byte(raw.(string)), &groups); err != nil {
		slog.Warn("Failed to parse worker-groups annotation", "error", err)
		return nil
	}
	return groups
}

// UpdateClusterWorkerGroups replaces the full set of worker groups for a
// cluster, updating both the Kubernetes resource and the annotation.
func (m *Manager) UpdateClusterWorkerGroups(ctx context.Context, clusterName, namespace string, groups []WorkerGroup) error {
	slog.Debug("Updating cluster worker groups", "cluster", clusterName, "namespace", namespace, "groups", len(groups))

	gvr := m.clusterGVR

	cluster, err := m.client.Resource(gvr).Namespace(namespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		slog.Error("Failed to get cluster for worker groups update", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to get cluster: %v", err)
	}

	// Validate that at least one group has replicas >= 1.
	totalReplicas := int32(0)
	for _, wg := range groups {
		if wg.Replicas < 0 {
			wg.Replicas = 0
		}
		totalReplicas += wg.Replicas
	}

	// Re-inject worker groups into the topology.
	if err := m.injectWorkerGroups(cluster.Object, groups); err != nil {
		return fmt.Errorf("failed to inject worker groups: %v", err)
	}

	// Update the annotation.
	annotations := cluster.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	if wgJSON, err := json.Marshal(groups); err == nil {
		annotations["chihiro.io/worker-groups"] = string(wgJSON)
	}
	cluster.SetAnnotations(annotations)

	_, err = m.client.Resource(gvr).Namespace(namespace).Update(ctx, cluster, metav1.UpdateOptions{})
	if err != nil {
		slog.Error("Failed to update cluster worker groups", "cluster", clusterName, "namespace", namespace, "error", err)
		return fmt.Errorf("failed to update cluster: %v", err)
	}

	slog.Info("Successfully updated cluster worker groups", "cluster", clusterName, "namespace", namespace, "groups", len(groups), "total_replicas", totalReplicas)
	return nil
}

// setYAMLPath sets a value in a nested map using a dot-separated path.
// Supports numeric indices in brackets for arrays, e.g. "spec.workers[0].replicas".
func setYAMLPath(obj map[string]interface{}, path string, value interface{}) {
	parts := parseYAMLPath(path)
	current := obj

	for i, part := range parts {
		isLast := i == len(parts)-1

		if idx, arrayIndex, ok := parseArrayIndex(part); ok {
			// This part has an array index like "machineDeployments[0]"
			var arr []interface{}
			if v, exists := current[idx]; exists {
				arr, _ = v.([]interface{})
			}
			if arr == nil {
				arr = make([]interface{}, 0)
			}

			index := arrayIndex
			// Extend array if needed
			for len(arr) <= index {
				arr = append(arr, make(map[string]interface{}))
			}

			if isLast {
				arr[index] = value
			} else {
				if child, ok := arr[index].(map[string]interface{}); ok {
					current = child
				} else {
					child = make(map[string]interface{})
					arr[index] = child
					current = child
				}
				continue
			}
			current[idx] = arr
			return
		}

		if isLast {
			current[part] = value
			return
		}

		if v, exists := current[part]; exists {
			if child, ok := v.(map[string]interface{}); ok {
				current = child
			} else {
				child = make(map[string]interface{})
				current[part] = child
				current = child
			}
		} else {
			child := make(map[string]interface{})
			current[part] = child
			current = child
		}
	}
}

// parseYAMLPath splits a dot-separated path, handling bracket notation and
// single-quoted segments. Quoting lets a single segment contain dots or
// slashes, which is required for Kubernetes label/annotation keys, e.g.:
//
//	metadata.labels.'sveltos.argus.rpcu.io/cilium'
func parseYAMLPath(path string) []string {
	var parts []string
	var buf strings.Builder
	inQuote := false
	flush := func() {
		if buf.Len() > 0 {
			parts = append(parts, buf.String())
			buf.Reset()
		}
	}
	for _, r := range path {
		switch {
		case r == '\'':
			// Toggle quoting; the quote characters themselves are dropped.
			inQuote = !inQuote
		case r == '.' && !inQuote:
			flush()
		default:
			buf.WriteRune(r)
		}
	}
	flush()
	return parts
}

// parseArrayIndex checks if a part like "foo[2]" has an array index.
func parseArrayIndex(part string) (string, int, bool) {
	bracketStart := strings.Index(part, "[")
	bracketEnd := strings.Index(part, "]")
	if bracketStart > 0 && bracketEnd > bracketStart {
		key := part[:bracketStart]
		idxStr := part[bracketStart+1 : bracketEnd]
		if idx, err := strconv.Atoi(idxStr); err == nil {
			return key, idx, true
		}
	}
	return "", 0, false
}

// Package capi resolves the served API versions for Cluster API resource
// groups at runtime. Cluster API has migrated its core types across versions
// (v1alpha*, v1beta1, v1beta2, ...), and newer releases drop older versions.
// Hardcoding a single version breaks whenever the management cluster's CAPI is
// upgraded, so we discover the version the API server actually serves instead.
package capi

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

// Well-known Cluster API groups.
const (
	GroupCore = "cluster.x-k8s.io"
)

// Resolver discovers and caches the preferred served version for a given
// (group, resource) pair using the API server's discovery endpoint.
type Resolver struct {
	disco discovery.DiscoveryInterface

	mu    sync.RWMutex
	cache map[string]schema.GroupVersionResource // key: group/resource
}

// NewResolver builds a Resolver from a rest.Config.
func NewResolver(config *rest.Config) (*Resolver, error) {
	dc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client: %w", err)
	}
	return &Resolver{
		disco: dc,
		cache: make(map[string]schema.GroupVersionResource),
	}, nil
}

// NewResolverWithDiscovery builds a Resolver from an existing discovery client.
// Useful for testing.
func NewResolverWithDiscovery(dc discovery.DiscoveryInterface) *Resolver {
	return &Resolver{
		disco: dc,
		cache: make(map[string]schema.GroupVersionResource),
	}
}

func cacheKey(group, resource string) string {
	return group + "/" + resource
}

// GVRFor returns the GroupVersionResource for the given group and resource,
// using the version the API server currently serves. The preferred version
// advertised by the API server is used; if the resource is not found in the
// preferred version, the first served version that contains it is used.
//
// If discovery fails entirely, fallbackVersion is used so the caller can still
// operate against a known-good version.
func (r *Resolver) GVRFor(group, resource, fallbackVersion string) (schema.GroupVersionResource, error) {
	key := cacheKey(group, resource)

	r.mu.RLock()
	if gvr, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return gvr, nil
	}
	r.mu.RUnlock()

	gvr, err := r.resolve(group, resource, fallbackVersion)
	if err != nil {
		return schema.GroupVersionResource{}, err
	}

	r.mu.Lock()
	r.cache[key] = gvr
	r.mu.Unlock()

	return gvr, nil
}

func (r *Resolver) resolve(group, resource, fallbackVersion string) (schema.GroupVersionResource, error) {
	groups, err := r.disco.ServerGroups()
	if err != nil {
		if fallbackVersion != "" {
			slog.Warn("API discovery failed, using fallback CAPI version",
				"group", group, "resource", resource, "fallback", fallbackVersion, "error", err)
			return schema.GroupVersionResource{Group: group, Version: fallbackVersion, Resource: resource}, nil
		}
		return schema.GroupVersionResource{}, fmt.Errorf("failed to discover server groups: %w", err)
	}

	var apiGroup *struct {
		preferred string
		versions  []string
	}
	for i := range groups.Groups {
		g := groups.Groups[i]
		if g.Name != group {
			continue
		}
		versions := make([]string, 0, len(g.Versions))
		for _, v := range g.Versions {
			versions = append(versions, v.Version)
		}
		apiGroup = &struct {
			preferred string
			versions  []string
		}{preferred: g.PreferredVersion.Version, versions: versions}
		break
	}

	if apiGroup == nil {
		if fallbackVersion != "" {
			slog.Warn("CAPI group not found in discovery, using fallback version",
				"group", group, "resource", resource, "fallback", fallbackVersion)
			return schema.GroupVersionResource{Group: group, Version: fallbackVersion, Resource: resource}, nil
		}
		return schema.GroupVersionResource{}, fmt.Errorf("API group %q not served by the cluster", group)
	}

	// Try the preferred version first, then any other served version, checking
	// that it actually contains the requested resource.
	candidates := append([]string{apiGroup.preferred}, apiGroup.versions...)
	seen := make(map[string]bool, len(candidates))
	for _, version := range candidates {
		if version == "" || seen[version] {
			continue
		}
		seen[version] = true

		gv := schema.GroupVersion{Group: group, Version: version}.String()
		rl, err := r.disco.ServerResourcesForGroupVersion(gv)
		if err != nil {
			slog.Debug("Failed to list resources for group version",
				"groupVersion", gv, "error", err)
			continue
		}
		for _, res := range rl.APIResources {
			if res.Name == resource {
				gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
				slog.Info("Resolved CAPI resource version",
					"group", group, "resource", resource, "version", version,
					"preferred", apiGroup.preferred)
				return gvr, nil
			}
		}
	}

	if fallbackVersion != "" {
		slog.Warn("Resource not found in any served version, using fallback",
			"group", group, "resource", resource, "fallback", fallbackVersion,
			"servedVersions", apiGroup.versions)
		return schema.GroupVersionResource{Group: group, Version: fallbackVersion, Resource: resource}, nil
	}

	return schema.GroupVersionResource{}, fmt.Errorf(
		"resource %q not found in group %q (served versions: %v)", resource, group, apiGroup.versions)
}

// ClusterGVR resolves the GVR for the core Cluster API "clusters" resource.
func (r *Resolver) ClusterGVR() (schema.GroupVersionResource, error) {
	return r.GVRFor(GroupCore, "clusters", "v1beta1")
}

// GVRForKind resolves the GroupVersionResource for an object identified by its
// apiVersion and kind, as found in an ObjectReference (e.g. a Cluster's
// spec.controlPlaneRef). It discovers the resource (plural) name from the API
// server so chihiro stays agnostic to which provider implements the resource.
//
// This is how chihiro resolves the control plane without hardcoding any
// specific provider (Kamaji, kubeadm, etc.): the Cluster's controlPlaneRef
// already declares the apiVersion and kind to follow.
func (r *Resolver) GVRForKind(apiVersion, kind string) (schema.GroupVersionResource, error) {
	if apiVersion == "" || kind == "" {
		return schema.GroupVersionResource{}, fmt.Errorf("apiVersion and kind are required to resolve a GVR (apiVersion: %q, kind: %q)", apiVersion, kind)
	}

	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, fmt.Errorf("failed to parse apiVersion %q: %w", apiVersion, err)
	}

	key := cacheKey(gv.String(), kind)

	r.mu.RLock()
	if gvr, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return gvr, nil
	}
	r.mu.RUnlock()

	resources, err := r.disco.ServerResourcesForGroupVersion(gv.String())
	if err != nil {
		return schema.GroupVersionResource{}, fmt.Errorf("failed to discover resources for %q: %w", gv.String(), err)
	}

	for _, res := range resources.APIResources {
		// Skip subresources (e.g. "kamajicontrolplanes/status").
		if strings.Contains(res.Name, "/") {
			continue
		}
		if res.Kind != kind {
			continue
		}
		gvr := gv.WithResource(res.Name)
		slog.Info("Resolved control plane resource from ref",
			"apiVersion", apiVersion, "kind", kind, "resource", res.Name)

		r.mu.Lock()
		r.cache[key] = gvr
		r.mu.Unlock()
		return gvr, nil
	}

	return schema.GroupVersionResource{}, fmt.Errorf("kind %q not found in group version %q", kind, gv.String())
}

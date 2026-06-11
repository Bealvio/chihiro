package capi

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
)

// newFakeDiscovery builds a fake discovery client advertising the given group
// versions and resources.
func newFakeDiscovery(t *testing.T, groups []*metav1.APIGroup, resources []*metav1.APIResourceList) discovery.DiscoveryInterface {
	t.Helper()
	cs := fake.NewSimpleClientset()
	fd, ok := cs.Discovery().(*fakediscovery.FakeDiscovery)
	if !ok {
		t.Fatalf("expected *fakediscovery.FakeDiscovery, got %T", cs.Discovery())
	}
	// FakeDiscovery serves ServerResourcesForGroupVersion from Resources.
	fd.Resources = resources
	// FakeDiscovery cannot report custom groups, so we wrap it to control
	// ServerGroups output.
	return &groupedFakeDiscovery{FakeDiscovery: fd, groups: groups}
}

// groupedFakeDiscovery wraps FakeDiscovery to return a controlled set of groups
// from ServerGroups, which FakeDiscovery does not let us set directly.
type groupedFakeDiscovery struct {
	*fakediscovery.FakeDiscovery
	groups []*metav1.APIGroup
}

func (g *groupedFakeDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	list := &metav1.APIGroupList{}
	for _, gr := range g.groups {
		list.Groups = append(list.Groups, *gr)
	}
	return list, nil
}

func clusterResourceList(version string) *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: GroupCore + "/" + version,
		APIResources: []metav1.APIResource{
			{Name: "clusters", Namespaced: true, Kind: "Cluster"},
		},
	}
}

func TestGVRFor_PrefersServedPreferredVersion(t *testing.T) {
	groups := []*metav1.APIGroup{
		{
			Name: GroupCore,
			Versions: []metav1.GroupVersionForDiscovery{
				{GroupVersion: GroupCore + "/v1beta2", Version: "v1beta2"},
			},
			PreferredVersion: metav1.GroupVersionForDiscovery{
				GroupVersion: GroupCore + "/v1beta2", Version: "v1beta2",
			},
		},
	}
	resources := []*metav1.APIResourceList{clusterResourceList("v1beta2")}

	r := NewResolverWithDiscovery(newFakeDiscovery(t, groups, resources))
	gvr, err := r.ClusterGVR()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvr.Version != "v1beta2" {
		t.Fatalf("expected v1beta2, got %q", gvr.Version)
	}
	if gvr.Group != GroupCore || gvr.Resource != "clusters" {
		t.Fatalf("unexpected GVR: %+v", gvr)
	}
}

func TestGVRFor_FallsBackWhenPreferredMissingResource(t *testing.T) {
	// Preferred version v1beta2 is advertised but has no "clusters" resource;
	// v1beta1 does, so the resolver should pick v1beta1.
	groups := []*metav1.APIGroup{
		{
			Name: GroupCore,
			Versions: []metav1.GroupVersionForDiscovery{
				{GroupVersion: GroupCore + "/v1beta2", Version: "v1beta2"},
				{GroupVersion: GroupCore + "/v1beta1", Version: "v1beta1"},
			},
			PreferredVersion: metav1.GroupVersionForDiscovery{
				GroupVersion: GroupCore + "/v1beta2", Version: "v1beta2",
			},
		},
	}
	resources := []*metav1.APIResourceList{
		{GroupVersion: GroupCore + "/v1beta2", APIResources: []metav1.APIResource{}},
		clusterResourceList("v1beta1"),
	}

	r := NewResolverWithDiscovery(newFakeDiscovery(t, groups, resources))
	gvr, err := r.ClusterGVR()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvr.Version != "v1beta1" {
		t.Fatalf("expected v1beta1, got %q", gvr.Version)
	}
}

func TestGVRFor_UsesFallbackWhenGroupAbsent(t *testing.T) {
	r := NewResolverWithDiscovery(newFakeDiscovery(t, nil, nil))
	gvr, err := r.GVRFor(GroupCore, "clusters", "v1beta1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvr.Version != "v1beta1" {
		t.Fatalf("expected fallback v1beta1, got %q", gvr.Version)
	}
}

func TestGVRFor_ErrorsWhenGroupAbsentAndNoFallback(t *testing.T) {
	r := NewResolverWithDiscovery(newFakeDiscovery(t, nil, nil))
	_, err := r.GVRFor(GroupCore, "clusters", "")
	if err == nil {
		t.Fatal("expected error when group absent and no fallback")
	}
}

func TestGVRFor_Caches(t *testing.T) {
	groups := []*metav1.APIGroup{
		{
			Name:             GroupCore,
			Versions:         []metav1.GroupVersionForDiscovery{{GroupVersion: GroupCore + "/v1beta2", Version: "v1beta2"}},
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: GroupCore + "/v1beta2", Version: "v1beta2"},
		},
	}
	resources := []*metav1.APIResourceList{clusterResourceList("v1beta2")}
	fd := newFakeDiscovery(t, groups, resources)
	r := NewResolverWithDiscovery(fd)

	if _, err := r.ClusterGVR(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r.mu.RLock()
	_, cached := r.cache[cacheKey(GroupCore, "clusters")]
	r.mu.RUnlock()
	if !cached {
		t.Fatal("expected result to be cached")
	}
}

func controlPlaneResourceList(version, kind, resource string) *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: GroupControlPlane + "/" + version,
		APIResources: []metav1.APIResource{
			{Name: resource + "/status", Namespaced: true, Kind: kind},
			{Name: resource, Namespaced: true, Kind: kind},
		},
	}
}

func TestGVRForControlPlaneKind_ResolvesByKind(t *testing.T) {
	groups := []*metav1.APIGroup{
		{
			Name: GroupControlPlane,
			Versions: []metav1.GroupVersionForDiscovery{
				{GroupVersion: GroupControlPlane + "/v1alpha1", Version: "v1alpha1"},
			},
			PreferredVersion: metav1.GroupVersionForDiscovery{
				GroupVersion: GroupControlPlane + "/v1alpha1", Version: "v1alpha1",
			},
		},
	}
	resources := []*metav1.APIResourceList{
		controlPlaneResourceList("v1alpha1", "KamajiControlPlane", "kamajicontrolplanes"),
	}

	r := NewResolverWithDiscovery(newFakeDiscovery(t, groups, resources))
	gvr, err := r.GVRForControlPlaneKind("KamajiControlPlane")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := schema.GroupVersionResource{Group: GroupControlPlane, Version: "v1alpha1", Resource: "kamajicontrolplanes"}
	if gvr != want {
		t.Fatalf("expected %+v, got %+v", want, gvr)
	}
}

func TestGVRForControlPlaneKind_ErrorsWhenGroupAbsent(t *testing.T) {
	r := NewResolverWithDiscovery(newFakeDiscovery(t, nil, nil))
	if _, err := r.GVRForControlPlaneKind("KamajiControlPlane"); err == nil {
		t.Fatal("expected error when control plane group absent")
	}
}

func TestGVRForControlPlaneKind_ErrorsWhenKindEmpty(t *testing.T) {
	r := NewResolverWithDiscovery(newFakeDiscovery(t, nil, nil))
	if _, err := r.GVRForControlPlaneKind(""); err == nil {
		t.Fatal("expected error when kind is empty")
	}
}

func TestCache_ExpiresAfterTTL(t *testing.T) {
	now := time.Now()
	r := NewResolverWithDiscovery(newFakeDiscovery(t, nil, nil))
	r.now = func() time.Time { return now }

	key := cacheKey(GroupCore, "clusters")
	gvr := schema.GroupVersionResource{Group: GroupCore, Version: "v1beta2", Resource: "clusters"}
	r.setCached(key, gvr)

	if _, ok := r.getCached(key); !ok {
		t.Fatal("expected fresh entry to be cached")
	}

	// Advance just before the TTL: still cached.
	now = now.Add(r.ttl - time.Second)
	if _, ok := r.getCached(key); !ok {
		t.Fatal("expected entry to still be cached before TTL")
	}

	// Advance past the TTL: expired.
	now = now.Add(2 * time.Second)
	if _, ok := r.getCached(key); ok {
		t.Fatal("expected entry to expire after TTL")
	}
}

func TestInvalidate_ClearsCache(t *testing.T) {
	r := NewResolverWithDiscovery(newFakeDiscovery(t, nil, nil))
	key := cacheKey(GroupCore, "clusters")
	r.setCached(key, schema.GroupVersionResource{Group: GroupCore, Version: "v1beta2", Resource: "clusters"})

	if _, ok := r.getCached(key); !ok {
		t.Fatal("expected entry to be cached")
	}

	r.Invalidate()

	if _, ok := r.getCached(key); ok {
		t.Fatal("expected cache to be cleared after Invalidate")
	}
}

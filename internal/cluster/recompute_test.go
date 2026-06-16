package cluster

import (
	"encoding/json"
	"testing"

	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// imageParamConfig mirrors the config.yaml node-image parameter: a select whose
// option values embed {{ chihiro.version }} and are version-constrained, with a
// recompute dependency on the version field.
func imageParamConfig() map[string]interface{} {
	return map[string]interface{}{
		"imageName": map[string]interface{}{
			"type": "select",
			"options": []interface{}{
				map[string]interface{}{
					"value":    "hephaestus-kaas-25.11-{{ chihiro.version }}",
					"label":    "25.11",
					"versions": []interface{}{"v1.35.4"},
				},
				map[string]interface{}{
					"value":    "hephaestus-kaas-26.05-{{ chihiro.version }}",
					"label":    "26.05",
					"versions": []interface{}{"v1.36.1"},
				},
			},
			"default":      "hephaestus-kaas-26.05-{{ chihiro.version }}",
			"editable":     true,
			"recompute_on": []interface{}{"version"},
			"path":         "spec.topology.variables[0].value",
		},
	}
}

func TestRecomputeDependents_VersionPicksCompatibleImage(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", imageParamConfig())
	viper.Set("cluster.template", "value: {{ chihiro.imageName }}")

	// Cluster currently on v1.35.4 with the 25.11 image; upgrade to v1.36.1.
	existing := map[string]string{
		"imagename": "hephaestus-kaas-25.11-{{ chihiro.version }}",
	}
	got := recomputeDependents(map[string]string{"version": "v1.36.1"}, existing)
	if len(got) != 1 {
		t.Fatalf("expected 1 recomputed param, got %d (%+v)", len(got), got)
	}
	r := got[0]
	if r.Key != "imageName" {
		t.Errorf("key = %q, want imageName", r.Key)
	}
	// Must switch to the option compatible with v1.36.1 (26.05) and resolve the
	// embedded version into the final node image name.
	if r.WriteValue != "hephaestus-kaas-26.05-v1.36.1" {
		t.Errorf("WriteValue = %q, want hephaestus-kaas-26.05-v1.36.1", r.WriteValue)
	}
	// Stored state keeps the raw template reference for round-tripping.
	if r.StoredState != "hephaestus-kaas-26.05-{{ chihiro.version }}" {
		t.Errorf("StoredState = %q, want raw template reference", r.StoredState)
	}
}

func TestRecomputeDependents_KeepsCompatibleOptionReResolves(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	// Single option compatible with all versions (no versions list).
	viper.Set("cluster.parameters", map[string]interface{}{
		"imageName": map[string]interface{}{
			"type": "select",
			"options": []interface{}{
				map[string]interface{}{"value": "img-{{ chihiro.version }}", "label": "any"},
			},
			"editable":     true,
			"recompute_on": []interface{}{"version"},
			"path":         "spec.topology.variables[0].value",
		},
	})

	existing := map[string]string{"imagename": "img-{{ chihiro.version }}"}
	got := recomputeDependents(map[string]string{"version": "v9.9.9"}, existing)
	if len(got) != 1 {
		t.Fatalf("expected 1 recomputed param, got %d", len(got))
	}
	if got[0].WriteValue != "img-v9.9.9" {
		t.Errorf("WriteValue = %q, want img-v9.9.9", got[0].WriteValue)
	}
}

func TestRecomputeDependents_NoDependencyNoChange(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", map[string]interface{}{
		"podCIDR": map[string]interface{}{
			"type":    "string",
			"default": "10.0.0.0/16",
		},
	})
	if got := recomputeDependents(map[string]string{"version": "v1.36.1"}, nil); len(got) != 0 {
		t.Fatalf("expected no recompute, got %+v", got)
	}
}

func TestRecomputeDependents_SkipsWhenNoPath(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", map[string]interface{}{
		"imageName": map[string]interface{}{
			"type":         "string",
			"default":      "img-{{ chihiro.version }}",
			"recompute_on": []interface{}{"version"},
			// no path -> cannot be written, must be skipped.
		},
	})
	if got := recomputeDependents(map[string]string{"version": "v1.36.1"}, nil); len(got) != 0 {
		t.Fatalf("expected skip when no path, got %+v", got)
	}
}

func TestApplyRecomputedDependents_WritesPathAndAnnotation(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", imageParamConfig())
	viper.Set("cluster.template", "value: {{ chihiro.imageName }}")

	cluster := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{
				"chihiro.io/parameters": `{"imageName":"hephaestus-kaas-25.11-{{ chihiro.version }}"}`,
			},
		},
		"spec": map[string]interface{}{
			"topology": map[string]interface{}{},
		},
	}}

	applyRecomputedDependents(cluster, map[string]string{"version": "v1.36.1"})

	// The resolved node image must be written at the configured path.
	spec := cluster.Object["spec"].(map[string]interface{})
	topology := spec["topology"].(map[string]interface{})
	vars, ok := topology["variables"].([]interface{})
	if !ok || len(vars) == 0 {
		t.Fatalf("variables not written: %#v", topology)
	}
	entry := vars[0].(map[string]interface{})
	if entry["value"] != "hephaestus-kaas-26.05-v1.36.1" {
		t.Errorf("written value = %v, want hephaestus-kaas-26.05-v1.36.1", entry["value"])
	}

	// The annotation must record the new raw state.
	ann := cluster.GetAnnotations()
	var params map[string]string
	if err := json.Unmarshal([]byte(ann["chihiro.io/parameters"]), &params); err != nil {
		t.Fatalf("annotation not valid JSON: %v", err)
	}
	if params["imageName"] != "hephaestus-kaas-26.05-{{ chihiro.version }}" {
		t.Errorf("annotation imageName = %q, want raw 26.05 template", params["imageName"])
	}
}

// imageParamConfigWithImplies mirrors imageParamConfig but adds an `implies`
// mapping: selecting a node image option pushes the option's first compatible
// version into spec.topology.version.
func imageParamConfigWithImplies() map[string]interface{} {
	return map[string]interface{}{
		"imageName": map[string]interface{}{
			"type": "select",
			"options": []interface{}{
				map[string]interface{}{
					"value":    "hephaestus-kaas-25.11-{{ chihiro.version }}",
					"label":    "25.11",
					"versions": []interface{}{"v1.35.4"},
				},
				map[string]interface{}{
					"value":    "hephaestus-kaas-26.05-{{ chihiro.version }}",
					"label":    "26.05",
					"versions": []interface{}{"v1.36.1"},
				},
			},
			"default":      "hephaestus-kaas-26.05-{{ chihiro.version }}",
			"editable":     true,
			"recompute_on": []interface{}{"version"},
			"implies": []interface{}{
				map[string]interface{}{
					"field":  "version",
					"source": "option_version",
				},
			},
			"path": "spec.topology.variables[0].value",
		},
	}
}

func TestImpliedFieldValues_ReturnsVersionFromOption(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", imageParamConfigWithImplies())

	// Selecting the 26.05 image should imply version v1.36.1.
	got := impliedFieldValues("imageName", "hephaestus-kaas-26.05-{{ chihiro.version }}")
	if got == nil {
		t.Fatal("expected implied fields, got nil")
	}
	if got["version"] != "v1.36.1" {
		t.Errorf("implied version = %q, want v1.36.1", got["version"])
	}
}

func TestImpliedFieldValues_OlderImageImpliesOlderVersion(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", imageParamConfigWithImplies())

	got := impliedFieldValues("imageName", "hephaestus-kaas-25.11-{{ chihiro.version }}")
	if got == nil {
		t.Fatal("expected implied fields, got nil")
	}
	if got["version"] != "v1.35.4" {
		t.Errorf("implied version = %q, want v1.35.4", got["version"])
	}
}

func TestImpliedFieldValues_NoImpliesReturnsNil(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", imageParamConfig())

	got := impliedFieldValues("imageName", "hephaestus-kaas-26.05-v1.36.1")
	if got != nil {
		t.Errorf("expected nil for param without implies, got %+v", got)
	}
}

func TestImpliedFieldValues_UnknownParamReturnsNil(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", imageParamConfigWithImplies())

	got := impliedFieldValues("nonexistent", "value")
	if got != nil {
		t.Errorf("expected nil for unknown param, got %+v", got)
	}
}

func TestApplyImpliedFields_SetsVersionOnCluster(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("cluster.parameters", imageParamConfigWithImplies())
	// Ensure the version injection path is available.
	viper.Set("cluster.injections", map[string]interface{}{
		"version": map[string]interface{}{
			"path":     "spec.topology.version",
			"editable": true,
		},
	})

	cluster := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"topology": map[string]interface{}{
				"version": "v1.35.4",
			},
		},
	}}

	implied := applyImpliedFields(cluster, "imageName", "hephaestus-kaas-26.05-{{ chihiro.version }}")
	if implied == nil || implied["version"] != "v1.36.1" {
		t.Fatalf("expected implied version v1.36.1, got %+v", implied)
	}

	// Verify the cluster object was mutated.
	topology := cluster.Object["spec"].(map[string]interface{})["topology"].(map[string]interface{})
	if topology["version"] != "v1.36.1" {
		t.Errorf("cluster version = %v, want v1.36.1", topology["version"])
	}
}

func TestApplyImpliedFields_ImpliesTriggerRecompute(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	// Set up both the implies and a second parameter that depends on version.
	viper.Set("cluster.parameters", map[string]interface{}{
		"imageName": map[string]interface{}{
			"type": "select",
			"options": []interface{}{
				map[string]interface{}{
					"value":    "hephaestus-kaas-26.05-{{ chihiro.version }}",
					"label":    "26.05",
					"versions": []interface{}{"v1.36.1"},
				},
			},
			"default":      "hephaestus-kaas-26.05-{{ chihiro.version }}",
			"editable":     true,
			"recompute_on": []interface{}{"version"},
			"implies": []interface{}{
				map[string]interface{}{
					"field":  "version",
					"source": "option_version",
				},
			},
			"path": "spec.topology.variables[0].value",
		},
		"imageTag": map[string]interface{}{
			"type":    "string",
			"default": "img-{{ chihiro.version }}",
			// Depends on version, which is implied by imageName.
			"recompute_on": []interface{}{"version"},
			"path":         "spec.topology.variables[1].value",
		},
	})
	viper.Set("cluster.template", "v0: {{ chihiro.imageName }} v1: {{ chihiro.imageTag }}")
	viper.Set("cluster.injections", map[string]interface{}{
		"version": map[string]interface{}{
			"path":     "spec.topology.version",
			"editable": true,
		},
	})

	cluster := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{
				"chihiro.io/parameters": `{"imageName":"hephaestus-kaas-25.11-{{ chihiro.version }}","imageTag":"img-v1.35.4"}`,
			},
		},
		"spec": map[string]interface{}{
			"topology": map[string]interface{}{
				"version":   "v1.35.4",
				"variables": []interface{}{},
			},
		},
	}}

	// Simulate editing the node image: implied version + recompute chain.
	implied := applyImpliedFields(cluster, "imageName", "hephaestus-kaas-26.05-{{ chihiro.version }}")
	changed := map[string]string{"imagename": "hephaestus-kaas-26.05-{{ chihiro.version }}"}
	for f, v := range implied {
		changed[f] = v
	}
	applyRecomputedDependents(cluster, changed)

	// The implied version should have been written.
	topology := cluster.Object["spec"].(map[string]interface{})["topology"].(map[string]interface{})
	if topology["version"] != "v1.36.1" {
		t.Errorf("cluster version = %v, want v1.36.1", topology["version"])
	}

	// The imageTag should also have been recomputed because version changed.
	vars := topology["variables"].([]interface{})
	if len(vars) < 2 {
		t.Fatalf("expected at least 2 variables, got %d", len(vars))
	}
	entry := vars[1].(map[string]interface{})
	if entry["value"] != "img-v1.36.1" {
		t.Errorf("imageTag value = %v, want img-v1.36.1", entry["value"])
	}
}

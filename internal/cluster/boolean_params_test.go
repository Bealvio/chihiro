package cluster

import (
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

func TestParseYAMLPathQuotedSegment(t *testing.T) {
	got := parseYAMLPath("metadata.labels.'sveltos.argus.rpcu.io/cilium'")
	want := []string{"metadata", "labels", "sveltos.argus.rpcu.io/cilium"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseYAMLPath = %#v, want %#v", got, want)
	}
}

func TestSetYAMLPathLabelKey(t *testing.T) {
	obj := map[string]interface{}{}
	setYAMLPath(obj, "metadata.labels.'sveltos.argus.rpcu.io/cilium'", "enabled")

	meta := obj["metadata"].(map[string]interface{})
	labels := meta["labels"].(map[string]interface{})
	if labels["sveltos.argus.rpcu.io/cilium"] != "enabled" {
		t.Fatalf("label not set correctly: %#v", labels)
	}
}

func TestResolveBooleanParameters(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("cluster.parameters", map[string]interface{}{
		"cilium": map[string]interface{}{
			"type":        "boolean",
			"default":     true,
			"true_value":  "enabled",
			"false_value": "disabled",
		},
		"oidcRbac": map[string]interface{}{
			"type":        "boolean",
			"default":     false,
			"true_value":  "enabled",
			"false_value": "disabled",
		},
	})

	// User turns cilium off; leaves oidcRbac at default (off).
	out := resolveBooleanParameters(map[string]string{"cilium": "false"})
	if out["cilium"] != "disabled" {
		t.Errorf("cilium = %q, want disabled", out["cilium"])
	}
	if out["oidcrbac"] != "disabled" {
		t.Errorf("oidcrbac = %q, want disabled (default false)", out["oidcrbac"])
	}

	// User turns oidcRbac on explicitly.
	out = resolveBooleanParameters(map[string]string{"oidcRbac": "true"})
	if out["oidcrbac"] != "enabled" {
		t.Errorf("oidcrbac = %q, want enabled", out["oidcrbac"])
	}
	// cilium default true -> enabled.
	if out["cilium"] != "enabled" {
		t.Errorf("cilium = %q, want enabled (default true)", out["cilium"])
	}
}

func TestDiscoverParametersBoolean(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("cluster.parameters", map[string]interface{}{
		"cilium": map[string]interface{}{
			"label":       "Cilium CNI",
			"type":        "boolean",
			"default":     true,
			"true_value":  "enabled",
			"false_value": "disabled",
			"editable":    true,
			"path":        "metadata.labels.'sveltos.argus.rpcu.io/cilium'",
		},
	})

	tmpl := "labels:\n  cni: {{ chihiro.cilium }}\n"
	params := DiscoverParameters(tmpl)
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}
	p := params[0]
	if p.Type != "boolean" {
		t.Errorf("type = %q, want boolean", p.Type)
	}
	if p.TrueValue != "enabled" || p.FalseValue != "disabled" {
		t.Errorf("true/false = %q/%q, want enabled/disabled", p.TrueValue, p.FalseValue)
	}
	if p.Default != "true" {
		t.Errorf("default = %q, want \"true\"", p.Default)
	}
	if p.Path == "" {
		t.Errorf("path should be surfaced for boolean param")
	}
}

func TestGetEditableFieldsBooleanParam(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set("cluster.parameters", map[string]interface{}{
		"cilium": map[string]interface{}{
			"type":        "boolean",
			"true_value":  "enabled",
			"false_value": "disabled",
			"editable":    true,
			"path":        "metadata.labels.'sveltos.argus.rpcu.io/cilium'",
		},
	})

	tmpl := "x: {{ chihiro.cilium }}"
	ef, ok := GetEditableField(tmpl, "cilium")
	if !ok || !ef.Enabled {
		t.Fatalf("cilium should be editable")
	}
	if ef.Type != "boolean" || ef.TrueValue != "enabled" || ef.FalseValue != "disabled" {
		t.Errorf("editable field = %+v, want boolean enabled/disabled", ef)
	}
	if ef.Path == "" {
		t.Errorf("editable field path missing")
	}
}

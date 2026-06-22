package cluster

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

func resetViper() {
	viper.Reset()
}

func TestWorkerGroupUnmarshalCapturesGenericFields(t *testing.T) {
	data := []byte(`{"name":"pool-a","class":"big-worker","flavor":"xlarge","replicas":3,"zone":"eu-1"}`)
	var wg WorkerGroup
	if err := json.Unmarshal(data, &wg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if wg.Name != "pool-a" || wg.Class != "big-worker" || wg.Flavor != "xlarge" || wg.Replicas != 3 {
		t.Fatalf("named fields not populated: %+v", wg)
	}
	if wg.Values["zone"] != "eu-1" {
		t.Fatalf("expected generic field zone=eu-1, got %q", wg.Values["zone"])
	}
	if wg.Values["replicas"] != "3" {
		t.Fatalf("expected replicas mirrored into Values as string, got %q", wg.Values["replicas"])
	}
}

func TestWorkerGroupMarshalRoundTrip(t *testing.T) {
	wg := WorkerGroup{Values: map[string]string{
		"name":     "pool-a",
		"flavor":   "xlarge",
		"replicas": "2",
		"zone":     "eu-1",
	}}
	wg.syncValuesFromNamed()
	b, err := json.Marshal(wg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var back WorkerGroup
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal back failed: %v", err)
	}
	if back.Values["zone"] != "eu-1" {
		t.Fatalf("generic field lost in round trip: %+v", back.Values)
	}
	if back.Name != "pool-a" || back.Flavor != "xlarge" || back.Replicas != 2 {
		t.Fatalf("named fields lost in round trip: %+v", back)
	}
}

func TestRenderWorkerGroupDefaultTemplate(t *testing.T) {
	resetViper()
	defer resetViper()

	wg := WorkerGroup{Values: map[string]string{
		"name":     "worker",
		"class":    "default-worker",
		"flavor":   "xlarge",
		"replicas": "4",
	}}
	fields := LoadWorkerGroupFields() // legacy fallback (no config) -> 4 fields
	md, err := renderWorkerGroupMachineDeployment(wg, fields, nil)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}

	if md["name"] != "worker" {
		t.Errorf("name = %v, want worker", md["name"])
	}
	if md["class"] != "default-worker" {
		t.Errorf("class = %v, want default-worker", md["class"])
	}
	// Numbers must be emitted unquoted -> parsed as a numeric type.
	switch md["replicas"].(type) {
	case float64, int64, int:
	default:
		t.Errorf("replicas type = %T, want numeric", md["replicas"])
	}

	vars, ok := md["variables"].(map[string]interface{})
	if !ok {
		t.Fatalf("variables missing: %+v", md)
	}
	overrides, ok := vars["overrides"].([]interface{})
	if !ok || len(overrides) != 1 {
		t.Fatalf("overrides missing/wrong: %+v", vars)
	}
	ov := overrides[0].(map[string]interface{})
	if ov["name"] != "workerFlavor" || ov["value"] != "xlarge" {
		t.Errorf("override = %+v, want workerFlavor/xlarge", ov)
	}
}

func TestRenderWorkerGroupCustomTemplateAndGenericField(t *testing.T) {
	resetViper()
	defer resetViper()

	viper.Set("cluster.worker_group_fields", map[string]interface{}{
		"name":     map[string]interface{}{"type": "string", "order": 0},
		"replicas": map[string]interface{}{"type": "number", "order": 1},
		"pool":     map[string]interface{}{"type": "string", "order": 2},
	})
	viper.Set("cluster.worker_group_template", `name: {{ chihiro.field.name }}
replicas: {{ chihiro.field.replicas }}
metadata:
  labels:
    pool: {{ chihiro.field.pool }}
`)

	wg := WorkerGroup{Values: map[string]string{
		"name":     "gpu",
		"replicas": "2",
		"pool":     "gpu-pool",
	}}
	fields := LoadWorkerGroupFields()
	md, err := renderWorkerGroupMachineDeployment(wg, fields, nil)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}

	meta, ok := md["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata missing: %+v", md)
	}
	labels, ok := meta["labels"].(map[string]interface{})
	if !ok {
		t.Fatalf("labels missing: %+v", meta)
	}
	if labels["pool"] != "gpu-pool" {
		t.Errorf("pool label = %v, want gpu-pool", labels["pool"])
	}
	// No class/flavor in the template -> no variables block expected.
	if _, ok := md["variables"]; ok {
		t.Errorf("unexpected variables block: %+v", md)
	}
}

func TestLoadWorkerGroupFieldsOrder(t *testing.T) {
	resetViper()
	defer resetViper()

	viper.Set("cluster.worker_group_fields", map[string]interface{}{
		"flavor":   map[string]interface{}{"order": 2},
		"name":     map[string]interface{}{"order": 0},
		"replicas": map[string]interface{}{"order": 1},
	})
	fields := LoadWorkerGroupFields()
	got := []string{fields[0].Key, fields[1].Key, fields[2].Key}
	want := []string{"name", "replicas", "flavor"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestDefaultWorkerGroupFieldsFallback(t *testing.T) {
	resetViper()
	defer resetViper()

	// No cluster.worker_group_fields configured -> built-in default schema.
	fields := LoadWorkerGroupFields()
	if len(fields) != 4 {
		t.Fatalf("expected 4 default fields, got %d", len(fields))
	}
	byKey := map[string]WorkerGroupField{}
	for _, f := range fields {
		byKey[f.Key] = f
	}
	if byKey["name"].Type != "string" || !byKey["name"].Required {
		t.Errorf("name field = %+v, want required string", byKey["name"])
	}
	if byKey["class"].Default != "default-worker" {
		t.Errorf("class default = %q, want default-worker", byKey["class"].Default)
	}
	if byKey["replicas"].Type != "number" {
		t.Errorf("replicas type = %q, want number", byKey["replicas"].Type)
	}
}

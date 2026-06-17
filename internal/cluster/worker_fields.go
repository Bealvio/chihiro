package cluster

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Bealvio/chihiro/internal/auth"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

// workerFieldRegex matches per-group field placeholders like
// {{ chihiro.field.flavor }} (separate namespace from the {{ chihiro.* }}
// built-ins used elsewhere).
var workerFieldRegex = regexp.MustCompile(`\{\{\s*chihiro\.field\.([\w-]+)\s*\}\}`)

// WorkerGroupField describes one config-driven input rendered for every worker
// group in the create/edit UI. It only describes the input; where its value is
// written is decided by the worker_group_template.
type WorkerGroupField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`              // "string" | "number" | "select"
	Options  []string `json:"options,omitempty"` // values for type "select"
	Default  string   `json:"default,omitempty"`
	Required bool     `json:"required"`
	Min      *int     `json:"min,omitempty"`
	Max      *int     `json:"max,omitempty"`
	// VisibleGroups restricts which OIDC groups can see/edit this field. When
	// empty, the field is visible/editable to all authenticated users.
	VisibleGroups []string `json:"visibleGroups,omitempty"`
	// order is the display order; not serialised.
	order int
}

// LoadWorkerGroupFields returns the configured worker-group field schema,
// ordered by the optional `order` key (then alphabetically). When the
// cluster.worker_group_fields section is absent it falls back to a built-in
// default schema (name + class + flavor + replicas) matching the default
// worker_group_template, so the app works out of the box.
func LoadWorkerGroupFields() []WorkerGroupField {
	raw, ok := viper.Get("cluster.worker_group_fields").(map[string]interface{})
	if !ok || len(raw) == 0 {
		return defaultWorkerGroupFields()
	}

	fields := make([]WorkerGroupField, 0, len(raw))
	for key, v := range raw {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		f := WorkerGroupField{
			Key:           key,
			Label:         getString(m, "label"),
			Type:          getString(m, "type"),
			Options:       getStringSlice(m, "options"),
			Default:       getString(m, "default"),
			Required:      getBool(m, "required"),
			Min:           getIntPtr(m, "min"),
			Max:           getIntPtr(m, "max"),
			VisibleGroups: getStringSlice(m, "visible_groups"),
		}
		if f.Label == "" {
			f.Label = humanizeKey(key)
		}
		if f.Type == "" {
			f.Type = "string"
		}
		if order := getIntPtr(m, "order"); order != nil {
			f.order = *order
		} else {
			f.order = 1 << 30 // unspecified order sorts last
		}
		fields = append(fields, f)
	}

	sort.SliceStable(fields, func(i, j int) bool {
		if fields[i].order != fields[j].order {
			return fields[i].order < fields[j].order
		}
		return fields[i].Key < fields[j].Key
	})
	return fields
}

// defaultWorkerGroupFields is the built-in schema used when
// cluster.worker_group_fields is unset. It matches defaultWorkerGroupTemplate
// (name + class + flavor + replicas).
func defaultWorkerGroupFields() []WorkerGroupField {
	one := 1
	ten := 10
	return []WorkerGroupField{
		{Key: "name", Label: "Group name", Type: "string", Required: true},
		{Key: "class", Label: "Class", Type: "string", Default: "default-worker"},
		{Key: "flavor", Label: "Flavor", Type: "string"},
		{Key: "replicas", Label: "Replicas", Type: "number", Default: "1", Min: &one, Max: &ten},
	}
}

// defaultWorkerGroupTemplate mirrors the legacy hardcoded machineDeployment
// shape (name + class + replicas + workerFlavor override). Used when no
// cluster.worker_group_template is configured.
const defaultWorkerGroupTemplate = `name: {{ chihiro.field.name }}
class: {{ chihiro.field.class }}
replicas: {{ chihiro.field.replicas }}
variables:
  overrides:
    - name: workerFlavor
      value: {{ chihiro.field.flavor }}
`

// WorkerGroupTemplate returns the configured per-group machineDeployment
// template, falling back to the default shape when unset.
func WorkerGroupTemplate() string {
	tmpl := viper.GetString("cluster.worker_group_template")
	if strings.TrimSpace(tmpl) == "" {
		return defaultWorkerGroupTemplate
	}
	return tmpl
}

// numericFieldKeys returns the set of field keys whose type is "number" so the
// renderer can emit them unquoted in YAML.
func numericFieldKeys(fields []WorkerGroupField) map[string]bool {
	out := make(map[string]bool)
	for _, f := range fields {
		if f.Type == "number" {
			out[f.Key] = true
		}
	}
	return out
}

// renderWorkerGroupMachineDeployment renders the worker_group_template for a
// single worker group and parses it into a machineDeployment map. field values
// come from wg.Values; built-in {{ chihiro.* }} tokens are taken from builtins.
func renderWorkerGroupMachineDeployment(wg WorkerGroup, fields []WorkerGroupField, builtins map[string]string) (map[string]interface{}, error) {
	wg.syncValuesFromNamed()
	numeric := numericFieldKeys(fields)
	tmpl := WorkerGroupTemplate()

	// Replace {{ chihiro.field.<key> }} placeholders first.
	rendered := workerFieldRegex.ReplaceAllStringFunc(tmpl, func(match string) string {
		sub := workerFieldRegex.FindStringSubmatch(match)
		if sub == nil {
			return match
		}
		key := sub[1]
		val := wg.Values[key]
		if numeric[key] {
			// Emit numbers unquoted; default missing/invalid to 0.
			if val == "" {
				return "0"
			}
			if _, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				return strings.TrimSpace(val)
			}
			return "0"
		}
		// Quote string scalars so values with special characters stay valid YAML.
		return strconv.Quote(val)
	})

	// Replace the shared {{ chihiro.* }} built-ins (name, version, ...).
	rendered = chihiroParamRegex.ReplaceAllStringFunc(rendered, func(match string) string {
		sub := chihiroParamRegex.FindStringSubmatch(match)
		if sub == nil {
			return match
		}
		if v, ok := builtins[strings.ToLower(sub[1])]; ok {
			return strconv.Quote(v)
		}
		return match
	})

	var md map[string]interface{}
	if err := yaml.Unmarshal([]byte(rendered), &md); err != nil {
		return nil, fmt.Errorf("failed to parse rendered worker group template: %w", err)
	}
	if md == nil {
		md = map[string]interface{}{}
	}
	return md, nil
}

// FilterWorkerGroupFieldsByGroups returns only the worker-group fields whose
// VisibleGroups setting permits the given user groups. A field with an empty
// VisibleGroups list is visible to everyone.
func FilterWorkerGroupFieldsByGroups(fields []WorkerGroupField, userGroups []string) []WorkerGroupField {
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if auth.CheckUserGroups(userGroups, adminGroups) {
		return fields
	}
	var filtered []WorkerGroupField
	for _, f := range fields {
		if len(f.VisibleGroups) == 0 || auth.CheckUserGroups(userGroups, f.VisibleGroups) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

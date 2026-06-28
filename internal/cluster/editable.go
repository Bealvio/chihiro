package cluster

import (
	"strings"

	"github.com/Bealvio/chihiro/internal/auth"
	"github.com/spf13/viper"
)

// EditableField describes whether a cluster field can be edited after creation
// and any bounds that apply to it. It is driven by the `editable` flag on
// cluster.injections entries (built-in fields) and cluster.parameters entries
// (template placeholders).
type EditableField struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
	Min     *int   `json:"min,omitempty"`
	Max     *int   `json:"max,omitempty"`
	// The following describe an editable template parameter (empty for built-in
	// injection fields). Type is e.g. "string"/"number"/"select"/"boolean";
	// Path is where the value is written; TrueValue/FalseValue apply to
	// booleans; Options applies to selects.
	Type       string       `json:"type,omitempty"`
	Path       string       `json:"path,omitempty"`
	Options    []OptionItem `json:"options,omitempty"`
	TrueValue  string       `json:"trueValue,omitempty"`
	FalseValue string       `json:"falseValue,omitempty"`
	Label      string       `json:"label,omitempty"`
	// RecomputeOn lists fields whose edit should also recompute this one. Empty
	// for built-in injection fields.
	RecomputeOn []string `json:"recomputeOn,omitempty"`
	// VisibleGroups restricts which OIDC groups can edit this field. When
	// empty, the field is editable by all users who have general cluster modify
	// permission (subject to the Enabled flag). The value is always shown in
	// the "More details" read-only section regardless of group membership.
	VisibleGroups []string `json:"visibleGroups,omitempty"`
}

// injectionConfig is a single cluster.injections entry. path is the YAML path
// the built-in value is written to (may be empty for annotation-managed fields
// such as groups). The remaining fields mirror the editable metadata.
type injectionConfig struct {
	Path          string
	Label         string
	Editable      bool
	Min           *int
	Max           *int
	VisibleGroups []string
}

// canonicalBuiltinKeys maps lowercase built-in keys back to their canonical
// camelCase form so the API and frontend receive predictable keys (viper
// lowercases config keys).
var canonicalBuiltinKeys = map[string]string{
	"name":                 "name",
	"version":              "version",
	"groups":               "groups",
	"servicedomain":        "serviceDomain",
	"nodes":                "nodes",
	"workergroups":         "workerGroups",
	"controlplanereplicas": "controlPlaneReplicas",
}

// loadInjectionConfig reads the cluster.injections section. Each entry is a
// nested map with a `path` plus optional editable metadata. viper lowercases
// keys, so we read the raw nested map and key by lowercase.
func loadInjectionConfig() map[string]injectionConfig {
	result := make(map[string]injectionConfig)

	raw, ok := viper.Get("cluster.injections").(map[string]interface{})
	if !ok {
		return result
	}

	for key, v := range raw {
		fields, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		result[strings.ToLower(key)] = injectionConfig{
			Path:          getString(fields, "path"),
			Label:         getString(fields, "label"),
			Editable:      getBool(fields, "editable"),
			Min:           getIntPtr(fields, "min"),
			Max:           getIntPtr(fields, "max"),
			VisibleGroups: getStringSlice(fields, "visible_groups"),
		}
	}
	return result
}

// GetEditableFields returns every field marked editable: true, drawn from both
// cluster.injections (built-in fields like version/nodes/controlPlaneReplicas/
// groups) and cluster.parameters (template placeholders like workerFlavor).
//
// Keys use canonical casing: built-ins map to their camelCase form, template
// parameters use the casing from the template placeholder. Callers should still
// match case-insensitively.
func GetEditableFields(templateStr string) []EditableField {
	fields := make([]EditableField, 0)

	// Built-in fields from injections.
	for key, cfg := range loadInjectionConfig() {
		if !cfg.Editable {
			continue
		}
		outKey := key
		if c, ok := canonicalBuiltinKeys[key]; ok {
			outKey = c
		}
		fields = append(fields, EditableField{
			Key:           outKey,
			Enabled:       true,
			Min:           cfg.Min,
			Max:           cfg.Max,
			VisibleGroups: cfg.VisibleGroups,
		})
	}

	// Template parameters from cluster.parameters. Recover original-cased keys
	// from the template tokens (viper lowercases config keys).
	casing := make(map[string]string)
	for _, m := range chihiroParamRegex.FindAllStringSubmatch(templateStr, -1) {
		casing[strings.ToLower(m[1])] = m[1]
	}
	for key, cfg := range loadParameterConfig() {
		if !cfg.Editable {
			continue
		}
		outKey := key
		if c, ok := casing[strings.ToLower(key)]; ok {
			outKey = c
		}
		ptype := cfg.Type
		if ptype == "" {
			ptype = "string"
		}
		ef := EditableField{
			Key:           outKey,
			Enabled:       true,
			Min:           cfg.Min,
			Max:           cfg.Max,
			Type:          ptype,
			Path:          cfg.Path,
			Options:       normalizeOptions(cfg.Options),
			Label:         cfg.Label,
			RecomputeOn:   cfg.RecomputeOn,
			VisibleGroups: cfg.VisibleGroups,
		}
		if ptype == "boolean" {
			ef.TrueValue, ef.FalseValue = boolValueStrings(cfg)
		}
		fields = append(fields, ef)
	}

	return fields
}

// GetEditableField returns the editable configuration for a single field,
// looked up case-insensitively. The second return value is false when the
// field is not editable.
func GetEditableField(templateStr, key string) (EditableField, bool) {
	for _, f := range GetEditableFields(templateStr) {
		if strings.EqualFold(f.Key, key) {
			return f, true
		}
	}
	return EditableField{}, false
}

func getIntPtr(m map[string]interface{}, key string) *int {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch n := v.(type) {
	case int:
		return &n
	case int64:
		i := int(n)
		return &i
	case float64:
		i := int(n)
		return &i
	default:
		return nil
	}
}

// UserCanEditField reports whether the given user groups are permitted to edit
// a field with the specified VisibleGroups. An empty VisibleGroups list means
// the field is editable by all users (subject to the Enabled flag). Admins
// (users in the cluster.admin_groups) can always edit any field.
func UserCanEditField(visibleGroups, userGroups []string) bool {
	if len(visibleGroups) == 0 {
		return true
	}
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if auth.CheckUserGroups(userGroups, adminGroups) {
		return true
	}
	return auth.CheckUserGroups(userGroups, visibleGroups)
}

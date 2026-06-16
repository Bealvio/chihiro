package cluster

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

var chihiroParamRegex = regexp.MustCompile(`\{\{\s*chihiro\.(\w+)\s*\}\}`)

// OptionItem describes one choice in a select parameter. Options may be plain
// strings (backward-compatible) or structured objects with a display label and
// an optional list of compatible Kubernetes versions.
type OptionItem struct {
	Value    string   `json:"value"`
	Label    string   `json:"label,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// ImpliedField declares that editing a parameter should also set another field
// based on the selected option's metadata. This is now auto-detected from
// version-constrained option lists rather than requiring explicit config.
// Deprecated: kept for backward compatibility with existing configs.
type ImpliedField struct {
	Field  string `json:"field"`
	Source string `json:"source,omitempty"`
}

type TemplateParameter struct {
	Key         string       `json:"key"`
	Label       string       `json:"label"`
	Description string       `json:"description"`
	Default     string       `json:"default"`
	Type        string       `json:"type"`
	Options     []OptionItem `json:"options,omitempty"`
	Required    bool         `json:"required"`
	Editable    bool         `json:"editable"`
	Min         *int         `json:"min,omitempty"`
	Max         *int         `json:"max,omitempty"`
	// TrueValue/FalseValue are the strings substituted into the template for a
	// boolean parameter when it is on/off (default "true"/"false").
	TrueValue  string `json:"trueValue,omitempty"`
	FalseValue string `json:"falseValue,omitempty"`
	// Path is the YAML path the value is written to on edit. Required for a
	// parameter to be editable after creation.
	Path string `json:"path,omitempty"`
	// RecomputeOn lists the names of other editable fields (built-in or
	// parameter, case-insensitive) whose change should trigger this parameter
	// to be re-resolved and written together in the same update. Generic: any
	// parameter can depend on any other field. Requires Path to be set so the
	// recomputed value can be written to the live object.
	RecomputeOn []string `json:"recomputeOn,omitempty"`
	// Implies declares fields that this parameter sets when it is edited, based
	// on the selected option's metadata (the reverse of RecomputeOn). E.g. a
	// node-image select can imply the cluster version from the chosen option's
	// versions list, keeping version and image coherent in both directions.
	Implies []ImpliedField `json:"implies,omitempty"`
}

type parameterConfig struct {
	Label       string      `mapstructure:"label"`
	Description string      `mapstructure:"description"`
	Default     string      `mapstructure:"default"`
	Type        string      `mapstructure:"type"`
	Options     interface{} `mapstructure:"options"`
	Required    bool        `mapstructure:"required"`
	Editable    bool        `mapstructure:"editable"`
	Min         *int        `mapstructure:"min"`
	Max         *int        `mapstructure:"max"`
	TrueValue   string      `mapstructure:"true_value"`
	FalseValue  string      `mapstructure:"false_value"`
	Path        string      `mapstructure:"path"`
	RecomputeOn []string    `mapstructure:"recompute_on"`
	Implies     interface{} `mapstructure:"implies"`
}

func DiscoverParameters(templateStr string) []TemplateParameter {
	configParams := loadParameterConfig()

	seen := make(map[string]bool)
	var params []TemplateParameter

	// First pass: collect raw defaults so we can resolve nested references.
	rawDefaults := make(map[string]string)
	for key, cfg := range configParams {
		if cfg.Default != "" {
			rawDefaults[key] = cfg.Default
		}
	}
	// Resolve nested {{ chihiro.* }} references within defaults (e.g.
	// parameter defaults referencing other parameters). Built-in tokens like
	// {{ chihiro.version }} are NOT resolved here — they are resolved at
	// cluster creation time so the UI can show the raw template reference.
	resolvedDefaults := resolveNestedDefaults(rawDefaults)

	matches := chihiroParamRegex.FindAllStringSubmatch(templateStr, -1)
	for _, match := range matches {
		key := match[1]
		if seen[key] {
			continue
		}
		seen[key] = true

		p := TemplateParameter{
			Key:      key,
			Type:     "string",
			Required: false,
		}

		// configParams keys come from viper which lowercases them, so match
		// case-insensitively against the template's original casing.
		cfg, ok := configParams[key]
		if !ok {
			cfg, ok = configParams[strings.ToLower(key)]
		}
		if ok {
			if cfg.Label != "" {
				p.Label = cfg.Label
			} else {
				p.Label = humanizeKey(key)
			}
			p.Description = cfg.Description
			p.Default = resolvedDefaults[key]
			if p.Default == "" {
				p.Default = resolvedDefaults[strings.ToLower(key)]
			}
			if cfg.Type != "" {
				p.Type = cfg.Type
			}
			p.Options = normalizeOptions(cfg.Options)
			p.Required = cfg.Required
			p.Editable = cfg.Editable
			p.Min = cfg.Min
			p.Max = cfg.Max
			p.Path = cfg.Path
			p.RecomputeOn = cfg.RecomputeOn
			p.Implies = normalizeImplies(cfg.Implies)
			if p.Type == "boolean" {
				p.TrueValue, p.FalseValue = boolValueStrings(cfg)
				// For booleans the default is the on/off state ("true"/"false"),
				// not the substituted string, so the checkbox renders correctly.
				p.Default = normalizeBool(cfg.Default)
			}
		} else {
			p.Label = humanizeKey(key)
		}

		params = append(params, p)
	}

	return params
}

// resolveNestedDefaults resolves {{ chihiro.* }} references within default
// values using other defaults and optional built-in token overrides. This
// allows a default like "hephaestus-kaas-26.05-{{ chihiro.version }}" to
// expand using the version parameter's default or a provided built-in value.
func resolveNestedDefaults(defaults map[string]string, builtins ...map[string]string) map[string]string {
	resolved := make(map[string]string, len(defaults))
	for k, v := range defaults {
		resolved[k] = v
	}

	// Merge built-in overrides (e.g. version → first available version).
	builtinMap := make(map[string]string)
	for _, b := range builtins {
		for k, v := range b {
			builtinMap[strings.ToLower(k)] = v
		}
	}

	const maxIterations = 5
	for iter := 0; iter < maxIterations; iter++ {
		replaced := false
		for key, val := range resolved {
			newVal := chihiroParamRegex.ReplaceAllStringFunc(val, func(match string) string {
				submatches := chihiroParamRegex.FindStringSubmatch(match)
				if submatches == nil {
					return match
				}
				refKey := strings.ToLower(submatches[1])
				// Check parameter defaults first, then built-in overrides.
				if refVal, ok := resolved[refKey]; ok && refVal != "" {
					replaced = true
					return refVal
				}
				if refVal, ok := builtinMap[refKey]; ok && refVal != "" {
					replaced = true
					return refVal
				}
				return match
			})
			resolved[key] = newVal
		}
		if !replaced {
			break
		}
	}
	return resolved
}

func loadParameterConfig() map[string]parameterConfig {
	result := make(map[string]parameterConfig)

	// viper lowercases keys and AllKeys() returns flattened dotted paths
	// (e.g. "podcidr.label"), so we cannot rely on it to recover the original
	// parameter names. Read the raw nested map instead, which preserves the
	// keys exactly as written in the config file.
	raw, ok := viper.Get("cluster.parameters").(map[string]interface{})
	if !ok {
		return result
	}

	for key, v := range raw {
		fields, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		cfg := parameterConfig{
			Label:       getString(fields, "label"),
			Description: getString(fields, "description"),
			Default:     getScalarString(fields, "default"),
			Type:        getString(fields, "type"),
			Required:    getBool(fields, "required"),
			Options:     fields["options"],
			Editable:    getBool(fields, "editable"),
			Min:         getIntPtr(fields, "min"),
			Max:         getIntPtr(fields, "max"),
			TrueValue:   getScalarString(fields, "true_value"),
			FalseValue:  getScalarString(fields, "false_value"),
			Path:        getString(fields, "path"),
			RecomputeOn: getStringSlice(fields, "recompute_on"),
			Implies:     fields["implies"],
		}
		result[key] = cfg
	}
	return result
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// getScalarString reads a value that may be written in YAML as a string, bool,
// or number (e.g. `default: true` or `false_value: disabled`) and returns its
// string form. Missing keys return "".
func getScalarString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// boolValueStrings returns the on/off substitution strings for a boolean
// parameter, defaulting to "true"/"false" when unset.
func boolValueStrings(cfg parameterConfig) (trueValue, falseValue string) {
	trueValue = cfg.TrueValue
	if trueValue == "" {
		trueValue = "true"
	}
	falseValue = cfg.FalseValue
	if falseValue == "" {
		falseValue = "false"
	}
	return trueValue, falseValue
}

// resolveBooleanParameters returns, for every boolean parameter declared in
// cluster.parameters, the configured on/off string to substitute into the
// template. The user-supplied value (in params, keyed case-insensitively) wins;
// otherwise the parameter's default state is used. Keys are lowercased.
func resolveBooleanParameters(params map[string]string) map[string]string {
	out := make(map[string]string)
	// Index incoming params case-insensitively.
	lowered := make(map[string]string, len(params))
	for k, v := range params {
		lowered[strings.ToLower(k)] = v
	}
	for key, cfg := range loadParameterConfig() {
		if cfg.Type != "boolean" {
			continue
		}
		trueValue, falseValue := boolValueStrings(cfg)
		state, ok := lowered[strings.ToLower(key)]
		if !ok {
			state = cfg.Default
		}
		if isTruthy(state) {
			out[strings.ToLower(key)] = trueValue
		} else {
			out[strings.ToLower(key)] = falseValue
		}
	}
	return out
}

// isTruthy reports whether a raw string represents an "on" boolean state.
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

// normalizeBool maps any truthy/falsy string to the canonical "true"/"false"
// used by the checkbox UI and default handling.
func normalizeBool(s string) string {
	if isTruthy(s) {
		return "true"
	}
	return "false"
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// GetParameterDefaults returns the default values for all template parameters
// defined in the cluster.parameters config section. Nested {{ chihiro.* }}
// references within defaults are resolved using other defaults and built-in
// token values from config (e.g. version → first available version).
func GetParameterDefaults() map[string]string {
	configParams := loadParameterConfig()
	raw := make(map[string]string)
	for key, cfg := range configParams {
		if cfg.Default != "" {
			raw[key] = cfg.Default
		}
	}
	builtinTokens := map[string]string{
		"version": firstAvailableVersion(),
	}
	return resolveNestedDefaults(raw, builtinTokens)
}

// firstAvailableVersion returns the first configured available Kubernetes
// version, used to resolve {{ chihiro.version }} in parameter defaults for UI
// display. Returns empty string if no versions are configured.
func firstAvailableVersion() string {
	versions := viper.GetStringSlice("cluster.available_versions")
	if len(versions) > 0 {
		return versions[0]
	}
	return ""
}

// normalizeOptions converts the raw options value from config (either a string
// slice or a slice of {value, label, versions} objects) into []OptionItem.
func normalizeOptions(raw interface{}) []OptionItem {
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]OptionItem, 0, len(arr))
	for _, item := range arr {
		switch v := item.(type) {
		case string:
			out = append(out, OptionItem{Value: v, Label: v})
		case map[string]interface{}:
			oi := OptionItem{
				Value: getString(v, "value"),
				Label: getString(v, "label"),
			}
			// versions is an optional string slice.
			if rawVersions, ok := v["versions"]; ok {
				if arr2, ok := rawVersions.([]interface{}); ok {
					for _, rv := range arr2 {
						if s, ok := rv.(string); ok {
							oi.Versions = append(oi.Versions, s)
						}
					}
				}
			}
			if oi.Value != "" {
				if oi.Label == "" {
					oi.Label = oi.Value
				}
				out = append(out, oi)
			}
		}
	}
	return out
}

// normalizeImplies converts the raw implies value from config (a slice of
// {field, source} objects) into []ImpliedField. Source defaults to
// "option_version" when omitted.
func normalizeImplies(raw interface{}) []ImpliedField {
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]ImpliedField, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		f := ImpliedField{
			Field:  getString(m, "field"),
			Source: getString(m, "source"),
		}
		if f.Field == "" {
			continue
		}
		if f.Source == "" {
			f.Source = "option_version"
		}
		out = append(out, f)
	}
	return out
}

func humanizeKey(key string) string {
	key = strings.ReplaceAll(key, "_", " ")
	key = strings.ReplaceAll(key, "-", " ")
	words := strings.Fields(key)
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

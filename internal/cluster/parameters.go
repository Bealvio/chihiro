package cluster

import (
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

var chihiroParamRegex = regexp.MustCompile(`\{\{\s*chihiro\.(\w+)\s*\}\}`)

type TemplateParameter struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Default     string   `json:"default"`
	Type        string   `json:"type"`
	Options     []string `json:"options,omitempty"`
	Required    bool     `json:"required"`
	Editable    bool     `json:"editable"`
	Min         *int     `json:"min,omitempty"`
	Max         *int     `json:"max,omitempty"`
}

type parameterConfig struct {
	Label       string   `mapstructure:"label"`
	Description string   `mapstructure:"description"`
	Default     string   `mapstructure:"default"`
	Type        string   `mapstructure:"type"`
	Options     []string `mapstructure:"options"`
	Required    bool     `mapstructure:"required"`
	Editable    bool     `mapstructure:"editable"`
	Min         *int     `mapstructure:"min"`
	Max         *int     `mapstructure:"max"`
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
			p.Options = cfg.Options
			p.Required = cfg.Required
			p.Editable = cfg.Editable
			p.Min = cfg.Min
			p.Max = cfg.Max
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
			Default:     getString(fields, "default"),
			Type:        getString(fields, "type"),
			Required:    getBool(fields, "required"),
			Options:     getStringSlice(fields, "options"),
			Editable:    getBool(fields, "editable"),
			Min:         getIntPtr(fields, "min"),
			Max:         getIntPtr(fields, "max"),
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

func humanizeKey(key string) string {
	key = strings.ReplaceAll(key, "_", " ")
	key = strings.ReplaceAll(key, "-", " ")
	words := strings.Fields(key)
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

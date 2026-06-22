package cluster

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

var templateParamRegex = regexp.MustCompile(`\{\{\s*chihiro\.(\w+)\s*\}\}`)

// ValidateConfig checks the chihiro configuration for common misconfigurations
// and returns an error describing every problem found. An empty error means the
// config is valid. The app must refuse to start when validation fails.
func ValidateConfig() error {
	var errs []string

	// --- cluster.template ---
	tmpl := viper.GetString("cluster.template")
	if strings.TrimSpace(tmpl) == "" {
		errs = append(errs, "cluster.template is empty — a CAPI cluster template is required")
	}

	// --- cluster.available_versions ---
	versions := viper.GetStringSlice("cluster.available_versions")
	if len(versions) == 0 {
		errs = append(errs, "cluster.available_versions is empty — at least one Kubernetes version is required")
	}

	// --- cluster.parameters ---
	rawParams, _ := viper.Get("cluster.parameters").(map[string]interface{})
	if rawParams == nil {
		rawParams = make(map[string]interface{})
	}

	// Collect template refs so we can cross-check against parameter definitions.
	templateRefs := make(map[string]bool)
	if matches := templateParamRegex.FindAllStringSubmatch(tmpl, -1); matches != nil {
		for _, m := range matches {
			templateRefs[strings.ToLower(m[1])] = true
		}
	}

	for key, v := range rawParams {
		fields, ok := v.(map[string]interface{})
		if !ok {
			errs = append(errs, fmt.Sprintf("cluster.parameters.%s: value is not a map", key))
			continue
		}

		ptype := getString(fields, "type")

		// editable without path → changes can't be persisted.
		if getBool(fields, "editable") && getString(fields, "path") == "" {
			errs = append(errs, fmt.Sprintf("cluster.parameters.%s: editable is true but path is empty", key))
		}

		// select without options → form renders an empty dropdown.
		if ptype == "select" {
			opts := fields["options"]
			if opts == nil {
				errs = append(errs, fmt.Sprintf("cluster.parameters.%s: type is select but options is missing", key))
			} else if arr, ok := opts.([]interface{}); !ok || len(arr) == 0 {
				errs = append(errs, fmt.Sprintf("cluster.parameters.%s: type is select but options is empty", key))
			} else {
				for i, item := range arr {
					switch opt := item.(type) {
					case string:
						if strings.TrimSpace(opt) == "" {
							errs = append(errs, fmt.Sprintf("cluster.parameters.%s.options[%d]: value is empty", key, i))
						}
					case map[string]interface{}:
						if getString(opt, "value") == "" {
							errs = append(errs, fmt.Sprintf("cluster.parameters.%s.options[%d]: value field is empty", key, i))
						}
					default:
						errs = append(errs, fmt.Sprintf("cluster.parameters.%s.options[%d]: unsupported type %T", key, i, item))
					}
				}
			}
		}
	}

	// --- template refs vs parameter definitions ---
	// A template ref without a matching parameter entry is likely a typo.
	if tmpl != "" {
		for ref := range templateRefs {
			// Skip built-in tokens that are injected, not user-defined.
			if ref == "version" || ref == "name" || ref == "groups" {
				continue
			}
			if _, ok := rawParams[ref]; !ok {
				// Also check case-insensitive match since viper lowercases keys.
				found := false
				for pk := range rawParams {
					if strings.EqualFold(pk, ref) {
						found = true
						break
					}
				}
				if !found {
					errs = append(errs, fmt.Sprintf("template references {{ chihiro.%s }} but no matching cluster.parameters.%s is defined", ref, ref))
				}
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
}

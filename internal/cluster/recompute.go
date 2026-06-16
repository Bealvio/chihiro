package cluster

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// recomputedParameter is the result of recomputing a dependent parameter: the
// raw state to persist in the chihiro.io/parameters annotation and the value to
// write at the parameter's configured YAML path.
type recomputedParameter struct {
	Key         string
	Path        string
	StoredState string
	WriteValue  string
}

// recomputeDependents finds every editable parameter that declares a dependency
// (recompute_on) on any of the changed fields and computes its new value.
//
// This is the generic engine behind "editing field X also edits field Y": a
// parameter Y declares `recompute_on: [X]` and an optional value template /
// version-constrained options, and whenever X changes the parameter's value is
// re-resolved using the new value of X (plus the cluster's existing parameter
// state for any other tokens).
//
// changed maps the lowercased name of each field being edited to its new value
// (e.g. {"version": "v1.36.1"}). existing holds the cluster's currently stored
// parameter raw states (from the chihiro.io/parameters annotation), used to
// resolve tokens that are not part of the change set.
//
// Parameters without a configured path are skipped (they cannot be written to
// the live object). Returns the recomputed parameters in no particular order.
func recomputeDependents(changed, existing map[string]string) []recomputedParameter {
	if len(changed) == 0 {
		return nil
	}

	// Index the changed set case-insensitively.
	changedLower := make(map[string]string, len(changed))
	for k, v := range changed {
		changedLower[strings.ToLower(k)] = v
	}

	// Token table used to resolve {{ chihiro.* }} references in the recomputed
	// value: changed values win, then existing parameter state.
	tokens := make(map[string]string)
	for k, v := range existing {
		tokens[strings.ToLower(k)] = v
	}
	for k, v := range changedLower {
		tokens[k] = v
	}

	// Recover the original parameter casing from the template tokens (viper
	// lowercases config keys) so recomputed keys match those used elsewhere
	// (annotation, API). Mirrors GetEditableFields.
	casing := make(map[string]string)
	for _, m := range chihiroParamRegex.FindAllStringSubmatch(viper.GetString("cluster.template"), -1) {
		casing[strings.ToLower(m[1])] = m[1]
	}

	var out []recomputedParameter
	for key, cfg := range loadParameterConfig() {
		if len(cfg.RecomputeOn) == 0 || cfg.Path == "" {
			continue
		}
		if !dependsOnAny(cfg.RecomputeOn, changedLower) {
			continue
		}

		// Determine the candidate value to (re-)resolve. For select parameters
		// with version-constrained options, pick the option compatible with the
		// changed value (when one of the triggers is a version-like field).
		candidate := pickParameterCandidate(cfg, existing[strings.ToLower(key)], tokens)
		if candidate == "" {
			continue
		}

		outKey := key
		if c, ok := casing[strings.ToLower(key)]; ok {
			outKey = c
		}

		resolved := resolveTokens(candidate, tokens)
		out = append(out, recomputedParameter{
			Key:         outKey,
			Path:        cfg.Path,
			StoredState: candidate,
			WriteValue:  resolved,
		})
	}
	return out
}

// applyRecomputedDependents recomputes every parameter that depends on any of
// the changed fields and applies the results to the given cluster object: each
// recomputed value is written at its configured YAML path and its raw state is
// persisted in the chihiro.io/parameters annotation. It mutates cluster in
// place and is a no-op when no dependent parameters are configured. changed maps
// field name -> new (raw) value (e.g. {"version": "v1.36.1"}).
func applyRecomputedDependents(cluster *unstructured.Unstructured, changed map[string]string) {
	// Read the cluster's currently stored parameter raw states.
	existing := map[string]string{}
	annotations := cluster.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	if raw, ok := annotations["chihiro.io/parameters"]; ok && raw != "" {
		if err := json.Unmarshal([]byte(raw), &existing); err != nil {
			slog.Warn("Failed to parse parameters annotation during recompute; ignoring", "error", err)
			existing = map[string]string{}
		}
	}

	recomputed := recomputeDependents(changed, existing)
	if len(recomputed) == 0 {
		return
	}

	params := make(map[string]string, len(existing))
	for k, v := range existing {
		params[k] = v
	}
	for _, r := range recomputed {
		setYAMLPath(cluster.Object, r.Path, r.WriteValue)
		params[r.Key] = r.StoredState
		slog.Info("Recomputed dependent parameter", "key", r.Key, "path", r.Path, "value", r.WriteValue)
	}

	if paramsJSON, err := json.Marshal(params); err == nil {
		annotations["chihiro.io/parameters"] = string(paramsJSON)
		cluster.SetAnnotations(annotations)
	} else {
		slog.Warn("Failed to marshal parameters annotation after recompute", "error", err)
	}
}

// dependsOnAny reports whether any name in deps matches a changed field
// (case-insensitive).
func dependsOnAny(deps []string, changedLower map[string]string) bool {
	for _, d := range deps {
		if _, ok := changedLower[strings.ToLower(strings.TrimSpace(d))]; ok {
			return true
		}
	}
	return false
}

// pickParameterCandidate returns the raw (still-templated) value to resolve for
// a dependent parameter. For select parameters whose options declare compatible
// versions, it prefers the option compatible with the new version (drawn from
// the changed tokens). If the currently stored option is still compatible, it
// is kept (only the embedded tokens are re-resolved). Falls back to the current
// stored value, then the parameter default.
func pickParameterCandidate(cfg parameterConfig, current string, tokens map[string]string) string {
	opts := normalizeOptions(cfg.Options)

	// Non-select or option-less parameter: just re-resolve the current value
	// (or the default).
	if cfg.Type != "select" || len(opts) == 0 {
		if current != "" {
			return current
		}
		return cfg.Default
	}

	// Identify a version trigger value if present so we can honour the per-
	// option `versions` compatibility lists.
	newVersion := tokens["version"]

	// If the current value matches an option that is still compatible with the
	// new version, keep that option (its raw, pre-resolution form).
	if current != "" {
		for _, o := range opts {
			if rawValuesEqual(o.Value, current, tokens) && optionCompatible(o, newVersion) {
				return o.Value
			}
		}
	}

	// Otherwise choose the first option compatible with the new version.
	if newVersion != "" {
		for _, o := range opts {
			if optionCompatible(o, newVersion) {
				return o.Value
			}
		}
	}

	// No version constraint matched: keep current if set, else default.
	if current != "" {
		return current
	}
	return cfg.Default
}

// optionCompatible reports whether an option is usable for the given version.
// Options without a versions list are considered compatible with everything.
func optionCompatible(o OptionItem, version string) bool {
	if len(o.Versions) == 0 {
		return true
	}
	if version == "" {
		return false
	}
	for _, v := range o.Versions {
		if strings.EqualFold(strings.TrimSpace(v), version) {
			return true
		}
	}
	return false
}

// rawValuesEqual compares an option's raw (templated) value against a stored
// value. The stored value may have been persisted either in raw templated form
// or already resolved, so compare both raw and resolved forms.
func rawValuesEqual(optionValue, stored string, tokens map[string]string) bool {
	if optionValue == stored {
		return true
	}
	return resolveTokens(optionValue, tokens) == resolveTokens(stored, tokens)
}

// resolveTokens replaces {{ chihiro.* }} references in val using the supplied
// case-insensitive token table. Unknown tokens are left untouched.
func resolveTokens(val string, tokens map[string]string) string {
	const maxIterations = 5
	for i := 0; i < maxIterations; i++ {
		replaced := false
		val = chihiroParamRegex.ReplaceAllStringFunc(val, func(match string) string {
			sub := chihiroParamRegex.FindStringSubmatch(match)
			if sub == nil {
				return match
			}
			if v, ok := tokens[strings.ToLower(sub[1])]; ok && v != "" {
				replaced = true
				return v
			}
			return match
		})
		if !replaced {
			break
		}
	}
	return val
}

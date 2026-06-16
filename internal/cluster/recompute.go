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

// impliedFieldValues returns the field values implied by editing the parameter
// identified by key to rawState. This is the reverse direction of recompute:
// for a select parameter with `implies` mappings, the selected option's
// metadata (e.g. its versions list) determines the value of another field such
// as the cluster version. Returns a map of lowercased field name -> value.
func impliedFieldValues(key, rawState string) map[string]string {
	cfg, ok := loadParameterConfig()[strings.ToLower(key)]
	if !ok {
		// loadParameterConfig keys preserve original config casing; retry exact.
		cfg, ok = loadParameterConfig()[key]
	}
	if !ok || len(normalizeImplies(cfg.Implies)) == 0 {
		return nil
	}

	opts := normalizeOptions(cfg.Options)
	selected := selectedOption(opts, rawState)

	out := map[string]string{}
	for _, imp := range normalizeImplies(cfg.Implies) {
		switch imp.Source {
		case "option_version":
			if selected != nil && len(selected.Versions) > 0 {
				out[strings.ToLower(imp.Field)] = selected.Versions[0]
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// selectedOption returns the option matching rawState, comparing both the raw
// (templated) option value and a token-stripped form so a stored value like
// "hephaestus-kaas-26.05-v1.36.1" still matches the option
// "hephaestus-kaas-26.05-{{ chihiro.version }}".
func selectedOption(opts []OptionItem, rawState string) *OptionItem {
	for i := range opts {
		if opts[i].Value == rawState {
			return &opts[i]
		}
	}
	// Compare with the chihiro token reduced to a wildcard match: replace the
	// token in each option value with the version captured from rawState.
	for i := range opts {
		if optionMatchesResolved(opts[i].Value, rawState) {
			return &opts[i]
		}
	}
	return nil
}

// optionMatchesResolved reports whether a (possibly resolved) stored value
// corresponds to an option whose raw value contains {{ chihiro.version }}. It
// strips the static prefix/suffix around the token and checks the stored value
// matches that shape.
func optionMatchesResolved(optionValue, stored string) bool {
	loc := chihiroParamRegex.FindStringIndex(optionValue)
	if loc == nil {
		return optionValue == stored
	}
	prefix := optionValue[:loc[0]]
	suffix := optionValue[loc[1]:]
	return strings.HasPrefix(stored, prefix) && strings.HasSuffix(stored, suffix) &&
		len(stored) >= len(prefix)+len(suffix)
}

// applyImpliedFields applies the fields implied by editing a parameter to the
// cluster object: each implied built-in field is written at its injection path
// (e.g. version -> spec.topology.version). It mutates cluster in place and is a
// no-op when the parameter declares no implications. Returns the applied field
// values (lowercased) so the caller can drive coherent recompute of any other
// dependents.
func applyImpliedFields(cluster *unstructured.Unstructured, key, rawState string) map[string]string {
	implied := impliedFieldValues(key, rawState)
	if len(implied) == 0 {
		return nil
	}
	for field, value := range implied {
		path := builtinFieldPath(field)
		if path == "" {
			slog.Warn("Implied field has no injection path; skipping", "field", field, "source_param", key)
			continue
		}
		setYAMLPath(cluster.Object, path, value)
		slog.Info("Applied implied field from parameter edit", "field", field, "value", value, "source_param", key)
	}
	return implied
}

// builtinFieldPath returns the YAML injection path for a built-in field
// (e.g. "version" -> spec.topology.version), looked up case-insensitively.
// Returns "" when the field is not a configured injection.
func builtinFieldPath(field string) string {
	for key, cfg := range loadInjectionConfig() {
		if strings.EqualFold(key, field) || strings.EqualFold(canonicalBuiltinKeys[strings.ToLower(key)], field) {
			return cfg.Path
		}
	}
	return ""
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

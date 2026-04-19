package redact

import "github.com/krypsis-io/wick/detect"

// PerRule wraps a fallback Replacer and applies per-rule replacement overrides.
// If a finding's RuleID has an entry in the overrides map, that string is used
// instead of the fallback replacer's output.
//
// This is used to honour per-pattern replacement fields defined in .wick.yaml.
func PerRule(fallback Replacer, overrides map[string]string) Replacer {
	if len(overrides) == 0 {
		return fallback
	}
	return perRuleReplacer{fallback: fallback, overrides: overrides}
}

type perRuleReplacer struct {
	fallback  Replacer
	overrides map[string]string
}

func (r perRuleReplacer) Replace(value string, finding detect.Finding) string {
	if s, ok := r.overrides[finding.RuleID]; ok {
		return s
	}
	return r.fallback.Replace(value, finding)
}

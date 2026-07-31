// Package detect provides secret, PII, and custom pattern detection.
package detect

import (
	"fmt"
	"os"
	"strings"
)

// Detector orchestrates secret, PII, and custom pattern detection.
type Detector struct {
	secretRules    []SecretRule
	customPatterns []compiledCustom
	allowlist      []compiledAllowlistEntry
	disabledPII    map[string]bool
}

// New creates a Detector with the embedded Gitleaks patterns and built-in PII rules.
func New() (*Detector, error) {
	rules, err := LoadSecretRules()
	if err != nil {
		return nil, err
	}
	return &Detector{secretRules: rules}, nil
}

// AddRulesFile loads additional secret rules from a Gitleaks-compatible TOML
// file and appends them to the detector's existing rules.
func (d *Detector) AddRulesFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading rules file %q: %w", path, err)
	}
	extra, err := LoadSecretRulesFromBytes(data)
	if err != nil {
		return fmt.Errorf("parsing rules file %q: %w", path, err)
	}
	d.secretRules = append(d.secretRules, extra...)
	return nil
}

// DisableRules removes rules with the given IDs from the detector.
// Unknown IDs are silently ignored.
func (d *Detector) DisableRules(ids []string) {
	if len(ids) == 0 {
		return
	}
	disabled := make(map[string]bool, len(ids))
	for _, id := range ids {
		disabled[id] = true
	}
	kept := d.secretRules[:0]
	for _, r := range d.secretRules {
		if !disabled[r.ID] {
			kept = append(kept, r)
		}
	}
	d.secretRules = kept

	// Also track disabled PII rule IDs (email, ipv4, etc.).
	for id := range disabled {
		if d.disabledPII == nil {
			d.disabledPII = make(map[string]bool)
		}
		d.disabledPII[id] = true
	}
}

// SetCustomPatterns loads user-defined patterns into the detector.
func (d *Detector) SetCustomPatterns(patterns []CustomPattern) error {
	compiled, err := compileCustomPatterns(patterns)
	if err != nil {
		return err
	}
	d.customPatterns = compiled
	return nil
}

// Detect scans the input text and returns all findings.
// Input is processed line by line; use DetectMultiline for patterns that span lines.
func (d *Detector) Detect(input string) []Finding {
	lines := strings.Split(input, "\n")
	var all []Finding
	for i, line := range lines {
		lineNum := i + 1
		all = append(all, matchSecretRules(d.secretRules, line, lineNum)...)
		all = append(all, matchPII(line, lineNum, d.disabledPII)...)
		all = append(all, matchCustom(d.customPatterns, line, lineNum)...)
	}
	return dedupeIdenticalSpans(d.filterAllowed(all))
}

// DetectMultiline runs only multiline-capable rules against the full unsplit input.
// Returned findings have Start/End as byte offsets within the full input string.
func (d *Detector) DetectMultiline(input string) []Finding {
	lower := strings.ToLower(input)
	var all []Finding
	for i := range d.secretRules {
		rule := &d.secretRules[i]
		if !rule.Multiline {
			continue
		}
		if len(rule.Keywords) > 0 {
			found := false
			for _, kw := range rule.Keywords {
				if strings.Contains(lower, kw) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		matches := rule.Regex.FindAllStringSubmatchIndex(input, -1)
		for _, match := range matches {
			matchStart := match[0]
			lineNum := strings.Count(input[:matchStart], "\n") + 1
			// Pass only the matched line as lineContext so allowlist rules with
			// RegexTarget == "line" match against the relevant line, not the full input.
			lineContext := extractLine(input, matchStart)
			if f, ok := resolveMatch(rule, input, lineContext, match, lineNum); ok {
				all = append(all, f)
			}
		}
	}
	return dedupeIdenticalSpans(d.filterAllowed(all))
}

// dedupeIdenticalSpans collapses findings that cover the exact same span into a
// single finding, so summaries and reports count redacted values, not the number
// of rules that happened to match them (e.g. a GitHub PAT matches both
// github-pat and the generic-api-key catch-all). The most specific finding wins:
// user-defined custom patterns first (their per-rule replacements must apply),
// then specific secret rules, then PII, with the generic-api-key catch-all
// always losing to a co-match. Ties keep the first finding in rule order.
func dedupeIdenticalSpans(findings []Finding) []Finding {
	if len(findings) < 2 {
		return findings
	}
	type spanKey struct{ line, start, end int }
	out := make([]Finding, 0, len(findings))
	idx := make(map[spanKey]int, len(findings))
	for _, f := range findings {
		k := spanKey{f.Line, f.Start, f.End}
		if i, ok := idx[k]; ok {
			if dedupePriority(f) < dedupePriority(out[i]) {
				out[i] = f
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, f)
	}
	return out
}

// dedupePriority orders findings on identical spans; lower wins.
func dedupePriority(f Finding) int {
	switch {
	case f.Category == "custom":
		return 0
	case f.RuleID == "generic-api-key":
		return 3
	case f.Category == "secret":
		return 1
	default: // pii
		return 2
	}
}

// extractLine returns the single line within s that contains byte position pos.
func extractLine(s string, pos int) string {
	start := strings.LastIndex(s[:pos], "\n") + 1 // 0 when no prior newline
	rest := s[start:]
	if nl := strings.Index(rest, "\n"); nl >= 0 {
		return rest[:nl]
	}
	return rest
}

// resolveMatch validates a regex submatch against entropy and allowlist rules and
// returns a Finding if the match is accepted.
//
// text is the string being matched (a single line for per-line rules, the full input
// for multiline rules). lineContext is passed to isAllowed for rules with
// RegexTarget == "line": for per-line calls text == lineContext; for full-input calls
// pass the specific matched line via extractLine so the allowlist sees the right scope.
func resolveMatch(rule *SecretRule, text, lineContext string, match []int, lineNum int) (Finding, bool) {
	// Mirror gitleaks: the secret is the configured secretGroup, or the first
	// non-empty capture group when secretGroup is unset, or the full match when
	// no capture group applies. Entropy and stopword checks run against the
	// secret, not the full match — otherwise key names like "password" in
	// `password=...` trip the rule's own stopword list.
	startIdx, endIdx := 0, 1
	if rule.SecretGroup > 0 {
		// A configured group that is out of range, unmatched, or empty is a
		// rule misconfiguration; gitleaks rejects the match rather than
		// falling back to the full match.
		si := rule.SecretGroup * 2
		if si+1 >= len(match) || match[si] < 0 || match[si] >= match[si+1] {
			return Finding{}, false
		}
		startIdx, endIdx = si, si+1
	} else {
		// When every capture group is empty, gitleaks keeps the full match as
		// the secret; do the same rather than dropping the finding.
		for gi := 2; gi+1 < len(match); gi += 2 {
			if match[gi] >= 0 && match[gi] < match[gi+1] {
				startIdx, endIdx = gi, gi+1
				break
			}
		}
	}
	start := match[startIdx]
	end := match[endIdx]
	value := text[start:end]
	fullMatch := text[match[0]:match[1]]
	if rule.Entropy > 0 && shannonEntropy(value) < rule.Entropy {
		return Finding{}, false
	}
	if isAllowed(rule.Allowlists, lineContext, fullMatch, value) {
		return Finding{}, false
	}
	return Finding{
		Category: "secret",
		RuleID:   rule.ID,
		Value:    value,
		Start:    start,
		End:      end,
		Line:     lineNum,
	}, true
}

// Package detect provides secret, PII, and custom pattern detection.
package detect

import (
	"strings"
)

// Detector orchestrates secret, PII, and custom pattern detection.
type Detector struct {
	secretRules    []SecretRule
	customPatterns []compiledCustom
}

// New creates a Detector with the embedded Gitleaks patterns and built-in PII rules.
func New() (*Detector, error) {
	rules, err := LoadSecretRules()
	if err != nil {
		return nil, err
	}
	return &Detector{secretRules: rules}, nil
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
		all = append(all, matchPII(line, lineNum)...)
		all = append(all, matchCustom(d.customPatterns, line, lineNum)...)
	}
	return all
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
	return all
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
	group := rule.SecretGroup
	startIdx := group * 2
	endIdx := startIdx + 1
	if startIdx >= len(match) || match[startIdx] < 0 {
		startIdx = 0
		endIdx = 1
	}
	start := match[startIdx]
	end := match[endIdx]
	value := text[start:end]
	if rule.Entropy > 0 && shannonEntropy(value) < rule.Entropy {
		return Finding{}, false
	}
	if isAllowed(rule.Allowlists, lineContext, value) {
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

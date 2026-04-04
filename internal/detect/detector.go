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
			group := rule.SecretGroup
			startIdx := group * 2
			endIdx := startIdx + 1
			if startIdx >= len(match) || match[startIdx] < 0 {
				startIdx = 0
				endIdx = 1
			}
			start := match[startIdx]
			end := match[endIdx]
			value := input[start:end]
			if rule.Entropy > 0 && shannonEntropy(value) < rule.Entropy {
				continue
			}
			if isAllowed(rule.Allowlists, input, value) {
				continue
			}
			lineNum := strings.Count(input[:start], "\n") + 1
			all = append(all, Finding{
				Category: "secret",
				RuleID:   rule.ID,
				Value:    value,
				Start:    start,
				End:      end,
				Line:     lineNum,
			})
		}
	}
	return all
}

// Package detect provides secret, PII, and custom pattern detection.
package detect

import "strings"

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

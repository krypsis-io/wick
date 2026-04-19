package detect

import (
	"regexp"
	"strings"
)

// AllowlistEntry defines a known-safe value that should not be redacted.
// Pattern is treated as a literal string by default; set Regex to true to
// treat it as a regular expression. File globs are not evaluated here —
// callers with file-path context are responsible for pre-filtering.
type AllowlistEntry struct {
	Pattern string `yaml:"pattern"`
	Regex   bool   `yaml:"regex,omitempty"`
	Reason  string `yaml:"reason,omitempty"`
}

type compiledAllowlistEntry struct {
	literal string
	re      *regexp.Regexp
}

// SetAllowlist compiles and stores project-level allowlist entries. Findings
// whose Value matches any entry will be suppressed from Detect output.
func (d *Detector) SetAllowlist(entries []AllowlistEntry) error {
	compiled := make([]compiledAllowlistEntry, 0, len(entries))
	for _, e := range entries {
		if e.Regex {
			re, err := regexp.Compile(e.Pattern)
			if err != nil {
				return err
			}
			compiled = append(compiled, compiledAllowlistEntry{re: re})
		} else {
			compiled = append(compiled, compiledAllowlistEntry{literal: e.Pattern})
		}
	}
	d.allowlist = compiled
	return nil
}

// isProjectAllowed returns true if value matches any compiled allowlist entry.
func (d *Detector) isProjectAllowed(value string) bool {
	for _, e := range d.allowlist {
		if e.re != nil {
			if e.re.MatchString(value) {
				return true
			}
		} else if strings.EqualFold(e.literal, value) {
			return true
		}
	}
	return false
}

// filterAllowed removes findings that match the project-level allowlist.
func (d *Detector) filterAllowed(findings []Finding) []Finding {
	if len(d.allowlist) == 0 {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if !d.isProjectAllowed(f.Value) {
			out = append(out, f)
		}
	}
	return out
}

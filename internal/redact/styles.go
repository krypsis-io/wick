package redact

import "github.com/krypsis-io/wick/internal/detect"

// Replacer determines how detected values are replaced in redacted output.
// Static styles ignore the arguments and return a fixed string. Context-aware
// replacers (hash, tokenize) use the value and finding to produce per-match output.
type Replacer interface {
	Replace(value string, finding detect.Finding) string
}

type staticReplacer struct {
	replacement string
}

func (r staticReplacer) Replace(string, detect.Finding) string {
	return r.replacement
}

// Replacement returns the static replacement string, or empty for dynamic replacers.
func (r staticReplacer) Replacement() string {
	return r.replacement
}

// Predefined replacers.
var (
	Redacted Replacer = staticReplacer{"[REDACTED]"}
	Stars    Replacer = staticReplacer{"***"}
)

// Custom returns a Replacer that always uses the given string.
func Custom(replacement string) Replacer {
	return staticReplacer{replacement}
}

// StaticReplacement returns the fixed replacement string if r is a static
// replacer, or empty string and false otherwise.
func StaticReplacement(r Replacer) (string, bool) {
	if sr, ok := r.(staticReplacer); ok {
		return sr.replacement, true
	}
	return "", false
}

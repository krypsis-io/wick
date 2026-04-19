package wick

import (
	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

// config holds the resolved options for a Redact call.
type config struct {
	replacer       redact.Replacer
	customPatterns []detect.CustomPattern
	allowlist      []detect.AllowlistEntry
	blocklist      []detect.CustomPattern
	rulesFile      string
	disableRules   []string
}

// Option configures a Redact call.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(c *config) { f(c) }

// WithReplacer sets the replacement strategy for redacted values.
// Use redact.Redacted, redact.Stars, redact.Custom("..."), or a custom Replacer.
func WithReplacer(r redact.Replacer) Option {
	return optionFunc(func(c *config) {
		c.replacer = r
	})
}

// WithCustomPatterns adds user-defined detection patterns.
func WithCustomPatterns(patterns []detect.CustomPattern) Option {
	return optionFunc(func(c *config) {
		c.customPatterns = append(c.customPatterns, patterns...)
	})
}

// WithAllowlist adds known-safe patterns that will never be redacted.
// Each entry can be an exact string or a regex (set Regex: true).
func WithAllowlist(entries []detect.AllowlistEntry) Option {
	return optionFunc(func(c *config) {
		c.allowlist = append(c.allowlist, entries...)
	})
}

// WithBlocklist adds patterns that are always redacted, even if not matched
// by built-in rules. Each entry is treated as a custom detection pattern.
func WithBlocklist(entries []detect.CustomPattern) Option {
	return optionFunc(func(c *config) {
		c.blocklist = append(c.blocklist, entries...)
	})
}

// WithRulesFile loads additional secret detection rules from a
// Gitleaks-compatible TOML file, appending them to the built-in rules.
func WithRulesFile(path string) Option {
	return optionFunc(func(c *config) {
		c.rulesFile = path
	})
}

// WithDisabledRules removes the named rules from the detector.
// Use this to suppress built-in rules that produce false positives.
func WithDisabledRules(ids []string) Option {
	return optionFunc(func(c *config) {
		c.disableRules = append(c.disableRules, ids...)
	})
}

package wick

import (
	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

// config holds the resolved options for a Redact call.
type config struct {
	replacer       redact.Replacer
	customPatterns []detect.CustomPattern
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

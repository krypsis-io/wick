// Package wick provides secret and PII detection and redaction for text streams.
//
// Wick detects secrets (API keys, tokens, credentials), PII (emails, IPs, SSNs),
// and custom patterns in any text input. It supports multiple redaction styles,
// format-aware processing (JSON, YAML, .env), and deterministic hash-based
// pseudonymization.
//
// Basic usage:
//
//	output, report, err := wick.Redact(input)
//
// With options:
//
//	output, report, err := wick.Redact(input,
//	    wick.WithReplacer(redact.Stars),
//	    wick.WithCustomPatterns(patterns),
//	)
package wick

import (
	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/format"
	"github.com/krypsis-io/wick/redact"
)

// Redact detects and redacts secrets and PII in the input string.
// It auto-detects the input format (JSON, YAML, .env, plain text) and
// applies format-aware redaction. The function is safe for concurrent use.
func Redact(input string, opts ...Option) (string, Report, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o.apply(cfg)
	}

	detector, err := buildDetector(cfg)
	if err != nil {
		return "", Report{}, err
	}

	redacted, findings := format.Process(input, detector, cfg.replacer)
	return redacted, buildReport(findings), nil
}

func buildDetector(cfg *config) (*detect.Detector, error) {
	d, err := detect.New()
	if err != nil {
		return nil, err
	}
	if len(cfg.customPatterns) > 0 {
		if err := d.SetCustomPatterns(cfg.customPatterns); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func buildReport(findings []detect.Finding) Report {
	r := Report{
		Findings: make([]Finding, len(findings)),
		ByRule:   make(map[string]int),
	}
	for i, f := range findings {
		r.Findings[i] = Finding{
			Category: f.Category,
			RuleID:   f.RuleID,
			Value:    f.Value,
			Start:    f.Start,
			End:      f.End,
			Line:     f.Line,
		}
		r.ByRule[f.RuleID]++
	}
	r.Total = len(findings)
	return r
}

func defaultConfig() *config {
	return &config{
		replacer: redact.Redacted,
	}
}

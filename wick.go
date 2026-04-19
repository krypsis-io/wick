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
	"strings"

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

	// Merge custom patterns and blocklist (blocklist is always-detect patterns).
	all := append(cfg.customPatterns, cfg.blocklist...)
	if len(all) > 0 {
		if err := d.SetCustomPatterns(all); err != nil {
			return nil, err
		}
	}

	if len(cfg.allowlist) > 0 {
		if err := d.SetAllowlist(cfg.allowlist); err != nil {
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

// Dehydrate redacts input using reversible token replacement and returns the
// redacted text along with a TokenMap that can be used to restore the original.
// The token map is encrypted with the provided AES-256 key (see GenerateKey).
// Each unique value gets a stable token of the form [RULEID-N], so the same
// value always maps to the same token within a single Dehydrate call.
func Dehydrate(input string, key []byte, opts ...Option) (string, TokenMap, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o.apply(cfg)
	}

	detector, err := buildDetector(cfg)
	if err != nil {
		return "", TokenMap{}, err
	}

	tr := redact.NewTokenizeReplacer()
	redacted, _ := format.Process(input, detector, tr)

	entries := tr.Entries()
	tm := TokenMap{entries: make(map[string]*TokenEntry, len(entries))}
	for token, e := range entries {
		tm.entries[token] = &TokenEntry{
			Original:    e.Original,
			Replacement: e.Replacement,
			Category:    e.Category,
			RuleID:      e.RuleID,
			Count:       e.Count,
		}
	}

	return redacted, tm, nil
}

// Rehydrate restores original values in a previously dehydrated string using
// the provided TokenMap. It performs a simple string replacement of each token
// with its original value.
func Rehydrate(input string, tm TokenMap) (string, error) {
	result := input
	for token, entry := range tm.entries {
		result = strings.ReplaceAll(result, token, entry.Original)
	}
	return result, nil
}

func defaultConfig() *config {
	return &config{
		replacer: redact.Redacted,
	}
}

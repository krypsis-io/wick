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
	"regexp"
	"sort"

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

	replacer := buildReplacer(cfg.replacer, cfg.customPatterns)
	redacted, findings := format.Process(input, detector, replacer)
	return redacted, buildReport(findings), nil
}

func buildDetector(cfg *config) (*detect.Detector, error) {
	d, err := detect.New()
	if err != nil {
		return nil, err
	}

	if cfg.rulesFile != "" {
		if err := d.AddRulesFile(cfg.rulesFile); err != nil {
			return nil, err
		}
	}

	if len(cfg.disableRules) > 0 {
		d.DisableRules(cfg.disableRules)
	}

	// Merge custom patterns and blocklist (blocklist is always-detect patterns).
	// Allocate a fresh slice so we never alias cfg.customPatterns' backing array.
	all := make([]detect.CustomPattern, 0, len(cfg.customPatterns)+len(cfg.blocklist))
	all = append(all, cfg.customPatterns...)
	all = append(all, cfg.blocklist...)
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

// buildReplacer wraps the base replacer with per-pattern overrides if any
// custom patterns have a Replacement field set.
func buildReplacer(base redact.Replacer, patterns []detect.CustomPattern) redact.Replacer {
	overrides := make(map[string]string)
	for _, p := range patterns {
		if p.Replacement != "" {
			overrides[p.Name] = p.Replacement
		}
	}
	return redact.PerRule(base, overrides)
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
// The returned TokenMap holds the plaintext originals in memory; use
// SaveTokenMap to persist it encrypted with an AES-256 key (see GenerateKey).
// Each unique value gets a stable token of the form [RULEID-N], so the same
// value always maps to the same token within a single Dehydrate call. Use
// WithTokenMap to keep the tokens of an earlier call.
func Dehydrate(input string, opts ...Option) (string, TokenMap, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o.apply(cfg)
	}

	detector, err := buildDetector(cfg)
	if err != nil {
		return "", TokenMap{}, err
	}

	// Use the tokenizer directly rather than wrapping it with per-pattern
	// replacement overrides: every replaced value must produce a reversible
	// TokenEntry, and a static override string would redact irreversibly.
	tr := redact.NewTokenizeReplacer()
	if cfg.tokenMap != nil {
		existing := make(map[string]*redact.TokenEntry, len(cfg.tokenMap.entries))
		for token, e := range cfg.tokenMap.entries {
			existing[token] = &redact.TokenEntry{
				Original:    e.Original,
				Replacement: e.Replacement,
				Category:    e.Category,
				RuleID:      e.RuleID,
				Count:       e.Count,
			}
		}
		tr = redact.NewTokenizeReplacerFrom(existing)
	}
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
// the provided TokenMap. Each token is replaced with its original value; for
// JSON and YAML input the original is encoded for the document, so values
// containing newlines or quotes (such as a PEM private key) still produce a
// valid document.
func Rehydrate(input string, tm TokenMap) (string, error) {
	originals := make(map[string]string, len(tm.entries))
	for token, entry := range tm.entries {
		originals[token] = entry.Original
	}
	return format.Restore(input, originals), nil
}

// tokenPattern matches text of the form of a token, such as [EMAIL-1].
var tokenPattern = regexp.MustCompile(`\[([A-Z0-9][A-Z0-9_.-]*)-[0-9]+\]`)

// UnknownTokens returns the tokens in input that are not in tm, sorted and
// without duplicates. It reports only tokens whose tag, such as EMAIL in
// [EMAIL-9], is used by a token in tm, so that other bracketed text is not
// reported. Rehydrate leaves unknown tokens unchanged.
func UnknownTokens(input string, tm TokenMap) []string {
	tags := make(map[string]bool)
	for token := range tm.entries {
		if m := tokenPattern.FindStringSubmatch(token); m != nil {
			tags[m[1]] = true
		}
	}
	seen := make(map[string]bool)
	var unknown []string
	for _, m := range tokenPattern.FindAllStringSubmatch(input, -1) {
		token := m[0]
		if _, ok := tm.entries[token]; ok || !tags[m[1]] || seen[token] {
			continue
		}
		seen[token] = true
		unknown = append(unknown, token)
	}
	sort.Strings(unknown)
	return unknown
}

func defaultConfig() *config {
	return &config{
		replacer: redact.Redacted,
	}
}

package redact

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/krypsis-io/wick/detect"
)

// TokenEntry records a single redaction mapping.
type TokenEntry struct {
	Original    string
	Replacement string
	Category    string
	RuleID      string
	Count       int
}

// TokenizeReplacer is a Replacer that replaces each unique value with a
// deterministic token of the form [CATEGORY-N]. The same original value
// always maps to the same token within a session. Call Entries() after
// processing to retrieve the full mapping.
type TokenizeReplacer struct {
	mu      sync.Mutex
	byValue map[string]*TokenEntry // original value → entry
	counter map[string]int         // category → next counter
	used    map[string]bool        // tokens already assigned
}

// NewTokenizeReplacer creates a TokenizeReplacer ready for use.
func NewTokenizeReplacer() *TokenizeReplacer {
	return &TokenizeReplacer{
		byValue: make(map[string]*TokenEntry),
		counter: make(map[string]int),
		used:    make(map[string]bool),
	}
}

// NewTokenizeReplacerFrom creates a TokenizeReplacer that already holds
// entries, such as the entries of an earlier run. A value that is in entries
// keeps its token, and new tokens continue the numbering of each rule.
func NewTokenizeReplacerFrom(entries map[string]*TokenEntry) *TokenizeReplacer {
	t := NewTokenizeReplacer()
	for _, e := range entries {
		cp := *e
		t.byValue[cp.Original] = &cp
		t.used[cp.Replacement] = true
		tag := strings.ToUpper(cp.RuleID)
		if n := tokenNumber(cp.Replacement, tag); n > t.counter[tag] {
			t.counter[tag] = n
		}
	}
	return t
}

// tokenNumber returns N for a token of the form [TAG-N], or 0.
func tokenNumber(token, tag string) int {
	digits, ok := strings.CutPrefix(token, "["+tag+"-")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSuffix(digits, "]"))
	if err != nil {
		return 0
	}
	return n
}

// Replace satisfies the Replacer interface. It assigns a stable token to each
// unique value, recording the mapping for later retrieval via Entries.
func (t *TokenizeReplacer) Replace(value string, finding detect.Finding) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry, ok := t.byValue[value]; ok {
		entry.Count++
		return entry.Replacement
	}

	tag := strings.ToUpper(finding.RuleID)
	var token string
	for token == "" || t.used[token] {
		t.counter[tag]++
		token = fmt.Sprintf("[%s-%d]", tag, t.counter[tag])
	}
	t.used[token] = true

	entry := &TokenEntry{
		Original:    value,
		Replacement: token,
		Category:    finding.Category,
		RuleID:      finding.RuleID,
		Count:       1,
	}
	t.byValue[value] = entry
	return token
}

// Entries returns all recorded value→token mappings, keyed by replacement token.
func (t *TokenizeReplacer) Entries() map[string]*TokenEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]*TokenEntry, len(t.byValue))
	for _, e := range t.byValue {
		// Deep-copy so callers cannot mutate or race with internal entries
		// after the mutex is released.
		cp := *e
		out[cp.Replacement] = &cp
	}
	return out
}

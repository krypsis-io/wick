package redact

import (
	"fmt"
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
}

// NewTokenizeReplacer creates a TokenizeReplacer ready for use.
func NewTokenizeReplacer() *TokenizeReplacer {
	return &TokenizeReplacer{
		byValue: make(map[string]*TokenEntry),
		counter: make(map[string]int),
	}
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
	t.counter[tag]++
	token := fmt.Sprintf("[%s-%d]", tag, t.counter[tag])

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
		out[e.Replacement] = e
	}
	return out
}

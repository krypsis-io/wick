package redact

import (
	"strings"
	"testing"

	"github.com/krypsis-io/wick/detect"
)

func TestTokenizeReplacer_Format(t *testing.T) {
	tr := NewTokenizeReplacer()
	f := detect.Finding{Category: "pii", RuleID: "email"}
	result := tr.Replace("admin@acme.com", f)

	if !strings.HasPrefix(result, "[EMAIL-") {
		t.Errorf("expected [EMAIL-N] format, got %q", result)
	}
	if !strings.HasSuffix(result, "]") {
		t.Errorf("expected closing ], got %q", result)
	}
}

func TestTokenizeReplacer_SameValueSameToken(t *testing.T) {
	tr := NewTokenizeReplacer()
	f := detect.Finding{Category: "pii", RuleID: "email"}
	a := tr.Replace("admin@acme.com", f)
	b := tr.Replace("admin@acme.com", f)
	if a != b {
		t.Errorf("same value should produce same token: %q != %q", a, b)
	}
}

func TestTokenizeReplacer_DifferentValuesDifferentTokens(t *testing.T) {
	tr := NewTokenizeReplacer()
	f := detect.Finding{Category: "pii", RuleID: "email"}
	a := tr.Replace("admin@acme.com", f)
	b := tr.Replace("other@acme.com", f)
	if a == b {
		t.Errorf("different values should get different tokens, both got %q", a)
	}
}

func TestTokenizeReplacer_CountIncrement(t *testing.T) {
	tr := NewTokenizeReplacer()
	f := detect.Finding{Category: "pii", RuleID: "email"}
	tr.Replace("admin@acme.com", f)
	tr.Replace("admin@acme.com", f)
	tr.Replace("admin@acme.com", f)

	entries := tr.Entries()
	for _, e := range entries {
		if e.Original == "admin@acme.com" && e.Count != 3 {
			t.Errorf("expected count 3, got %d", e.Count)
		}
	}
}

func TestTokenizeReplacer_Entries(t *testing.T) {
	tr := NewTokenizeReplacer()
	tr.Replace("admin@acme.com", detect.Finding{Category: "pii", RuleID: "email"})
	tr.Replace("10.0.1.42", detect.Finding{Category: "pii", RuleID: "ipv4"})

	entries := tr.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Entries are keyed by replacement token.
	found := 0
	for _, e := range entries {
		if e.Original == "admin@acme.com" || e.Original == "10.0.1.42" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("expected both originals in entries, got %d", found)
	}
}

func TestTokenizeReplacer_TokenCountersPerRuleID(t *testing.T) {
	tr := NewTokenizeReplacer()
	e1 := tr.Replace("admin@acme.com", detect.Finding{RuleID: "email"})
	e2 := tr.Replace("other@acme.com", detect.Finding{RuleID: "email"})
	ip := tr.Replace("10.0.1.42", detect.Finding{RuleID: "ipv4"})

	if e1 != "[EMAIL-1]" {
		t.Errorf("expected [EMAIL-1], got %q", e1)
	}
	if e2 != "[EMAIL-2]" {
		t.Errorf("expected [EMAIL-2], got %q", e2)
	}
	if ip != "[IPV4-1]" {
		t.Errorf("expected [IPV4-1], got %q", ip)
	}
}

func TestNewTokenizeReplacerFrom(t *testing.T) {
	email := detect.Finding{Category: "pii", RuleID: "email"}
	first := NewTokenizeReplacer()
	a := first.Replace("a@acme.com", email)
	b := first.Replace("b@acme.com", email)

	tr := NewTokenizeReplacerFrom(first.Entries())
	if got := tr.Replace("b@acme.com", email); got != b {
		t.Errorf("known value: got %q, want %q", got, b)
	}
	if got := tr.Replace("c@acme.com", email); got != "[EMAIL-3]" {
		t.Errorf("new value: got %q, want [EMAIL-3]", got)
	}
	entries := tr.Entries()
	if len(entries) != 3 || entries[a] == nil || entries[a].Original != "a@acme.com" {
		t.Errorf("entries do not keep the earlier values: %v", entries)
	}
}

func TestNewTokenizeReplacerFrom_TokenInUse(t *testing.T) {
	// A token that does not follow the [TAG-N] form must not be assigned
	// again to a different value.
	tr := NewTokenizeReplacerFrom(map[string]*TokenEntry{
		"[EMAIL-1]": {Original: "a@acme.com", Replacement: "[EMAIL-1]", RuleID: "Email"},
		"[EMAIL-2]": {Original: "b@acme.com", Replacement: "[EMAIL-2]", RuleID: "custom"},
	})
	got := tr.Replace("c@acme.com", detect.Finding{Category: "pii", RuleID: "email"})
	if got == "[EMAIL-1]" || got == "[EMAIL-2]" {
		t.Errorf("new value got a token that is in use: %q", got)
	}
}

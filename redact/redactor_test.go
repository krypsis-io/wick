package redact

import (
	"testing"

	"github.com/krypsis-io/wick/detect"
)

func TestRedact_SingleFinding(t *testing.T) {
	line := "key=AKIAZ5GMHYJKLMNOPQRS done"
	findings := []detect.Finding{
		{Start: 4, End: 24, Category: "secret", RuleID: "aws"},
	}
	got := Redact(line, findings, Redacted)
	want := "key=[REDACTED] done"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedact_Stars(t *testing.T) {
	line := "email: admin@acme.com"
	findings := []detect.Finding{
		{Start: 7, End: 21, Category: "pii", RuleID: "email"},
	}
	got := Redact(line, findings, Stars)
	want := "email: ***"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedact_Overlapping(t *testing.T) {
	line := "ABCDEFGHIJ"
	findings := []detect.Finding{
		{Start: 2, End: 6},
		{Start: 4, End: 8},
	}
	got := Redact(line, findings, Redacted)
	want := "AB[REDACTED]IJ"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ruleReplacer renders each finding as a token derived from its RuleID so tests
// can assert which finding's replacement was applied.
type ruleReplacer struct{}

func (ruleReplacer) Replace(_ string, f detect.Finding) string {
	return "<" + f.RuleID + ">"
}

func TestRedact_Adjacent(t *testing.T) {
	line := "ABCDEFGHIJ"
	// Half-open ranges that merely touch (end == next start) are not overlapping
	// and must each keep their own replacement.
	findings := []detect.Finding{
		{Start: 2, End: 4, RuleID: "first"},
		{Start: 4, End: 6, RuleID: "second"},
	}
	got := Redact(line, findings, ruleReplacer{})
	want := "AB<first><second>GHIJ"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedact_EqualStartDeterministic(t *testing.T) {
	line := "ABCDEFGHIJ"
	// Two findings begin at the same offset; the longer one takes precedence,
	// and the result must not depend on the findings' input order.
	a := detect.Finding{Start: 2, End: 4, RuleID: "short"}
	b := detect.Finding{Start: 2, End: 6, RuleID: "long"}
	want := "AB<long>GHIJ"
	if got := Redact(line, []detect.Finding{a, b}, ruleReplacer{}); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := Redact(line, []detect.Finding{b, a}, ruleReplacer{}); got != want {
		t.Errorf("order-dependent result: got %q, want %q", got, want)
	}
}

func TestRedact_NoFindings(t *testing.T) {
	line := "nothing here"
	got := Redact(line, nil, Redacted)
	if got != line {
		t.Errorf("got %q, want %q", got, line)
	}
}

func TestRedact_CustomStyle(t *testing.T) {
	replacer := Custom("XXXXX")
	line := "secret=mysecret"
	findings := []detect.Finding{
		{Start: 7, End: 15},
	}
	got := Redact(line, findings, replacer)
	want := "secret=XXXXX"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

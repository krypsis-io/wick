package redact

import (
	"testing"

	"github.com/krypsis-io/wick/internal/detect"
)

func TestRedact_SingleFinding(t *testing.T) {
	line := "key=AKIAZ5GMHYJKLMNOPQRS done"
	findings := []detect.Finding{
		{Start: 4, End: 24, Category: "secret", RuleID: "aws"},
	}
	got := Redact(line, findings, StyleRedacted)
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
	got := Redact(line, findings, StyleStars)
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
	got := Redact(line, findings, StyleRedacted)
	want := "AB[REDACTED]IJ"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedact_NoFindings(t *testing.T) {
	line := "nothing here"
	got := Redact(line, nil, StyleRedacted)
	if got != line {
		t.Errorf("got %q, want %q", got, line)
	}
}

func TestRedact_CustomStyle(t *testing.T) {
	SetCustomReplacement("XXXXX")
	line := "secret=mysecret"
	findings := []detect.Finding{
		{Start: 7, End: 15},
	}
	got := Redact(line, findings, CustomStyle())
	want := "secret=XXXXX"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

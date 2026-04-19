package redact

import (
	"testing"

	"github.com/krypsis-io/wick/detect"
)

func TestPerRule_Override(t *testing.T) {
	overrides := map[string]string{
		"internal-code": "[INTERNAL]",
	}
	r := PerRule(Redacted, overrides)
	f := detect.Finding{RuleID: "internal-code"}
	got := r.Replace("ACME-1234", f)
	if got != "[INTERNAL]" {
		t.Errorf("expected [INTERNAL], got %q", got)
	}
}

func TestPerRule_FallsBackToBase(t *testing.T) {
	overrides := map[string]string{
		"internal-code": "[INTERNAL]",
	}
	r := PerRule(Stars, overrides)
	f := detect.Finding{RuleID: "email"}
	got := r.Replace("admin@acme.com", f)
	if got != "***" {
		t.Errorf("expected fallback ***, got %q", got)
	}
}

func TestPerRule_EmptyOverrides(t *testing.T) {
	r := PerRule(Redacted, nil)
	f := detect.Finding{RuleID: "email"}
	got := r.Replace("admin@acme.com", f)
	if got != "[REDACTED]" {
		t.Errorf("expected [REDACTED], got %q", got)
	}
}

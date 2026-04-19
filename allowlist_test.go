package wick

import (
	"strings"
	"testing"

	"github.com/krypsis-io/wick/detect"
)

func TestWithAllowlist_SuppressesValue(t *testing.T) {
	input := "Contact admin@acme.com for help"
	output, report, err := Redact(input, WithAllowlist([]detect.AllowlistEntry{
		{Pattern: "admin@acme.com", Reason: "test fixture"},
	}))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(output, "[REDACTED]") {
		t.Errorf("allowlisted value should not be redacted: %s", output)
	}
	if output != input {
		t.Errorf("output should equal input when all findings are allowlisted: %s", output)
	}
	if report.Total != 0 {
		t.Errorf("expected 0 findings, got %d", report.Total)
	}
}

func TestWithAllowlist_Regex(t *testing.T) {
	input := "Email: test@fixture.com"
	output, _, err := Redact(input, WithAllowlist([]detect.AllowlistEntry{
		{Pattern: `test@.*\.com`, Regex: true},
	}))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(output, "[REDACTED]") {
		t.Errorf("regex-allowlisted value should not be redacted: %s", output)
	}
}

func TestWithAllowlist_OnlyAllowlistedSuppressed(t *testing.T) {
	input := "safe@example.com and danger@corp.com both here"
	_, report, err := Redact(input, WithAllowlist([]detect.AllowlistEntry{
		{Pattern: "safe@example.com"},
	}))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	for _, f := range report.Findings {
		if f.Value == "safe@example.com" {
			t.Errorf("safe@example.com should be suppressed by allowlist")
		}
	}
	found := false
	for _, f := range report.Findings {
		if f.Value == "danger@corp.com" {
			found = true
		}
	}
	if !found {
		t.Error("danger@corp.com should still be detected")
	}
}

func TestWithBlocklist_AlwaysRedacts(t *testing.T) {
	// Custom value not in any built-in rule.
	input := "Project code: ACME-INTERNAL-ABC123"
	output, report, err := Redact(input, WithBlocklist([]detect.CustomPattern{
		{Name: "internal-code", Regex: `ACME-INTERNAL-[A-Z0-9]+`},
	}))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(output, "ACME-INTERNAL-ABC123") {
		t.Errorf("blocklisted value should be redacted: %s", output)
	}
	if report.Total == 0 {
		t.Error("expected at least 1 finding from blocklist")
	}
}

func TestWithBlocklist_CombinedWithBuiltins(t *testing.T) {
	// Blocklist adds to built-in detection, not replaces it.
	input := "Email: admin@acme.com, Code: ACME-INTERNAL-XYZ"
	output, report, err := Redact(input, WithBlocklist([]detect.CustomPattern{
		{Name: "internal-code", Regex: `ACME-INTERNAL-[A-Z]+`},
	}))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(output, "admin@acme.com") {
		t.Errorf("email should still be detected: %s", output)
	}
	if strings.Contains(output, "ACME-INTERNAL-XYZ") {
		t.Errorf("blocklisted value should be redacted: %s", output)
	}
	if report.Total < 2 {
		t.Errorf("expected at least 2 findings, got %d", report.Total)
	}
}

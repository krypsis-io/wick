package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDisableRules(t *testing.T) {
	d, _ := New()

	// Email should be detected before disabling.
	findings := d.Detect("admin@acme.com")
	found := false
	for _, f := range findings {
		if f.RuleID == "email" {
			found = true
		}
	}
	if !found {
		t.Fatal("email should be detected before disabling")
	}

	// Disable PII email rule.
	d.DisableRules([]string{"email"})
	findings = d.Detect("admin@acme.com")
	for _, f := range findings {
		if f.RuleID == "email" {
			t.Errorf("email rule should be disabled, got finding: %+v", f)
		}
	}
}

func TestDisableRules_UnknownID(t *testing.T) {
	d, _ := New()
	// Should not panic on unknown rule IDs.
	d.DisableRules([]string{"nonexistent-rule-id"})
}

func TestDisableRules_Empty(t *testing.T) {
	d, _ := New()
	d.DisableRules(nil)
	// Should still detect normally.
	findings := d.Detect("admin@acme.com")
	found := false
	for _, f := range findings {
		if f.RuleID == "email" {
			found = true
		}
	}
	if !found {
		t.Error("empty disable list should not affect detection")
	}
}

func TestAddRulesFile(t *testing.T) {
	toml := `
title = "test rules"

[[rules]]
id = "test-custom-token"
description = "Test custom token"
regex = '''TEST-[A-Z0-9]{8}'''
keywords = ["test"]
`
	tmp := filepath.Join(t.TempDir(), "rules.toml")
	if err := os.WriteFile(tmp, []byte(toml), 0o600); err != nil {
		t.Fatalf("write temp rules: %v", err)
	}

	d, _ := New()
	if err := d.AddRulesFile(tmp); err != nil {
		t.Fatalf("AddRulesFile: %v", err)
	}

	findings := d.Detect("token: TEST-ABCD1234")
	found := false
	for _, f := range findings {
		if f.RuleID == "test-custom-token" {
			found = true
		}
	}
	if !found {
		t.Errorf("custom rule from file not matched, findings: %+v", findings)
	}
}

func TestAddRulesFile_Missing(t *testing.T) {
	d, _ := New()
	if err := d.AddRulesFile("/nonexistent/path.toml"); err == nil {
		t.Error("expected error for missing rules file")
	}
}

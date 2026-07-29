package detect

import (
	"testing"
)

func TestAllowlist_ExactMatch(t *testing.T) {
	d, _ := New()
	_ = d.SetAllowlist([]AllowlistEntry{
		{Pattern: "admin@acme.com", Reason: "test fixture"},
	})

	findings := d.Detect("Contact admin@acme.com for help")
	for _, f := range findings {
		if f.Value == "admin@acme.com" {
			t.Errorf("allowlisted value should be suppressed, got finding: %+v", f)
		}
	}
}

func TestAllowlist_ExactMatch_CaseInsensitive(t *testing.T) {
	d, _ := New()
	_ = d.SetAllowlist([]AllowlistEntry{
		{Pattern: "Admin@Acme.Com"},
	})

	findings := d.Detect("Contact admin@acme.com for help")
	for _, f := range findings {
		if f.Value == "admin@acme.com" {
			t.Errorf("case-insensitive allowlist should suppress finding: %+v", f)
		}
	}
}

func TestAllowlist_RegexMatch(t *testing.T) {
	d, _ := New()
	_ = d.SetAllowlist([]AllowlistEntry{
		{Pattern: `test@.*\.com`, Regex: true, Reason: "test emails"},
	})

	findings := d.Detect("Email: test@example.com")
	for _, f := range findings {
		if f.RuleID == "email" {
			t.Errorf("regex-allowlisted email should be suppressed: %+v", f)
		}
	}
}

func TestAllowlist_DoesNotSuppressOthers(t *testing.T) {
	d, _ := New()
	_ = d.SetAllowlist([]AllowlistEntry{
		{Pattern: "safe@example.com"},
	})

	findings := d.Detect("safe@example.com and admin@acme.com both appear")
	foundSafe, foundOther := false, false
	for _, f := range findings {
		if f.Value == "safe@example.com" {
			foundSafe = true
		}
		if f.Value == "admin@acme.com" {
			foundOther = true
		}
	}
	if foundSafe {
		t.Error("safe@example.com should be allowlisted and suppressed")
	}
	if !foundOther {
		t.Error("admin@acme.com should still be detected")
	}
}

func TestAllowlist_InvalidRegex(t *testing.T) {
	d, _ := New()
	err := d.SetAllowlist([]AllowlistEntry{
		{Pattern: `[invalid`, Regex: true},
	})
	if err == nil {
		t.Error("expected error for invalid regex in allowlist")
	}
}

func TestAllowlist_Empty(t *testing.T) {
	d, _ := New()
	_ = d.SetAllowlist(nil)

	// Should still detect normally.
	findings := d.Detect("admin@acme.com")
	found := false
	for _, f := range findings {
		if f.RuleID == "email" {
			found = true
		}
	}
	if !found {
		t.Error("empty allowlist should not suppress normal detection")
	}
}

func TestAllowlist_AWSExampleKey(t *testing.T) {
	// Common preset: suppress the AWS documentation example key.
	d, _ := New()
	_ = d.SetAllowlist([]AllowlistEntry{
		{Pattern: "AKIAIOSFODNN7EXAMPLE", Reason: "AWS docs example"},
	})

	findings := d.Detect("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	for _, f := range findings {
		if f.Value == "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("AWS example key should be allowlisted: %+v", f)
		}
	}
}

package detect

import (
	"testing"
)

func TestDetector_Secrets(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	input := `AWS_ACCESS_KEY_ID=AKIAZ5GMHYJKLMNOPQRS`
	findings := d.Detect(input)

	found := false
	for _, f := range findings {
		if f.Category == "secret" && f.Value == "AKIAZ5GMHYJKLMNOPQRS" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find AWS access key, got findings: %+v", findings)
	}
}

func TestDetector_PII_Email(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	input := `Contact admin@acme.com for help`
	findings := d.Detect(input)

	found := false
	for _, f := range findings {
		if f.RuleID == "email" && f.Value == "admin@acme.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find email, got findings: %+v", findings)
	}
}

func TestDetector_PII_IPv4(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	input := `Server at 10.0.1.42 is down`
	findings := d.Detect(input)

	found := false
	for _, f := range findings {
		if f.RuleID == "ipv4" && f.Value == "10.0.1.42" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find IPv4, got findings: %+v", findings)
	}
}

func TestDetector_PII_SSN(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	input := `SSN: 123-45-6789`
	findings := d.Detect(input)

	found := false
	for _, f := range findings {
		if f.RuleID == "us-ssn" && f.Value == "123-45-6789" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find SSN, got findings: %+v", findings)
	}
}

func TestDetector_CustomPattern(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	if err := d.SetCustomPatterns([]CustomPattern{
		{Name: "internal-code", Regex: `ACME-\d{4}`},
	}); err != nil {
		t.Fatalf("failed to set custom patterns: %v", err)
	}

	input := `Project ACME-1234 is active`
	findings := d.Detect(input)

	found := false
	for _, f := range findings {
		if f.RuleID == "internal-code" && f.Value == "ACME-1234" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find custom pattern, got findings: %+v", findings)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		minBits float64
		maxBits float64
	}{
		{"aaaa", 0, 0.1},
		{"abcd", 1.9, 2.1},
		{"AKIAIOSFODNN7EXAMPLE", 3.5, 4.5},
	}
	for _, tt := range tests {
		e := shannonEntropy(tt.input)
		if e < tt.minBits || e > tt.maxBits {
			t.Errorf("shannonEntropy(%q) = %f, want [%f, %f]", tt.input, e, tt.minBits, tt.maxBits)
		}
	}
}

package redact

import (
	"strings"
	"testing"

	"github.com/krypsis-io/wick/detect"
)

func TestHashReplacer_Format(t *testing.T) {
	f := detect.Finding{Category: "pii", RuleID: "email", Value: "admin@acme.com"}
	result := Hash.Replace("admin@acme.com", f)

	if !strings.HasPrefix(result, "[EMAIL:") {
		t.Errorf("expected [EMAIL:...] format, got %q", result)
	}
	if !strings.HasSuffix(result, "]") {
		t.Errorf("expected closing ], got %q", result)
	}
	// Tag should be uppercase RuleID, hash should be 8 hex chars.
	// Format: [EMAIL:a1b2c3d4]
	inner := result[1 : len(result)-1] // strip [ and ]
	parts := strings.SplitN(inner, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("expected TAG:HASH format, got %q", inner)
	}
	if parts[0] != "EMAIL" {
		t.Errorf("expected tag EMAIL, got %q", parts[0])
	}
	if len(parts[1]) != 8 {
		t.Errorf("expected 8-char hash, got %q (len %d)", parts[1], len(parts[1]))
	}
}

func TestHashReplacer_Deterministic(t *testing.T) {
	f := detect.Finding{Category: "pii", RuleID: "email"}
	a := Hash.Replace("admin@acme.com", f)
	b := Hash.Replace("admin@acme.com", f)
	if a != b {
		t.Errorf("hash not deterministic: %q != %q", a, b)
	}
}

func TestHashReplacer_DifferentValues(t *testing.T) {
	f := detect.Finding{Category: "pii", RuleID: "email"}
	a := Hash.Replace("admin@acme.com", f)
	b := Hash.Replace("other@acme.com", f)
	if a == b {
		t.Errorf("different values produced same hash: %q", a)
	}
}

func TestHashReplacer_RuleIDInTag(t *testing.T) {
	tests := []struct {
		ruleID  string
		wantTag string
	}{
		{"email", "EMAIL"},
		{"ipv4", "IPV4"},
		{"us-ssn", "US-SSN"},
		{"aws-access-token", "AWS-ACCESS-TOKEN"},
	}
	for _, tt := range tests {
		f := detect.Finding{RuleID: tt.ruleID}
		result := Hash.Replace("somevalue", f)
		if !strings.HasPrefix(result, "["+tt.wantTag+":") {
			t.Errorf("ruleID %q: expected tag %q, got %q", tt.ruleID, tt.wantTag, result)
		}
	}
}

func TestHashReplacer_OneWay(t *testing.T) {
	// Just verifies the output does not contain the original value.
	f := detect.Finding{RuleID: "email"}
	value := "supersecret@example.com"
	result := Hash.Replace(value, f)
	if strings.Contains(result, value) {
		t.Errorf("hash output should not contain original value: %q", result)
	}
}

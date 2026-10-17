package output

import (
	"strings"
	"testing"

	"github.com/krypsis-io/wick/detect"
)

func TestReport_Empty(t *testing.T) {
	var buf strings.Builder
	Report(&buf, nil, false)
	if buf.String() != "" {
		t.Errorf("expected no output for empty findings, got %q", buf.String())
	}
}

func TestReport_SingleFinding(t *testing.T) {
	findings := []detect.Finding{
		{Category: "pii", RuleID: "email", Value: "admin@acme.com", Line: 3, Start: 9},
	}
	var buf strings.Builder
	Report(&buf, findings, true)
	out := buf.String()

	if !strings.Contains(out, "1 finding") {
		t.Errorf("expected finding count in output: %q", out)
	}
	if !strings.Contains(out, "line 3") {
		t.Errorf("expected line number in output: %q", out)
	}
	if !strings.Contains(out, "col 10") { // Start+1
		t.Errorf("expected 1-based column in output: %q", out)
	}
	if !strings.Contains(out, "pii") {
		t.Errorf("expected category in output: %q", out)
	}
	if !strings.Contains(out, "email") {
		t.Errorf("expected rule ID in output: %q", out)
	}
	if !strings.Contains(out, "admin@acme.com") {
		t.Errorf("expected value in output: %q", out)
	}
}

func TestReport_MasksValuesByDefault(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"ghp_SXI2fQZCMY2w4YJLj0ajZIZXb2Poe4nS53gb", "ghp_…53gb (40 chars)"},
		{"hunter2horse", "hu… (12 chars)"},
		{"s3cret!", "… (7 chars)"},
	}
	for _, tt := range tests {
		var buf strings.Builder
		Report(&buf, []detect.Finding{{Category: "secret", RuleID: "r", Value: tt.value, Line: 1}}, false)
		out := buf.String()
		if strings.Contains(out, tt.value) {
			t.Errorf("masked report leaked raw value %q: %q", tt.value, out)
		}
		if !strings.Contains(out, tt.want) {
			t.Errorf("expected masked preview %q in output: %q", tt.want, out)
		}
	}
}

func TestReport_MultipleFindings(t *testing.T) {
	findings := []detect.Finding{
		{Category: "pii", RuleID: "email", Value: "admin@acme.com", Line: 1, Start: 0},
		{Category: "secret", RuleID: "aws-access-token", Value: "AKIAZ5GMHYJKLMNOPQRS", Line: 2, Start: 4},
	}
	var buf strings.Builder
	Report(&buf, findings, true)
	out := buf.String()

	if !strings.Contains(out, "2 finding") {
		t.Errorf("expected 2 findings in header: %q", out)
	}
	if !strings.Contains(out, "email") || !strings.Contains(out, "aws-access-token") {
		t.Errorf("expected both rule IDs: %q", out)
	}
}

func TestReport_ValueTruncation(t *testing.T) {
	long := strings.Repeat("a", 50)
	findings := []detect.Finding{
		{Category: "custom", RuleID: "test", Value: long, Line: 1, Start: 0},
	}
	var buf strings.Builder
	Report(&buf, findings, true)
	out := buf.String()

	if strings.Contains(out, long) {
		t.Errorf("long value should be truncated: %q", out)
	}
	if !strings.Contains(out, "...") {
		t.Errorf("truncated value should end with ...: %q", out)
	}
}

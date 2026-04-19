package wick

import (
	"strings"
	"testing"

	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

func TestRedact_Basic(t *testing.T) {
	input := "Contact admin@acme.com from 10.0.1.42"
	output, report, err := Redact(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(output, "admin@acme.com") {
		t.Errorf("email should be redacted: %s", output)
	}
	if strings.Contains(output, "10.0.1.42") {
		t.Errorf("IP should be redacted: %s", output)
	}
	if report.Total < 2 {
		t.Errorf("expected at least 2 findings, got %d", report.Total)
	}
}

func TestRedact_WithReplacer(t *testing.T) {
	input := "key=AKIAZ5GMHYJKLMNOPQRS"
	output, _, err := Redact(input, WithReplacer(redact.Stars))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "***") {
		t.Errorf("expected stars replacement: %s", output)
	}
}

func TestRedact_WithCustomPatterns(t *testing.T) {
	input := "Project ACME-1234 is active"
	output, report, err := Redact(input, WithCustomPatterns([]detect.CustomPattern{
		{Name: "internal-code", Regex: `ACME-\d{4}`},
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(output, "ACME-1234") {
		t.Errorf("custom pattern should be redacted: %s", output)
	}
	if report.ByRule["internal-code"] != 1 {
		t.Errorf("expected 1 internal-code finding, got %d", report.ByRule["internal-code"])
	}
}

func TestRedact_JSON(t *testing.T) {
	input := `{"api_key": "AKIAZ5GMHYJKLMNOPQRS", "name": "test"}`
	output, report, err := Redact(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Total == 0 {
		t.Fatal("expected findings")
	}
	if strings.Contains(output, "AKIAZ5GMHYJKLMNOPQRS") {
		t.Errorf("secret should be redacted: %s", output)
	}
}

func TestRedact_NoFindings(t *testing.T) {
	input := "nothing sensitive here"
	output, report, err := Redact(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != input {
		t.Errorf("output should be unchanged: %s", output)
	}
	if report.Total != 0 {
		t.Errorf("expected 0 findings, got %d", report.Total)
	}
}

func TestRedact_ConcurrentSafety(t *testing.T) {
	input := "Contact admin@acme.com"
	errs := make(chan error, 10)
	for range 10 {
		go func() {
			_, _, err := Redact(input)
			errs <- err
		}()
	}
	for range 10 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Redact failed: %v", err)
		}
	}
}

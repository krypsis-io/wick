package format

import (
	"strings"
	"testing"

	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

func newDetector(t *testing.T) *detect.Detector {
	t.Helper()
	d, err := detect.New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}
	return d
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Format
	}{
		{"json object", `{"key": "value"}`, FormatJSON},
		{"json array", `[1, 2, 3]`, FormatJSON},
		{"env", "API_KEY=secret\nDB_HOST=localhost", FormatEnv},
		{"yaml", "name: test\nversion: 1", FormatYAML},
		{"plain", "just some text", FormatPlain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != tt.want {
				t.Errorf("Detect() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProcessJSON(t *testing.T) {
	d := newDetector(t)
	input := `{"api_key": "AKIAZ5GMHYJKLMNOPQRS", "name": "test"}`
	output, findings := ProcessJSON(input, d, redact.Redacted)

	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected redaction in output: %s", output)
	}
	if !strings.Contains(output, `"name"`) {
		t.Errorf("expected name key preserved: %s", output)
	}
	if strings.Contains(output, "AKIAZ5GMHYJKLMNOPQRS") {
		t.Errorf("secret should be redacted: %s", output)
	}
}

func TestProcessEnv(t *testing.T) {
	d := newDetector(t)
	input := "# Config\nAPI_KEY=AKIAZ5GMHYJKLMNOPQRS\nDB_NAME=mydb"
	output, findings := ProcessEnv(input, d, redact.Redacted)

	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if !strings.Contains(output, "API_KEY=[REDACTED]") {
		t.Errorf("expected API_KEY redacted: %s", output)
	}
	if !strings.Contains(output, "DB_NAME=mydb") {
		t.Errorf("expected DB_NAME preserved: %s", output)
	}
	if !strings.Contains(output, "# Config") {
		t.Errorf("expected comment preserved: %s", output)
	}
}

func TestProcessPlain(t *testing.T) {
	d := newDetector(t)
	input := "Contact admin@acme.com from 10.0.1.42"
	output, findings := ProcessPlain(input, d, redact.Redacted)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	if strings.Contains(output, "admin@acme.com") {
		t.Errorf("email should be redacted: %s", output)
	}
	if strings.Contains(output, "10.0.1.42") {
		t.Errorf("IP should be redacted: %s", output)
	}
}

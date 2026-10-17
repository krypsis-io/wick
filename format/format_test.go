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
		{"pem is not yaml", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", FormatPlain},
		{"yaml document marker", "---\nname: test", FormatYAML},
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

func TestProcessJSON_KeyedSecret(t *testing.T) {
	// The aws-secret-access-key rule is keyword-anchored: the key name must be
	// adjacent to the value. In JSON the name is the mapping key, so detection
	// must use the key as context.
	d := newDetector(t)
	input := `{"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzzzzzzzAB"}`
	output, findings := ProcessJSON(input, d, redact.Redacted)

	if len(findings) == 0 {
		t.Fatal("expected the keyed AWS secret to be detected")
	}
	if strings.Contains(output, "wJalrXUtnFEMI") {
		t.Errorf("secret should be redacted: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected value replaced with [REDACTED]: %s", output)
	}
	if !strings.Contains(output, `"aws_secret_access_key"`) {
		t.Errorf("expected key preserved: %s", output)
	}
}

func TestProcessYAML_KeyedSecret(t *testing.T) {
	d := newDetector(t)
	input := "config:\n  aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzzzzzzzAB\n  name: prod\n"
	output, findings := ProcessYAML(input, d, redact.Redacted)

	if len(findings) == 0 {
		t.Fatal("expected the keyed AWS secret to be detected")
	}
	if strings.Contains(output, "wJalrXUtnFEMI") {
		t.Errorf("secret should be redacted: %s", output)
	}
	if !strings.Contains(output, "aws_secret_access_key:") {
		t.Errorf("expected key preserved: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected value replaced with [REDACTED]: %s", output)
	}
	if !strings.Contains(output, "name: prod") {
		t.Errorf("expected other keys preserved: %s", output)
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

// Portainer, Kubernetes and ECS put the secret's name in a sibling field. The
// value must be redacted even when it would fail entropy checks on its own,
// and non-secret pairs must be left alone.
func TestProcessJSON_NameValuePairs(t *testing.T) {
	d := newDetector(t)
	input := `{"env":[{"name":"FINNHUB_KEY","value":"6320eaa997719c91"},{"name":"POSTGRES_PASSWORD","value":"hunter2horse"},{"name":"LOG_LEVEL","value":"debugging"}]}`
	out, findings := ProcessJSON(input, d, redact.Redacted)
	for _, leaked := range []string{"6320eaa997719c91", "hunter2horse"} {
		if strings.Contains(out, leaked) {
			t.Errorf("secret %q not redacted: %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"value":"debugging"`) {
		t.Errorf("non-secret pair should be untouched: %s", out)
	}
	if !strings.Contains(out, `"name":"FINNHUB_KEY"`) {
		t.Errorf("names must not be redacted: %s", out)
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (one per secret), got %d: %+v", len(findings), findings)
	}
}

func TestProcessYAML_NameValuePairs(t *testing.T) {
	d := newDetector(t)
	input := "env:\n  - name: GITEA_TOKEN\n    value: 9f8e7d6c5b4a3928\n  - name: DB_PASSWORD\n    value: hunter2horse\n  - name: LOG_LEVEL\n    value: debug\n"
	out, _ := ProcessYAML(input, d, redact.Redacted)
	for _, leaked := range []string{"9f8e7d6c5b4a3928", "hunter2horse"} {
		if strings.Contains(out, leaked) {
			t.Errorf("secret %q not redacted: %s", leaked, out)
		}
	}
	if !strings.Contains(out, "value: debug") {
		t.Errorf("non-secret pair should be untouched: %s", out)
	}
}

// A passphrase with spaces must be redacted whole: the parser strips quotes,
// so a bare key=value context alone would capture only the first word.
func TestProcessStructured_PassphraseWithSpaces(t *testing.T) {
	d := newDetector(t)
	tests := []struct {
		name string
		run  func(string, *detect.Detector, redact.Replacer) (string, []detect.Finding)
		in   string
	}{
		{"json pair", ProcessJSON, `{"name":"DB_PASSWORD","value":"correct horse battery"}`},
		{"json key", ProcessJSON, `{"db_password":"correct horse battery"}`},
		{"yaml key", ProcessYAML, "password: correct horse battery\nuser: x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, findings := tt.run(tt.in, d, redact.Redacted)
			if strings.Contains(out, "horse") || strings.Contains(out, "battery") {
				t.Errorf("passphrase partially leaked: %s", out)
			}
			if len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d: %+v", len(findings), findings)
			}
		})
	}
}

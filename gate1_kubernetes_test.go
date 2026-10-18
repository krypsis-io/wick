package wick_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/krypsis-io/wick"
)

// fakePEM returns a PEM-shaped private key block with a random body, plus the
// body lines, so tests never carry a real or fixed key.
func fakePEM(t *testing.T) (string, []string) {
	t.Helper()
	body := make([]string, 5)
	for i := range body {
		body[i] = randAlnum(t, 64)
	}
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----"
	return pem, body
}

// TestKubernetesArtifacts covers the leaks found by the Gate 1 kind-cluster
// test: a private key stored as a value in pod YAML / JSON (including the
// escaped JSON in kubectl's last-applied-configuration annotation), and
// column-aligned env values in `kubectl describe`. Diagnostic context such as
// the database host must survive.
func TestKubernetesArtifacts(t *testing.T) {
	pem, body := fakePEM(t)
	apiKey := randAlnum(t, 32)
	dbPass := randAlnum(t, 20)
	const diag = "postgres.payments.svc.cluster.local"

	env := []map[string]string{
		{"name": "TLS_PRIVATE_KEY", "value": pem},
		{"name": "DB_HOST", "value": diag},
	}
	podJSON, err := json.MarshalIndent(map[string]any{
		"kind": "Pod",
		"spec": map[string]any{"containers": []any{map[string]any{"name": "ledger-api", "env": env}}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	annotated, err := json.MarshalIndent(map[string]any{
		"kind": "Deployment",
		"metadata": map[string]any{"annotations": map[string]string{
			"kubectl.kubernetes.io/last-applied-configuration": string(podJSON),
		}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	indented := "        " + strings.ReplaceAll(pem, "\n", "\n        ")
	podYAML := "kind: Pod\nspec:\n  containers:\n  - name: ledger-api\n    env:\n" +
		"    - name: TLS_PRIVATE_KEY\n      value: |\n" + indented + "\n" +
		"    - name: DB_HOST\n      value: " + diag + "\n"
	describe := "Containers:\n  ledger-api:\n    Image:  busybox:1.36.1\n    Environment:\n" +
		"      GENERIC_API_KEY:       " + apiKey + "\n" +
		"      DB_PASSWORD:           " + dbPass + "\n" +
		"      DB_HOST:               " + diag + "\n" +
		// Real describe output is not valid YAML (event messages contain
		// ": " inside plain scalars), so wick processes it as plain text.
		"Events:\n  Type     Reason   Age  From     Message\n" +
		"  Warning  BackOff  1m   kubelet  Back-off restarting failed container ledger-api: exit code 1\n"

	cases := []struct {
		name    string
		input   string
		secrets []string
	}{
		{"pod json env value", string(podJSON), body},
		{"last-applied-configuration annotation", string(annotated), body},
		{"pod yaml block scalar", podYAML, body},
		{"kubectl describe aligned env", describe, []string{apiKey, dbPass}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := wick.Redact(c.input)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range c.secrets {
				if strings.Contains(out, s) {
					t.Errorf("secret leaked:\n%s", out)
					break
				}
			}
			if !strings.Contains(out, diag) {
				t.Errorf("diagnostic host %q was redacted:\n%s", diag, out)
			}
		})
	}
}

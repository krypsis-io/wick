package wick_test

import (
	"encoding/base64"
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

// TestKubernetesArtifacts covers secrets in kubectl output: a private key
// stored as a value in pod YAML / JSON (including the escaped JSON in
// kubectl's last-applied-configuration annotation), and column-aligned env
// values in `kubectl describe`. Diagnostic context such as the database host
// must survive.
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

	dsn := "postgres://ledger:" + dbPass + "@" + diag + ":5432/ledger"
	appLog := "2026-10-18T04:10:01.123Z ledger-api config: log_level=debug\n" +
		"2026-10-18T04:10:03.500Z ledger-api ERROR dial " + dsn + ": ECONNREFUSED\n"
	jsonLog := `{"level":"error","msg":"db connect failed","dsn":"` + dsn + `"}` + "\n" +
		`{"level":"info","msg":"retrying"}` + "\n"

	cases := []struct {
		name    string
		input   string
		secrets []string
	}{
		{"pod json env value", string(podJSON), body},
		{"url credentials in a timestamped log", appLog, []string{dbPass}},
		{"url credentials in json lines", jsonLog, []string{dbPass}},
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

// TestKubernetesSecretPayload checks that every value in a Secret's data and
// stringData is redacted, whatever its key name or encoding, including the
// copy kubectl keeps in the last-applied-configuration annotation, while the
// rest of the object and other kinds' data stay readable.
func TestKubernetesSecretPayload(t *testing.T) {
	dsn := "postgres://ledger:" + randAlnum(t, 16) + "@db:5432/ledger"
	encoded := base64.StdEncoding.EncodeToString([]byte(dsn))
	pin := "482913"
	auth := randAlnum(t, 24)
	// The & is written as \u0026 in kubectl's JSON, the < and > likewise.
	config := `{"auth":"` + auth + `","dsn":"db?sslmode=require&x=<1>"}`
	secrets := []string{encoded, pin, auth}

	secretJSON, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": "ledger-creds"},
		"data":       map[string]string{"DATABASE_URL": encoded},
		"stringData": map[string]string{"config.json": config},
	})
	if err != nil {
		t.Fatal(err)
	}
	secretYAML := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ledger-creds\n" +
		"data:\n  DATABASE_URL: " + encoded + "\nstringData:\n  PIN: " + pin + "\n  config.json: '" + config + "'\n"
	appliedYAML := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ledger-creds\n  annotations:\n" +
		"    kubectl.kubernetes.io/last-applied-configuration: |\n      " + string(secretJSON) + "\n" +
		"data:\n  DATABASE_URL: " + encoded + "\n"
	list := `{"apiVersion":"v1","kind":"List","items":[` + string(secretJSON) + `]}`
	aliased := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ledger-creds\n  labels:\n    pin: &pin " + pin + "\n" +
		"creds: &creds\n  DATABASE_URL: " + encoded + "\n  config.json: '" + config + "'\n" +
		"data: *creds\nstringData:\n  PIN: *pin\n"

	for _, c := range []struct{ name, input string }{
		{"secret json", string(secretJSON)},
		{"secret yaml", secretYAML},
		{"last-applied-configuration", appliedYAML},
		{"list of secrets", list},
		{"values given as yaml aliases", aliased},
		{"secret after a document with a spaced key", "display name: Alice\n---\n" + secretYAML},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := wick.Redact(c.input)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Errorf("secret value %q leaked:\n%s", s, out)
				}
			}
			for _, keep := range []string{"ledger-creds", "DATABASE_URL", "config.json"} {
				if !strings.Contains(out, keep) {
					t.Errorf("%q was redacted:\n%s", keep, out)
				}
			}
		})
	}

	configMap := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ledger\ndata:\n  LOG_LEVEL: debug\n  REGION: " + encoded[:12] + "\n"
	out, _, err := wick.Redact(configMap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, encoded[:12]) {
		t.Errorf("ConfigMap data was redacted:\n%s", out)
	}
}

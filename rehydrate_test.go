package wick_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/krypsis-io/wick"
	"gopkg.in/yaml.v3"
)

// TestRehydrate_StructuredRoundTrip checks that Dehydrate followed by
// Rehydrate restores JSON and YAML documents to the same data, including
// originals that contain newlines (PEM keys) or YAML-significant characters.
// Plain token substitution would put a raw newline inside a JSON string or
// break YAML indentation.
func TestRehydrate_StructuredRoundTrip(t *testing.T) {
	pem, _ := fakePEM(t)
	pass := "s3cr3t: v@lue's #" + randAlnum(t, 8)

	podJSON, err := json.MarshalIndent(map[string]any{
		"kind": "Pod",
		"env":  []map[string]string{{"name": "TLS_PRIVATE_KEY", "value": pem}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	nested, err := json.MarshalIndent(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			"kubectl.kubernetes.io/last-applied-configuration": string(podJSON),
		}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	indented := "    " + strings.ReplaceAll(pem, "\n", "\n    ")
	blockYAML := "env:\n- name: TLS_PRIVATE_KEY\n  value: |\n" + indented + "\n- name: DB_HOST\n  value: db.internal\n"
	quotedYAML := "db:\n  host: db.internal\n  password: '" + strings.ReplaceAll(pass, "'", "''") + "'\n"

	cases := []struct {
		name   string
		input  string
		secret string
		decode func(string) (any, error)
	}{
		{"json value with newlines", string(podJSON), pem, decodeJSON},
		{"json nested in a json string", string(nested), pem, decodeJSON},
		{"yaml block scalar", blockYAML, pem, decodeYAML},
		{"yaml quoted value with special characters", quotedYAML, pass, decodeYAML},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dehydrated, tm, err := wick.Dehydrate(c.input)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(dehydrated, c.secret) {
				t.Fatalf("secret not tokenized:\n%s", dehydrated)
			}
			restored, err := wick.Rehydrate(dehydrated, tm)
			if err != nil {
				t.Fatal(err)
			}
			want, err := c.decode(c.input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.decode(restored)
			if err != nil {
				t.Fatalf("rehydrated document does not parse: %v\n%s", err, restored)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("rehydrated data differs from the original:\n%s", restored)
			}
		})
	}
}

func decodeJSON(s string) (any, error) {
	var v any
	err := json.Unmarshal([]byte(s), &v)
	return v, err
}

func decodeYAML(s string) (any, error) {
	var v any
	err := yaml.Unmarshal([]byte(s), &v)
	return v, err
}

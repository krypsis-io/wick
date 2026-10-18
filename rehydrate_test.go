package wick_test

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/krypsis-io/wick"
	"gopkg.in/yaml.v3"
)

// TestRehydrate_StructuredRoundTrip checks that rehydrated JSON and YAML parse
// to the original data when originals need escaping (newlines, quotes, ": ").
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
	multiYAML := "kind: ConfigMap\ndata:\n  host: db.internal\n---\n" + quotedYAML
	secretJSON, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"stringData": map[string]string{"config": pass + "&<x>\n" + pem},
	})
	if err != nil {
		t.Fatal(err)
	}
	secretYAML := "apiVersion: v1\nkind: Secret\nmetadata:\n  annotations:\n" +
		"    kubectl.kubernetes.io/last-applied-configuration: |\n      " + string(secretJSON) + "\n" +
		"stringData:\n  config: |\n    " + strings.ReplaceAll(pass+"&<x>\n"+pem, "\n", "\n    ") + "\n"
	unquote := func(s string) string { return regexp.MustCompile(`'(\[[A-Z0-9-]+\])'`).ReplaceAllString(s, "$1") }

	cases := []struct {
		name   string
		input  string
		secret string
		decode func(string) (any, error)
		edit   func(string) string
	}{
		{"json value with newlines", string(podJSON), pem, decodeJSON, nil},
		{"json nested in a json string", string(nested), pem, decodeJSON, nil},
		{"yaml block scalar", blockYAML, pem, decodeYAML, nil},
		{"yaml quoted value with special characters", quotedYAML, pass, decodeYAML, nil},
		{"multi-document yaml", multiYAML, pass, decodeYAML, nil},
		{"yaml token left unquoted", quotedYAML, pass, decodeYAML, unquote},
		{"kubernetes secret json", string(secretJSON), pass, decodeJSON, nil},
		{"kubernetes secret yaml with last-applied-configuration", secretYAML, pass, decodeYAML, nil},
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
			if c.edit != nil {
				dehydrated = c.edit(dehydrated)
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
	dec := yaml.NewDecoder(strings.NewReader(s))
	var docs []any
	for {
		var v any
		if err := dec.Decode(&v); errors.Is(err, io.EOF) {
			return docs, nil
		} else if err != nil {
			return nil, err
		}
		docs = append(docs, v)
	}
}

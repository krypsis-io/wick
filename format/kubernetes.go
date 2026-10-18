package format

import (
	"encoding/json"
	"strings"

	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

// lastAppliedAnnotation holds the full object as JSON for anything created
// with kubectl apply, including a Secret's data.
const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// isSecretPayload reports whether key, in an object of the given kind, holds
// the values of a Kubernetes Secret.
func isSecretPayload(kind, key string) bool {
	return kind == "Secret" && (key == "data" || key == "stringData")
}

// redactSecretPayloadValue redacts val in full as a Kubernetes Secret value.
func redactSecretPayloadValue(val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	f, ok := d.KubernetesSecretValue(val)
	if !ok {
		return val, false
	}
	*findings = append(*findings, f)
	return replacer.Replace(val, f), true
}

// redactLastApplied redacts the Secret values inside a
// last-applied-configuration annotation. Each value is replaced where it
// appears in the annotation's JSON text, still JSON-escaped, rather than by
// re-encoding the JSON: the annotation keeps its exact bytes, and a token
// stands for text at the same escaping level as every other token in the
// string, which is what rehydration relies on.
func redactLastApplied(val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	var obj struct {
		Kind       string         `json:"kind"`
		Data       map[string]any `json:"data"`
		StringData map[string]any `json:"stringData"`
	}
	if json.Unmarshal([]byte(val), &obj) != nil || obj.Kind != "Secret" {
		return val, false
	}
	changed := false
	for _, payload := range []map[string]any{obj.Data, obj.StringData} {
		for _, v := range payload {
			s, ok := v.(string)
			if !ok {
				continue
			}
			for _, enc := range jsonStringForms(s) {
				f, ok := d.KubernetesSecretValue(enc)
				if !ok || !strings.Contains(val, `"`+enc+`"`) {
					continue
				}
				*findings = append(*findings, f)
				val = strings.ReplaceAll(val, `"`+enc+`"`, `"`+replacer.Replace(enc, f)+`"`)
				changed = true
			}
		}
	}
	return val, changed
}

// jsonStringForms returns the ways s can appear between the quotes of a JSON
// string: as written by an encoder with HTML escaping off, and as written by
// encoding/json's default (kubectl), which writes &, < and > as \u0026,
// \u003c and \u003e.
func jsonStringForms(s string) []string {
	plain := jsonStringContent(s)
	b, err := json.Marshal(s)
	if err != nil {
		return []string{plain}
	}
	if escaped := string(b[1 : len(b)-1]); escaped != plain {
		return []string{plain, escaped}
	}
	return []string{plain}
}

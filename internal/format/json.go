package format

import (
	"encoding/json"
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// redactString detects and redacts secrets/PII in a string value line by line,
// so that multi-line strings have correct byte offsets for redaction.
func redactString(val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	lines := strings.Split(val, "\n")
	changed := false
	for i, line := range lines {
		found := d.Detect(line)
		if len(found) > 0 {
			for j := range found {
				found[j].Line = i + 1
			}
			*findings = append(*findings, found...)
			lines[i] = redact.Redact(line, found, replacer)
			changed = true
		}
	}
	if changed {
		return strings.Join(lines, "\n"), true
	}
	return val, false
}

// ProcessJSON parses JSON, redacts string values, and preserves structure.
func ProcessJSON(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
	var data any
	dec := json.NewDecoder(strings.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		// Fall back to plaintext if JSON parsing fails.
		return ProcessPlain(input, detector, replacer)
	}

	var allFindings []detect.Finding
	redacted := walkJSON(data, detector, replacer, &allFindings)

	indent := indentOf(input)
	var (
		out []byte
		err error
	)
	if indent == "" {
		out, err = json.Marshal(redacted)
	} else {
		out, err = json.MarshalIndent(redacted, "", indent)
	}
	if err != nil {
		return ProcessPlain(input, detector, replacer)
	}
	return string(out), allFindings
}

func walkJSON(v any, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, child := range val {
			result[k] = walkJSON(child, d, replacer, findings)
		}
		return result
	case []any:
		result := make([]any, len(val))
		for i, child := range val {
			result[i] = walkJSON(child, d, replacer, findings)
		}
		return result
	case string:
		if result, changed := redactString(val, d, replacer, findings); changed {
			return result
		}
		return val
	default:
		return val
	}
}

// indentOf tries to detect the indentation used in the original JSON.
// Returns "" for single-line/minified input.
func indentOf(input string) string {
	lines := strings.Split(input, "\n")
	if len(lines) <= 1 {
		return ""
	}
	second := lines[1]
	trimmed := strings.TrimLeft(second, " \t")
	if len(second) > len(trimmed) {
		return second[:len(second)-len(trimmed)]
	}
	return ""
}

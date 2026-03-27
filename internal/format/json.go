package format

import (
	"encoding/json"
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// ProcessJSON parses JSON, redacts string values, and preserves structure.
func ProcessJSON(input string, detector *detect.Detector, style redact.Style) (string, []detect.Finding) {
	var data any
	if err := json.Unmarshal([]byte(input), &data); err != nil {
		// Fall back to plaintext if JSON parsing fails.
		return ProcessPlain(input, detector, style)
	}

	var allFindings []detect.Finding
	redacted := walkJSON(data, detector, style, &allFindings)

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
		return ProcessPlain(input, detector, style)
	}
	return string(out), allFindings
}

func walkJSON(v any, d *detect.Detector, style redact.Style, findings *[]detect.Finding) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, child := range val {
			result[k] = walkJSON(child, d, style, findings)
		}
		return result
	case []any:
		result := make([]any, len(val))
		for i, child := range val {
			result[i] = walkJSON(child, d, style, findings)
		}
		return result
	case string:
		found := d.Detect(val)
		if len(found) > 0 {
			*findings = append(*findings, found...)
			return redact.Redact(val, found, style)
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

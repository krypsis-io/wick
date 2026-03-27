package format

import (
	"encoding/json"
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// redactString detects and redacts secrets/PII in a string value line by line,
// so that multi-line strings have correct byte offsets for redaction.
func redactString(val string, d *detect.Detector, style redact.Style, findings *[]detect.Finding) (string, bool) {
	lines := strings.Split(val, "\n")
	changed := false
	for i, line := range lines {
		found := d.Detect(line)
		lineFindings := filterLineFindings(found, 1)
		if len(lineFindings) > 0 {
			*findings = append(*findings, lineFindings...)
			lines[i] = redact.Redact(line, lineFindings, style)
			changed = true
		}
	}
	if changed {
		return strings.Join(lines, "\n"), true
	}
	return val, false
}

// filterLineFindings returns findings for a specific 1-based line number.
func filterLineFindings(findings []detect.Finding, lineNum int) []detect.Finding {
	var filtered []detect.Finding
	for _, f := range findings {
		if f.Line == lineNum {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

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
		if result, changed := redactString(val, d, style, findings); changed {
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

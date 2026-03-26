package format

import (
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// ProcessPlain detects and redacts secrets/PII line by line.
func ProcessPlain(input string, detector *detect.Detector, style redact.Style) (string, []detect.Finding) {
	lines := strings.Split(input, "\n")
	var allFindings []detect.Finding
	result := make([]string, len(lines))

	for i, line := range lines {
		lineNum := i + 1
		findings := filterLine(detector.Detect(line), lineNum)
		allFindings = append(allFindings, findings...)
		result[i] = redact.Redact(line, findings, style)
	}

	return strings.Join(result, "\n"), allFindings
}

// filterLine returns only findings for the given line number.
func filterLine(findings []detect.Finding, lineNum int) []detect.Finding {
	var filtered []detect.Finding
	for _, f := range findings {
		if f.Line == lineNum {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

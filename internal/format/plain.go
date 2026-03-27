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
		findings := detector.Detect(line)
		for j := range findings {
			findings[j].Line = i + 1
		}
		allFindings = append(allFindings, findings...)
		result[i] = redact.Redact(line, findings, style)
	}

	return strings.Join(result, "\n"), allFindings
}

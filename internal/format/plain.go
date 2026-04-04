package format

import (
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// ProcessPlain detects and redacts secrets/PII line by line.
func ProcessPlain(input string, detector *detect.Detector, style redact.Style) (string, []detect.Finding) {
	var allFindings []detect.Finding

	// First pass: multiline rules against the full input (e.g. PEM private key blocks).
	// These are applied before line-by-line processing so their byte offsets remain valid.
	multiFindings := detector.DetectMultiline(input)
	working := input
	if len(multiFindings) > 0 {
		working = redact.Redact(input, multiFindings, style)
		allFindings = append(allFindings, multiFindings...)
	}

	// Second pass: line-by-line detection on the (possibly pre-redacted) input.
	lines := strings.Split(working, "\n")
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

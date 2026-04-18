package format

import (
	"strings"

	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

// ProcessPlain detects and redacts secrets/PII line by line.
func ProcessPlain(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
	var allFindings []detect.Finding

	// First pass: multiline rules against the full input (e.g. PEM private key blocks).
	// These are applied before line-by-line processing so their byte offsets remain valid.
	multiFindings := detector.DetectMultiline(input)
	working := input
	if len(multiFindings) > 0 {
		working = redact.Redact(input, multiFindings, replacer)
		// Normalize multiline findings from absolute input offsets to per-line relative
		// offsets so all entries in allFindings share the same coordinate semantics as
		// the per-line findings appended below. End is clamped to the end of the
		// starting line because the match may span multiple lines.
		for _, f := range multiFindings {
			lineStart := lineStartOffset(input, f.Line)
			absStart := f.Start
			f.Start = absStart - lineStart
			if nl := strings.Index(input[absStart:], "\n"); nl >= 0 {
				f.End = f.Start + nl
			} else {
				f.End = len(input) - lineStart
			}
			allFindings = append(allFindings, f)
		}
	}

	// Second pass: line-by-line detection on the (possibly pre-redacted) working buffer.
	// Line numbers here reflect working, not the original input — multiline redactions
	// may have collapsed multiple source lines into one replacement, shifting subsequent
	// line numbers. Overlapping detections with the first pass are expected to be absent
	// since multiline regions are already replaced in working.
	lines := strings.Split(working, "\n")
	result := make([]string, len(lines))
	for i, line := range lines {
		findings := detector.Detect(line)
		for j := range findings {
			findings[j].Line = i + 1
		}
		allFindings = append(allFindings, findings...)
		result[i] = redact.Redact(line, findings, replacer)
	}

	return strings.Join(result, "\n"), allFindings
}

// lineStartOffset returns the byte offset of the start of the given 1-based line in s.
func lineStartOffset(s string, line int) int {
	off := 0
	for l := 1; l < line; l++ {
		nl := strings.Index(s[off:], "\n")
		if nl < 0 {
			return len(s)
		}
		off += nl + 1
	}
	return off
}

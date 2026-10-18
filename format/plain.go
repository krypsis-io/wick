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
	working, multiFindings := redactMultiline(input, detector, replacer)
	allFindings = append(allFindings, multiFindings...)

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

// redactMultiline runs the multiline rules (e.g. PEM private key blocks)
// against the whole of input and redacts their matches. The returned findings
// use the same per-line coordinates as Detect: Start is relative to the start
// of the finding's line, and End is the end of the match, clamped to the end
// of that line when the match spans several lines.
func redactMultiline(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
	found := detector.DetectMultiline(input)
	if len(found) == 0 {
		return input, nil
	}
	working := redact.Redact(input, found, replacer)
	for i, f := range found {
		lineStart := lineStartOffset(input, f.Line)
		absStart, absEnd := f.Start, f.End
		lineEnd := len(input)
		if nl := strings.Index(input[absStart:], "\n"); nl >= 0 {
			lineEnd = absStart + nl
		}
		f.Start = absStart - lineStart
		f.End = min(absEnd, lineEnd) - lineStart
		found[i] = f
	}
	return working, found
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

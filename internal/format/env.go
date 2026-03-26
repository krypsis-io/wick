package format

import (
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// ProcessEnv parses KEY=VALUE lines, redacting only the VALUE portion.
func ProcessEnv(input string, detector *detect.Detector, style redact.Style) (string, []detect.Finding) {
	lines := strings.Split(input, "\n")
	var allFindings []detect.Finding
	result := make([]string, len(lines))

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			result[i] = line
			continue
		}

		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			result[i] = line
			continue
		}

		key := line[:eqIdx+1] // includes "="
		value := line[eqIdx+1:]

		// Strip surrounding quotes for detection, but preserve them.
		stripped, prefix, suffix := stripQuotes(value)

		found := detector.Detect(stripped)
		if len(found) > 0 {
			// Adjust finding offsets to account for key + "=" + prefix.
			offset := len(key) + len(prefix)
			for j := range found {
				found[j].Start += offset
				found[j].End += offset
				found[j].Line = i + 1
			}
			allFindings = append(allFindings, found...)
			redacted := redact.Redact(stripped, rebaseFindings(found, len(key)+len(prefix)), style)
			result[i] = key + prefix + redacted + suffix
		} else {
			result[i] = line
		}
	}
	return strings.Join(result, "\n"), allFindings
}

func stripQuotes(s string) (stripped, prefix, suffix string) {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1], s[:1], s[len(s)-1:]
		}
	}
	return s, "", ""
}

// rebaseFindings adjusts finding offsets by subtracting the given offset,
// so they are relative to the stripped value string.
func rebaseFindings(findings []detect.Finding, offset int) []detect.Finding {
	rebased := make([]detect.Finding, len(findings))
	for i, f := range findings {
		rebased[i] = f
		rebased[i].Start -= offset
		rebased[i].End -= offset
	}
	return rebased
}

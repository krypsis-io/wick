package format

import (
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// ProcessEnv parses KEY=VALUE lines, redacting only the VALUE portion.
func ProcessEnv(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
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

		// Detect against the full line so keyword-based rules (e.g.,
		// aws_secret_access_key) can see the key name for pre-filtering.
		// Then filter findings to only those within the value portion.
		valueStart := len(key) + len(prefix)
		valueEnd := valueStart + len(stripped)
		allFound := detector.Detect(line)
		var found []detect.Finding
		for _, f := range allFound {
			if f.Start >= valueStart && f.End <= valueEnd {
				// Shift offsets to be relative to stripped value.
				f.Start -= valueStart
				f.End -= valueStart
				found = append(found, f)
			}
		}

		if len(found) > 0 {
			// Redact using offsets relative to stripped value.
			redacted := redact.Redact(stripped, found, replacer)
			result[i] = key + prefix + redacted + suffix
			// Adjust finding offsets for output (relative to full line).
			for j := range found {
				found[j].Start += valueStart
				found[j].End += valueStart
				found[j].Line = i + 1
			}
			allFindings = append(allFindings, found...)
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

package output

import (
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

var redactedStyle = lipgloss.NewStyle().
	Background(lipgloss.Color("196")).
	Foreground(lipgloss.Color("231")).
	Bold(true)

// Terminal returns the output string. When stdout is a TTY, redacted values
// in the original text are highlighted with color. When piped, returns the
// pre-redacted plain text.
func Terminal(original, redacted string, findings []detect.Finding, replacer redact.Replacer) string {
	if !isTTY() || len(findings) == 0 {
		return redacted
	}
	return colorize(original, findings, replacer)
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// colorize rebuilds the output from the original text, replacing finding
// ranges with color-highlighted replacement strings.
func colorize(input string, findings []detect.Finding, replacer redact.Replacer) string {
	lines := strings.Split(input, "\n")

	for i, line := range lines {
		lineFindings := findingsForLine(findings, i+1)
		if len(lineFindings) == 0 {
			continue
		}
		lines[i] = replaceLine(line, lineFindings, replacer)
	}
	return strings.Join(lines, "\n")
}

func replaceLine(line string, findings []detect.Finding, replacer redact.Replacer) string {
	type coloredSpan struct {
		start   int
		end     int
		colored string
	}

	spans := make([]coloredSpan, len(findings))
	for i, f := range findings {
		replacement := replacer.Replace(line[f.Start:f.End], f)
		spans[i] = coloredSpan{f.Start, f.End, redactedStyle.Render(replacement)}
	}

	// Sort and merge overlapping spans.
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j].start < spans[j-1].start; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}
	merged := []coloredSpan{spans[0]}
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
		} else {
			merged = append(merged, s)
		}
	}

	var result strings.Builder
	prev := 0
	for _, s := range merged {
		if s.start >= len(line) {
			continue
		}
		end := s.end
		if end > len(line) {
			end = len(line)
		}
		result.WriteString(line[prev:s.start])
		result.WriteString(s.colored)
		prev = end
	}
	result.WriteString(line[prev:])
	return result.String()
}

func findingsForLine(findings []detect.Finding, lineNum int) []detect.Finding {
	var result []detect.Finding
	for _, f := range findings {
		if f.Line == lineNum {
			result = append(result, f)
		}
	}
	return result
}

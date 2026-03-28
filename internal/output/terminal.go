package output

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
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
func Terminal(original, redacted string, findings []detect.Finding, style redact.Style) string {
	if !isTTY() || len(findings) == 0 {
		return redacted
	}
	return colorize(original, findings, style)
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
func colorize(input string, findings []detect.Finding, style redact.Style) string {
	lines := strings.Split(input, "\n")
	replacement := style.Replacement()
	colored := redactedStyle.Render(replacement)

	for i, line := range lines {
		lineFindings := findingsForLine(findings, i+1)
		if len(lineFindings) == 0 {
			continue
		}
		lines[i] = replaceLine(line, lineFindings, colored)
	}
	return strings.Join(lines, "\n")
}

func replaceLine(line string, findings []detect.Finding, colored string) string {
	spans := make([]span, len(findings))
	for i, f := range findings {
		spans[i] = span{f.Start, f.End}
	}
	merged := mergeSpans(spans)

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
		result.WriteString(colored)
		prev = end
	}
	result.WriteString(line[prev:])
	return result.String()
}

type span struct{ start, end int }

func mergeSpans(spans []span) []span {
	if len(spans) == 0 {
		return nil
	}
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j].start < spans[j-1].start; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}
	merged := []span{spans[0]}
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
	return merged
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

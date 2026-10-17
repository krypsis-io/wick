package output

import (
	"fmt"
	"io"

	"github.com/krypsis-io/wick/detect"
)

const maxValueLen = 40

// Report writes a detailed per-finding report to w (typically stderr).
// Each finding gets its own line with line number, column, category, rule ID,
// and a preview of the matched value. Output goes to stderr so it does not
// interfere with the redacted stdout.
//
// The preview is masked unless showValues is set: stderr is routinely merged
// into logs, CI output, and agent transcripts (2>&1), and printing the raw
// value there would undo the redaction.
func Report(w io.Writer, findings []detect.Finding, showValues bool) {
	if len(findings) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "wick: %d finding(s)\n", len(findings))
	for _, f := range findings {
		preview := mask(f.Value, f.Category)
		if showValues {
			preview = truncate(f.Value, maxValueLen)
		}
		_, _ = fmt.Fprintf(w, "  line %d col %d  %-8s  %-30s  %s\n",
			f.Line,
			f.Start+1, // 1-based column
			f.Category,
			f.RuleID,
			preview,
		)
	}
}

// mask returns a preview that identifies a value without revealing it: the
// length, plus a few edge characters for secrets long enough that they leave
// most of it hidden (enough to recognise a ghp_ or ptr_ prefix). PII shows the
// length only, since the edges of an email or phone number identify a person.
func mask(s, category string) string {
	r := []rune(s)
	n := len(r)
	switch {
	case category == "pii":
		return fmt.Sprintf("… (%d chars)", n)
	case n >= 20:
		return fmt.Sprintf("%s…%s (%d chars)", string(r[:4]), string(r[n-4:]), n)
	case n >= 12:
		return fmt.Sprintf("%s… (%d chars)", string(r[:2]), n)
	default:
		return fmt.Sprintf("… (%d chars)", n)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

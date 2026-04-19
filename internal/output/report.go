package output

import (
	"fmt"
	"io"

	"github.com/krypsis-io/wick/detect"
)

const maxValueLen = 40

// Report writes a detailed per-finding report to w (typically stderr).
// Each finding gets its own line with line number, column, category, rule ID,
// and a truncated preview of the matched value.
// Output goes to stderr so it does not interfere with the redacted stdout.
func Report(w io.Writer, findings []detect.Finding) {
	if len(findings) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "wick: %d finding(s)\n", len(findings))
	for _, f := range findings {
		_, _ = fmt.Fprintf(w, "  line %d col %d  %-8s  %-30s  %s\n",
			f.Line,
			f.Start+1, // 1-based column
			f.Category,
			f.RuleID,
			truncate(f.Value, maxValueLen),
		)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

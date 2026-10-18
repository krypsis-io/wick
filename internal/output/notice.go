package output

import (
	"fmt"
	"io"
)

// BestEffortNotice is printed to stderr after any run that redacted something.
// Detection is pattern-based and will miss formats it has no rule for, so the
// output must still be reviewed before it is shared.
const BestEffortNotice = "wick: redaction is best-effort; review the output before sharing it"

// Notice writes BestEffortNotice to w when redacted is true. It goes to stderr,
// never stdout, so pipelines like `wick | pbcopy` stay clean.
func Notice(w io.Writer, redacted bool) {
	if redacted {
		_, _ = fmt.Fprintln(w, BestEffortNotice)
	}
}

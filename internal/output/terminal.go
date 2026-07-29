package output

import (
	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

// Terminal returns the output string for terminal display.
//
// It returns the already-redacted text as-is. Earlier revisions re-derived the
// output from the original input to add TTY color highlighting, but that was
// unsafe: per-line finding coordinates do not survive multiline redaction
// collapse (risking a slice panic or, worse, echoing an un-redacted multiline
// secret verbatim), and re-running a stateful replacer such as the tokenizer a
// second time corrupted its token map. The redacted string passed in is already
// safe, so we use it directly.
func Terminal(_, redacted string, _ []detect.Finding, _ redact.Replacer) string {
	return redacted
}

package output

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// BestEffortNotice reminds the user that detection is pattern-based and will
// miss formats it has no rule for, so the output must still be reviewed.
const BestEffortNotice = "wick: redaction is best-effort. Review the output before you share it. This message is shown once."

const (
	ansiYellow = "\x1b[33m"
	ansiReset  = "\x1b[0m"
)

// Notifier prints BestEffortNotice the first time wick redacts something on
// this machine. After that, a marker file keeps it quiet, so the notice does
// not repeat under every command's output.
type Notifier struct {
	Out io.Writer
	// Terminal reports whether Out is a terminal. The notice is for a person
	// reading the output, so CI logs and scripts never get it.
	Terminal bool
	// Color prints the notice in yellow, apart from the redacted text.
	Color bool
	// Marker is the file that records the notice was shown. When it is empty,
	// the notice cannot be remembered and is printed on every redaction.
	Marker string
}

// Notify prints the notice if redacted is true and it has not been shown.
func (n Notifier) Notify(redacted bool) {
	if !redacted || !n.Terminal {
		return
	}
	if n.Marker != "" {
		if _, err := os.Stat(n.Marker); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return
		}
	}
	msg := BestEffortNotice
	if n.Color {
		msg = ansiYellow + msg + ansiReset
	}
	_, _ = fmt.Fprintln(n.Out, msg)
	if n.Marker != "" {
		if err := os.MkdirAll(filepath.Dir(n.Marker), 0o755); err == nil {
			_ = os.WriteFile(n.Marker, nil, 0o644)
		}
	}
}

// NoticeMarkerPath returns $XDG_STATE_HOME/wick/notice-shown, or
// ~/.local/state/wick/notice-shown when XDG_STATE_HOME is not set. It returns
// "" when neither can be found.
func NoticeMarkerPath() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "wick", "notice-shown")
}

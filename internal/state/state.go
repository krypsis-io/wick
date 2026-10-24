// Package state finds the directory where wick keeps files between runs.
package state

import (
	"os"
	"path/filepath"
)

// Dir returns $XDG_STATE_HOME/wick, or ~/.local/state/wick when
// XDG_STATE_HOME is not set or not an absolute path, as the XDG spec
// requires. It returns "" when neither can be found.
func Dir() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(dir) {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "wick")
}

// MkdirPrivate creates dir with mode 0700. If dir exists, it sets its mode
// to 0700, because os.MkdirAll does not change an existing directory.
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

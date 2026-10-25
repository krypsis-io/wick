// Package state finds the directory where wick keeps files between runs.
package state

import (
	"os"
	"path/filepath"
	"runtime"
)

// Dir returns $XDG_STATE_HOME/wick when XDG_STATE_HOME is an absolute path.
// Otherwise it returns %LOCALAPPDATA%\wick on Windows and
// ~/.local/state/wick on other systems, as the XDG spec requires. It returns
// "" when none of these can be found.
func Dir() string {
	if dir := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(dir) {
		return filepath.Join(dir, "wick")
	}
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("LOCALAPPDATA"); filepath.IsAbs(dir) {
			return filepath.Join(dir, "wick")
		}
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "state", "wick")
}

// MkdirPrivate creates dir with mode 0700. If dir exists, it sets its mode
// to 0700, because os.MkdirAll does not change an existing directory.
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

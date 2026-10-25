package state

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestDir(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)
	if got, want := Dir(), filepath.Join(xdg, "wick"); got != want {
		t.Errorf("with XDG_STATE_HOME: got %q, want %q", got, want)
	}

	home, local := t.TempDir(), t.TempDir()
	t.Setenv("XDG_STATE_HOME", "relative/state")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", local)
	want := filepath.Join(home, ".local", "state", "wick")
	if runtime.GOOS == "windows" {
		want = filepath.Join(local, "wick")
	}
	if got := Dir(); got != want {
		t.Errorf("without XDG_STATE_HOME: got %q, want %q", got, want)
	}
}

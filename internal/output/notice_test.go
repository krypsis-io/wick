package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNotifier_ShownOnce(t *testing.T) {
	var buf strings.Builder
	n := Notifier{Out: &buf, Terminal: true, Marker: filepath.Join(t.TempDir(), "wick", "notice-shown")}

	n.Notify(false)
	if buf.String() != "" {
		t.Fatalf("notice printed without a redaction: %q", buf.String())
	}

	n.Notify(true)
	if buf.String() != BestEffortNotice+"\n" {
		t.Fatalf("first redaction: got %q, want %q", buf.String(), BestEffortNotice+"\n")
	}
	if _, err := os.Stat(n.Marker); err != nil {
		t.Fatalf("marker not written: %v", err)
	}

	buf.Reset()
	n.Notify(true)
	if buf.String() != "" {
		t.Fatalf("notice printed twice: %q", buf.String())
	}
}

func TestNotifier_NotTerminal(t *testing.T) {
	var buf strings.Builder
	n := Notifier{Out: &buf, Marker: filepath.Join(t.TempDir(), "notice-shown")}
	n.Notify(true)
	if buf.String() != "" {
		t.Fatalf("notice printed to a non-terminal: %q", buf.String())
	}
	if _, err := os.Stat(n.Marker); !os.IsNotExist(err) {
		t.Fatalf("marker written although the notice was not shown: %v", err)
	}
}

func TestNotifier_Color(t *testing.T) {
	var buf strings.Builder
	n := Notifier{Out: &buf, Terminal: true, Color: true, Marker: filepath.Join(t.TempDir(), "notice-shown")}
	n.Notify(true)
	want := ansiYellow + BestEffortNotice + ansiReset + "\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

func TestNotifier_NoMarker(t *testing.T) {
	var buf strings.Builder
	n := Notifier{Out: &buf, Terminal: true}
	n.Notify(true)
	n.Notify(true)
	if got := strings.Count(buf.String(), BestEffortNotice); got != 2 {
		t.Fatalf("without a marker the notice should print on each redaction, got %d", got)
	}
}

func TestNoticeMarkerPath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/state")
	if got, want := NoticeMarkerPath(), filepath.Join("/state", "wick", "notice-shown"); got != want {
		t.Errorf("with XDG_STATE_HOME: got %q, want %q", got, want)
	}

	home := t.TempDir()
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if got, want := NoticeMarkerPath(), filepath.Join(home, ".local", "state", "wick", "notice-shown"); got != want {
		t.Errorf("without XDG_STATE_HOME: got %q, want %q", got, want)
	}
}

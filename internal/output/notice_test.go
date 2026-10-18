package output

import (
	"strings"
	"testing"
)

func TestNotice(t *testing.T) {
	var buf strings.Builder
	Notice(&buf, false)
	if buf.String() != "" {
		t.Errorf("expected no notice without findings, got %q", buf.String())
	}

	Notice(&buf, true)
	if buf.String() != BestEffortNotice+"\n" {
		t.Errorf("got %q, want %q", buf.String(), BestEffortNotice+"\n")
	}
}

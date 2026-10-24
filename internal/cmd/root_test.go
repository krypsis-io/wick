package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/krypsis-io/wick/internal/config"
)

func TestRunTokenize_ExitStatus(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"redacted", "contact jordan.lee@shopco.io\n", errFindingsPresent},
		{"clean", "nothing to see here\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetTokenFlags(t)
			flagTokenFile = filepath.Join(t.TempDir(), "tokens.enc")

			setStdin(t, tt.input)
			silenceStdio(t)

			err := runTokenize(&config.Config{}, nil)
			if !errors.Is(err, tt.want) {
				t.Fatalf("runTokenize() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"clean", nil, 0},
		{"redacted", errFindingsPresent, 1},
		{"wrapped findings", fmt.Errorf("dir mode: %w", errFindingsPresent), 1},
		{"error", errors.New("open app.log: no such file or directory"), 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.err); got != tt.want {
				t.Errorf("exitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func setStdin(t *testing.T, input string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = orig
		f.Close()
	})
}

func silenceStdio(t *testing.T) {
	t.Helper()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devNull, devNull
	t.Cleanup(func() {
		os.Stdout, os.Stderr = origOut, origErr
		devNull.Close()
	})
}

package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/krypsis-io/wick/internal/config"
)

func TestMain(m *testing.M) {
	// Never touch the keychain of the machine that runs the tests.
	keyring.MockInit()
	os.Exit(m.Run())
}

// resetTokenFlags clears the token flags, points the state directory and the
// working directory at empty temporary directories, and empties the mock
// keychain.
func resetTokenFlags(t *testing.T) string {
	t.Helper()
	flagKey, flagTokenFile, flagForget = "", "", false
	flagTokenize, flagRehydrate = false, false
	t.Cleanup(func() {
		flagKey, flagTokenFile, flagForget = "", "", false
		flagTokenize, flagRehydrate = false, false
	})
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv(keyEnv, "")
	t.Chdir(t.TempDir())
	keyring.MockInit()
	return filepath.Join(state, "wick", "tokens.enc")
}

// runCaptured runs fn with input on stdin and returns stdout and stderr.
func runCaptured(t *testing.T, input string, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	setStdin(t, input)
	dir := t.TempDir()
	outF, _ := os.Create(filepath.Join(dir, "stdout"))
	errF, _ := os.Create(filepath.Join(dir, "stderr"))
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outF, errF
	err = fn()
	os.Stdout, os.Stderr = origOut, origErr
	outF.Close()
	errF.Close()
	o, _ := os.ReadFile(outF.Name())
	e, _ := os.ReadFile(errF.Name())
	return string(o), string(e), err
}

func tokenize(t *testing.T, input string) (string, string, error) {
	t.Helper()
	return runCaptured(t, input, func() error { return runTokenize(&config.Config{}, nil) })
}

func rehydrate(t *testing.T, input string) (string, string, error) {
	t.Helper()
	return runCaptured(t, input, func() error { return runRehydrate(nil) })
}

func TestTokenize_KeychainKey(t *testing.T) {
	path := resetTokenFlags(t)

	out, stderr, err := tokenize(t, "contact a@acme.com\n")
	if !errors.Is(err, errFindingsPresent) {
		t.Fatalf("first run: %v", err)
	}
	if out != "contact [EMAIL-1]\n" {
		t.Errorf("first run: got %q", out)
	}
	if !strings.Contains(stderr, "stored a new key in the system keychain") || strings.Contains(stderr, "key:") {
		t.Errorf("first run stderr: %q", stderr)
	}

	out, stderr, _ = tokenize(t, "cc b@acme.com and a@acme.com\n")
	if out != "cc [EMAIL-2] and [EMAIL-1]\n" {
		t.Errorf("second run: got %q", out)
	}
	if strings.Contains(stderr, "stored a new key") {
		t.Errorf("second run made a new key: %q", stderr)
	}

	out, _, err = rehydrate(t, "[EMAIL-1] wrote to [EMAIL-2]\n")
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if out != "a@acme.com wrote to b@acme.com\n" {
		t.Errorf("rehydrate: got %q", out)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("token map mode = %o, want 600", info.Mode().Perm())
		}
		dir, _ := os.Stat(filepath.Dir(path))
		if dir.Mode().Perm() != 0o700 {
			t.Errorf("state directory mode = %o, want 700", dir.Mode().Perm())
		}
	}
}

var keyLine = regexp.MustCompile(`wick: key: (\S+)`)

func TestTokenize_NoKeychain(t *testing.T) {
	path := resetTokenFlags(t)
	keyring.MockInitWithError(errors.New("no secret service"))

	_, stderr, _ := tokenize(t, "contact a@acme.com\n")
	m := keyLine.FindStringSubmatch(stderr)
	if m == nil || !strings.Contains(stderr, "cannot use the system keychain: no secret service") {
		t.Fatalf("expected the key on stderr, got %q", stderr)
	}
	before, _ := os.ReadFile(path)

	if _, _, err := tokenize(t, "contact b@acme.com\n"); err == nil || !strings.Contains(err.Error(), "no key was found") {
		t.Fatalf("expected a missing key error, got %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("the token map changed after a run without a key")
	}
	if _, _, err := rehydrate(t, "[EMAIL-1]\n"); err == nil || !strings.Contains(err.Error(), "cannot use the system keychain") {
		t.Fatalf("expected a keychain error, got %v", err)
	}

	t.Setenv(keyEnv, m[1])
	if out, _, _ := tokenize(t, "contact b@acme.com\n"); out != "contact [EMAIL-2]\n" {
		t.Errorf("with %s: got %q", keyEnv, out)
	}
	if out, _, err := rehydrate(t, "[EMAIL-1] [EMAIL-2]\n"); err != nil || out != "a@acme.com b@acme.com\n" {
		t.Errorf("rehydrate with %s: got %q, %v", keyEnv, out, err)
	}
}

func TestTokenize_WrongKeyKeepsMap(t *testing.T) {
	path := resetTokenFlags(t)
	tokenize(t, "contact a@acme.com\n")
	before, _ := os.ReadFile(path)

	flagKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, _, err := tokenize(t, "contact b@acme.com\n"); err == nil || !strings.Contains(err.Error(), "wick --forget") {
		t.Fatalf("expected a decrypt error, got %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("the token map changed after a run with the wrong key")
	}
}

func TestRehydrate_NoTokenMap(t *testing.T) {
	resetTokenFlags(t)
	if _, _, err := rehydrate(t, "x\n"); err == nil || !strings.Contains(err.Error(), "run wick --tokenize first") {
		t.Errorf("got %v", err)
	}

	if err := os.WriteFile(legacyTokenFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rehydrate(t, "x\n"); err == nil || !strings.Contains(err.Error(), "--token-file "+legacyTokenFile) {
		t.Errorf("expected a hint about %s, got %v", legacyTokenFile, err)
	}
}

func TestForget(t *testing.T) {
	path := resetTokenFlags(t)
	tokenize(t, "contact a@acme.com\n")

	_, stderr, err := runCaptured(t, "", runForget)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "deleted "+path) || !strings.Contains(stderr, "deleted the key") {
		t.Errorf("stderr: %q", stderr)
	}
	if fileExists(path) {
		t.Error("token map still exists")
	}
	if _, err := keyring.Get(keyringService, keyringUser); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("key still in the keychain: %v", err)
	}

	if _, stderr, err := runCaptured(t, "", runForget); err != nil || stderr != "" {
		t.Errorf("second forget: %q, %v", stderr, err)
	}
}

func TestForget_CustomTokenFileKeepsKey(t *testing.T) {
	resetTokenFlags(t)
	tokenize(t, "contact a@acme.com\n")

	flagTokenFile = filepath.Join(t.TempDir(), "other.enc")
	tokenize(t, "contact b@acme.com\n")
	if _, _, err := runCaptured(t, "", runForget); err != nil {
		t.Fatal(err)
	}
	if fileExists(flagTokenFile) {
		t.Error("custom token map still exists")
	}
	if _, err := keyring.Get(keyringService, keyringUser); err != nil {
		t.Errorf("key was deleted: %v", err)
	}
}

func TestValidateRunFlags_Forget(t *testing.T) {
	resetTokenFlags(t)
	flagForget, flagTokenize = true, true
	if err := validateRunFlags(nil); err == nil {
		t.Error("expected an error for --forget with --tokenize")
	}
	flagTokenize = false
	if err := validateRunFlags([]string{"app.log"}); err == nil {
		t.Error("expected an error for --forget with a file")
	}
	if err := validateRunFlags(nil); err != nil {
		t.Errorf("--forget alone: %v", err)
	}
}

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
	"time"

	"github.com/zalando/go-keyring"

	"github.com/krypsis-io/wick"
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

// storedKey returns the key that the mock keychain holds for the token map at path.
func storedKey(t *testing.T, path string) (string, error) {
	t.Helper()
	account, err := keychainAccount(path)
	if err != nil {
		t.Fatal(err)
	}
	return keyring.Get(keyringService, account)
}

func mustKey(t *testing.T) string {
	t.Helper()
	k, err := wick.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
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

func TestTokenMapStatusUnknown(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory that the user cannot read")
	}
	resetTokenFlags(t)
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	flagTokenFile = filepath.Join(locked, "tokens.enc")
	if err := os.WriteFile(flagTokenFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	if _, _, err := tokenize(t, "contact a@acme.com\n"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("tokenize: got %v, want a permission error", err)
	}
	if _, err := storedKey(t, flagTokenFile); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("tokenize stored a key for a token map it cannot read: %v", err)
	}
	if _, _, err := rehydrate(t, "x\n"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("rehydrate: got %v, want a permission error", err)
	}
}

func TestTokenize_LegacyTokenMap(t *testing.T) {
	path := resetTokenFlags(t)
	if err := os.WriteFile(legacyTokenFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tokenize(t, "contact a@acme.com\n"); err == nil || !strings.Contains(err.Error(), "--token-file "+legacyTokenFile) {
		t.Errorf("expected a hint about %s, got %v", legacyTokenFile, err)
	}
	if exists, _ := fileExists(path); exists {
		t.Error("tokenize made a new token map next to the legacy one")
	}

	t.Setenv(keyEnv, mustKey(t))
	if _, _, err := tokenize(t, "contact a@acme.com\n"); err == nil || !strings.Contains(err.Error(), "--token-file "+legacyTokenFile) {
		t.Errorf("with %s: expected a hint about %s, got %v", keyEnv, legacyTokenFile, err)
	}
	if _, err := storedKey(t, path); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("tokenize stored a key: %v", err)
	}
}

func TestTokenize_LegacyStatusUnknown(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory that the user cannot read")
	}
	path := resetTokenFlags(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cwd, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cwd, 0o700) })

	if _, _, err := tokenize(t, "contact a@acme.com\n"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("tokenize: got %v, want a permission error", err)
	}
	if exists, _ := fileExists(path); exists {
		t.Error("tokenize made a new token map")
	}
}

func TestForget_WaitsForLock(t *testing.T) {
	path := resetTokenFlags(t)
	tokenize(t, "contact a@acme.com\n")
	unlock, err := lockTokenMap(path)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error)
	go func() { done <- runForget() }()
	select {
	case <-done:
		t.Fatal("--forget ran while a tokenize run held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("--forget did not run after unlock")
	}
	if exists, _ := fileExists(path + ".lock"); !exists {
		t.Error("--forget deleted the lock file")
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
	if exists, _ := fileExists(path); exists {
		t.Error("token map still exists")
	}
	if _, err := storedKey(t, path); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("key still in the keychain: %v", err)
	}

	if _, stderr, err := runCaptured(t, "", runForget); err != nil || stderr != "" {
		t.Errorf("second forget: %q, %v", stderr, err)
	}
}

func TestForget_KeepsKeyOfOtherTokenMap(t *testing.T) {
	defaultPath := resetTokenFlags(t)
	tokenize(t, "contact a@acme.com\n")

	flagTokenFile = filepath.Join(t.TempDir(), "other.enc")
	tokenize(t, "contact b@acme.com\n")
	if _, _, err := runCaptured(t, "", runForget); err != nil {
		t.Fatal(err)
	}
	if exists, _ := fileExists(flagTokenFile); exists {
		t.Error("custom token map still exists")
	}
	if _, err := storedKey(t, flagTokenFile); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("key of the custom token map still in the keychain: %v", err)
	}

	flagTokenFile = ""
	if _, err := storedKey(t, defaultPath); err != nil {
		t.Errorf("key of the default token map was deleted: %v", err)
	}
	if out, _, err := rehydrate(t, "[EMAIL-1]\n"); err != nil || out != "a@acme.com\n" {
		t.Errorf("rehydrate the default token map: got %q, %v", out, err)
	}
}

func TestTokenize_TightensStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use Unix file modes")
	}
	path := resetTokenFlags(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	tokenize(t, "contact a@acme.com\n")
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("state directory mode: got %o, want 700", mode)
	}
}

func TestLockTokenMap(t *testing.T) {
	path := resetTokenFlags(t)
	unlock, err := lockTokenMap(path)
	if err != nil {
		t.Fatal(err)
	}

	locked := make(chan struct{})
	go func() {
		unlock2, err := lockTokenMap(path)
		if err == nil {
			unlock2()
		}
		close(locked)
	}()

	select {
	case <-locked:
		t.Fatal("a second lock was taken while the first lock was held")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("the second lock was not taken after unlock")
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

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
	if !strings.Contains(stderr, "new token map at "+path) {
		t.Errorf("first run does not show the token map path: %q", stderr)
	}

	out, stderr, _ = tokenize(t, "cc b@acme.com and a@acme.com\n")
	if out != "cc [EMAIL-2] and [EMAIL-1]\n" {
		t.Errorf("second run: got %q", out)
	}
	if stderr != "" {
		t.Errorf("second run stderr: %q", stderr)
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

func TestTokenizeAndRehydrate_Files(t *testing.T) {
	resetTokenFlags(t)
	dir := t.TempDir()
	a, b, reply := filepath.Join(dir, "a.log"), filepath.Join(dir, "b.log"), filepath.Join(dir, "reply.txt")
	for path, data := range map[string]string{a: "from a@acme.com\n", b: "to b@acme.com\n", reply: "[EMAIL-2] answered [EMAIL-1]\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	out, _, err := runCaptured(t, "", func() error { return runTokenize(&config.Config{}, []string{a, b}) })
	if !errors.Is(err, errFindingsPresent) || out != "from [EMAIL-1]\nto [EMAIL-2]\n" {
		t.Fatalf("tokenize files: got %q, %v", out, err)
	}
	out, _, err = runCaptured(t, "", func() error { return runRehydrate([]string{reply}) })
	if err != nil || out != "b@acme.com answered a@acme.com\n" {
		t.Errorf("rehydrate file: got %q, %v", out, err)
	}
	if _, _, err := runCaptured(t, "", func() error { return runTokenize(&config.Config{}, []string{dir}) }); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("tokenize a directory: got %v", err)
	}
}

func TestRehydrate_UnknownTokens(t *testing.T) {
	resetTokenFlags(t)
	tokenize(t, "contact a@acme.com\n")

	out, stderr, err := rehydrate(t, "[EMAIL-1], [EMAIL-9], [EMAIL-9] and [ERROR-404]\n")
	if err != nil {
		t.Fatal(err)
	}
	if out != "a@acme.com, [EMAIL-9], [EMAIL-9] and [ERROR-404]\n" {
		t.Errorf("stdout: %q", out)
	}
	if want := "wick: 1 token is not in the token map: [EMAIL-9]\n"; stderr != want {
		t.Errorf("stderr: got %q, want %q", stderr, want)
	}
	if _, stderr, _ := rehydrate(t, "[EMAIL-1]\n"); stderr != "" {
		t.Errorf("stderr with only known tokens: %q", stderr)
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

func TestValidateRunFlags_TokenModes(t *testing.T) {
	tests := []struct {
		name  string
		set   func()
		files []string
		want  string
	}{
		{"forget with tokenize", func() { flagForget, flagTokenize = true, true }, nil, "--forget cannot be combined"},
		{"forget with a file", func() { flagForget = true }, []string{"app.log"}, "--forget cannot be combined"},
		{"forget with key", func() { flagForget, flagKey = true, "k" }, nil, "--key cannot be combined with --forget"},
		{"tokenize with dir", func() { flagTokenize, flagDir = true, "logs" }, nil, "--tokenize does not support --dir"},
		{"tokenize with format", func() { flagTokenize, flagFormat = true, "json" }, nil, "--format cannot be combined with --tokenize"},
		{"tokenize with style", func() { flagTokenize, flagStyle = true, "stars" }, nil, "--style cannot be combined with --tokenize"},
		{"tokenize with summary", func() { flagTokenize, flagSummary = true, true }, nil, "--summary cannot be combined with --tokenize"},
		{"rehydrate with report", func() { flagRehydrate, flagReport = true, true }, nil, "--report cannot be combined with --rehydrate"},
		{"rehydrate with report-unsafe", func() { flagRehydrate, flagUnsafe = true, true }, nil, "--report-unsafe cannot be combined with --rehydrate"},
		{"key without a token mode", func() { flagKey = "k" }, nil, "--key is only valid"},
		{"token-file without a token mode", func() { flagTokenFile = "x.enc" }, nil, "--token-file is only valid"},
		{"forget alone", func() { flagForget = true }, nil, ""},
		{"forget with token-file", func() { flagForget, flagTokenFile = true, "x.enc" }, nil, ""},
		{"tokenize with files and key", func() { flagTokenize, flagKey = true, "k" }, []string{"app.log"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetTokenFlags(t)
			flagDir, flagFormat, flagStyle = "", "", ""
			flagSummary, flagReport, flagUnsafe = false, false, false
			t.Cleanup(func() {
				flagDir, flagFormat, flagStyle = "", "", ""
				flagSummary, flagReport, flagUnsafe = false, false, false
			})
			tt.set()
			err := validateRunFlags(tt.files)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("got %v, want an error with %q", err, tt.want)
			}
		})
	}
}

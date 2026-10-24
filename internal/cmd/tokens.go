package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"

	"github.com/krypsis-io/wick"
	"github.com/krypsis-io/wick/internal/state"
)

const (
	keyringService = "wick"
	keyEnv         = "WICK_KEY"

	// legacyTokenFile is where wick 0.4 and earlier wrote the token map.
	legacyTokenFile = ".wick-tokens.enc"
)

// tokenFilePath returns --token-file, or tokens.enc in the state directory.
func tokenFilePath() (string, error) {
	if flagTokenFile != "" {
		return flagTokenFile, nil
	}
	dir := state.Dir()
	if dir == "" {
		return "", errors.New("cannot find the home directory: pass --token-file")
	}
	return filepath.Join(dir, "tokens.enc"), nil
}

// keychainAccount returns the keychain account that holds the key of the
// token map at path. Each token map has its own key, so that --forget for one
// map does not delete the key of another map.
func keychainAccount(path string) (string, error) {
	return filepath.Abs(path)
}

// lookupKey returns the key from --key, then WICK_KEY, then the system
// keychain entry for the token map at path. It returns "" when no key is set.
// The error is not nil only when the keychain cannot be used.
func lookupKey(path string) (string, error) {
	if flagKey != "" {
		return flagKey, nil
	}
	if k := os.Getenv(keyEnv); k != "" {
		return k, nil
	}
	account, err := keychainAccount(path)
	if err != nil {
		return "", err
	}
	k, err := keyring.Get(keyringService, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return k, err
}

// newKey generates a key for the token map at path and stores it in the
// system keychain. When the keychain cannot be used, it prints the key so
// that the user can set WICK_KEY.
func newKey(path string, keychainErr error) (string, error) {
	k, err := wick.GenerateKey()
	if err != nil {
		return "", err
	}
	if keychainErr == nil {
		var account string
		if account, keychainErr = keychainAccount(path); keychainErr == nil {
			keychainErr = keyring.Set(keyringService, account, k)
		}
	}
	if keychainErr != nil {
		fmt.Fprintf(os.Stderr, "wick: cannot use the system keychain: %v\n", keychainErr)
		fmt.Fprintf(os.Stderr, "wick: key: %s\n", k)
		fmt.Fprintf(os.Stderr, "wick: set %s to this key to tokenize more input or to rehydrate. It is not shown again.\n", keyEnv)
		return k, nil
	}
	fmt.Fprintln(os.Stderr, "wick: stored a new key in the system keychain")
	return k, nil
}

// fileExists reports whether path exists. It returns an error when the
// status of path is unknown, for example when a parent directory cannot be read.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// lockTokenMap creates the directory of the token map at path and takes an
// exclusive lock on path.lock, so that two tokenize runs do not save over each
// other. The caller must call unlock.
func lockTokenMap(path string) (unlock func(), err error) {
	dir := filepath.Dir(path)
	if flagTokenFile == "" {
		err = state.MkdirPrivate(dir)
	} else {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cannot lock %s: %w", f.Name(), err)
	}
	return func() { _ = f.Close() }, nil
}

// loadTokenMap loads the token map at path. It returns an empty map and
// exists == false when there is no file at path.
func loadTokenMap(key []byte, path string) (tm wick.TokenMap, exists bool, err error) {
	exists, err = fileExists(path)
	if err != nil || !exists {
		return wick.TokenMap{}, false, err
	}
	tm, err = wick.LoadTokenMap(key, path)
	return tm, true, err
}

func runForget() error {
	path, err := tokenFilePath()
	if err != nil {
		return err
	}
	// Keep the lock file. If it is deleted, a tokenize run that waits for the
	// old lock and a new run that creates a new lock file can run together.
	unlock, err := lockTokenMap(path)
	if err != nil {
		return err
	}
	defer unlock()
	switch err := os.Remove(path); {
	case err == nil:
		fmt.Fprintf(os.Stderr, "wick: deleted %s\n", path)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}

	account, err := keychainAccount(path)
	if err != nil {
		return err
	}
	// When the keychain cannot be used, it holds no key, so there is nothing
	// to delete or to report.
	if _, err := keyring.Get(keyringService, account); err == nil {
		if err := keyring.Delete(keyringService, account); err != nil {
			return fmt.Errorf("cannot delete the key from the system keychain: %w", err)
		}
		fmt.Fprintln(os.Stderr, "wick: deleted the key from the system keychain")
	}
	if os.Getenv(keyEnv) != "" {
		fmt.Fprintf(os.Stderr, "wick: %s is still set in the environment\n", keyEnv)
	}
	return nil
}

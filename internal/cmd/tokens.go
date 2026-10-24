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
	keyringUser    = "token-map-key"
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

// lookupKey returns the key from --key, then WICK_KEY, then the system
// keychain. It returns "" when no key is set. The error is not nil only when
// the keychain cannot be used.
func lookupKey() (string, error) {
	if flagKey != "" {
		return flagKey, nil
	}
	if k := os.Getenv(keyEnv); k != "" {
		return k, nil
	}
	k, err := keyring.Get(keyringService, keyringUser)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return k, err
}

// newKey generates a key and stores it in the system keychain. When the
// keychain cannot be used, it prints the key so that the user can set WICK_KEY.
func newKey(keychainErr error) (string, error) {
	k, err := wick.GenerateKey()
	if err != nil {
		return "", err
	}
	if keychainErr == nil {
		keychainErr = keyring.Set(keyringService, keyringUser, k)
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadTokenMap loads the token map at path. It returns an empty map and
// exists == false when there is no file at path.
func loadTokenMap(key []byte, path string) (tm wick.TokenMap, exists bool, err error) {
	if !fileExists(path) {
		return wick.TokenMap{}, false, nil
	}
	tm, err = wick.LoadTokenMap(key, path)
	return tm, true, err
}

func runForget() error {
	path, err := tokenFilePath()
	if err != nil {
		return err
	}
	switch err := os.Remove(path); {
	case err == nil:
		fmt.Fprintf(os.Stderr, "wick: deleted %s\n", path)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}

	// A custom --token-file can share the key with the default token map, so
	// keep the key in that case. When the keychain cannot be used, it holds
	// no key, so there is nothing to report.
	if flagTokenFile == "" {
		if err := keyring.Delete(keyringService, keyringUser); err == nil {
			fmt.Fprintln(os.Stderr, "wick: deleted the key from the system keychain")
		}
	}
	if os.Getenv(keyEnv) != "" {
		fmt.Fprintf(os.Stderr, "wick: %s is still set in the environment\n", keyEnv)
	}
	return nil
}

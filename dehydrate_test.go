package wick

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	k1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if k1 == k2 {
		t.Error("two GenerateKey calls should not produce the same key")
	}
}

func TestDecodeKey_Valid(t *testing.T) {
	encoded, _ := GenerateKey()
	key, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

func TestDecodeKey_Invalid(t *testing.T) {
	if _, err := DecodeKey("not-base64!!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
	// Valid base64 but wrong length (16 bytes = 24 base64 chars).
	if _, err := DecodeKey("AAAAAAAAAAAAAAAAAAAAAA=="); err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestDehydrate_Basic(t *testing.T) {
	input := "Contact admin@acme.com from 10.0.1.42"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)

	redacted, tm, err := Dehydrate(input, keyBytes)
	if err != nil {
		t.Fatalf("Dehydrate: %v", err)
	}

	if strings.Contains(redacted, "admin@acme.com") {
		t.Errorf("email should be redacted: %s", redacted)
	}
	if strings.Contains(redacted, "10.0.1.42") {
		t.Errorf("IP should be redacted: %s", redacted)
	}
	if len(tm.entries) == 0 {
		t.Error("expected non-empty token map")
	}
}

func TestRoundTrip(t *testing.T) {
	input := "Contact admin@acme.com from 10.0.1.42 — key: AKIAZ5GMHYJKLMNOPQRS"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)

	redacted, tm, err := Dehydrate(input, keyBytes)
	if err != nil {
		t.Fatalf("Dehydrate: %v", err)
	}

	restored, err := Rehydrate(redacted, tm)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if restored != input {
		t.Errorf("round-trip failed:\n  input:    %q\n  restored: %q", input, restored)
	}
}

func TestRoundTrip_RepeatedValue(t *testing.T) {
	input := "admin@acme.com is the admin. Contact admin@acme.com."
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)

	redacted, tm, err := Dehydrate(input, keyBytes)
	if err != nil {
		t.Fatalf("Dehydrate: %v", err)
	}

	restored, err := Rehydrate(redacted, tm)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if restored != input {
		t.Errorf("round-trip with repeated value failed:\n  input:    %q\n  restored: %q", input, restored)
	}
}

func TestSaveAndLoadTokenMap(t *testing.T) {
	input := "Contact admin@acme.com from 10.0.1.42"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)

	_, tm, err := Dehydrate(input, keyBytes)
	if err != nil {
		t.Fatalf("Dehydrate: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "tokens.enc")
	if err := SaveTokenMap(tm, keyBytes, tmpFile); err != nil {
		t.Fatalf("SaveTokenMap: %v", err)
	}

	loaded, err := LoadTokenMap(keyBytes, tmpFile)
	if err != nil {
		t.Fatalf("LoadTokenMap: %v", err)
	}

	if len(loaded.entries) != len(tm.entries) {
		t.Errorf("loaded %d entries, want %d", len(loaded.entries), len(tm.entries))
	}
}

func TestLoadTokenMap_WrongKey(t *testing.T) {
	input := "admin@acme.com"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)

	_, tm, _ := Dehydrate(input, keyBytes)
	tmpFile := filepath.Join(t.TempDir(), "tokens.enc")
	_ = SaveTokenMap(tm, keyBytes, tmpFile)

	wrongKey, _ := GenerateKey()
	wrongKeyBytes, _ := DecodeKey(wrongKey)
	if _, err := LoadTokenMap(wrongKeyBytes, tmpFile); err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestLoadTokenMap_MissingFile(t *testing.T) {
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)
	if _, err := LoadTokenMap(keyBytes, "/nonexistent/path.enc"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSaveTokenMap_FilePermissions(t *testing.T) {
	input := "admin@acme.com"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)
	_, tm, _ := Dehydrate(input, keyBytes)

	tmpFile := filepath.Join(t.TempDir(), "tokens.enc")
	if err := SaveTokenMap(tm, keyBytes, tmpFile); err != nil {
		t.Fatalf("SaveTokenMap: %v", err)
	}

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected file mode 0600, got %o", info.Mode().Perm())
	}
}

func TestRehydrate_NoFindings(t *testing.T) {
	input := "nothing sensitive here"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)

	redacted, tm, err := Dehydrate(input, keyBytes)
	if err != nil {
		t.Fatalf("Dehydrate: %v", err)
	}
	if redacted != input {
		t.Errorf("no-findings input should pass through unchanged: %q", redacted)
	}

	restored, err := Rehydrate(redacted, tm)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if restored != input {
		t.Errorf("round-trip with no findings failed: %q", restored)
	}
}

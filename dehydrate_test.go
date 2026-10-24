package wick

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/krypsis-io/wick/detect"
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

	redacted, tm, err := Dehydrate(input)
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

	redacted, tm, err := Dehydrate(input)
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

	redacted, tm, err := Dehydrate(input)
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

func TestRoundTrip_CustomPatternWithReplacement(t *testing.T) {
	// A custom pattern that defines a static replacement override must still
	// round-trip under Dehydrate: tokenization takes precedence over the
	// override so the value stays reversible rather than being lost.
	patterns := []detect.CustomPattern{
		{Name: "internal-code", Regex: `ACME-\d{4}`, Replacement: "[CODE]"},
	}
	input := "Ticket ACME-1234 is open"

	redacted, tm, err := Dehydrate(input, WithCustomPatterns(patterns))
	if err != nil {
		t.Fatalf("Dehydrate: %v", err)
	}
	if strings.Contains(redacted, "ACME-1234") {
		t.Errorf("custom value should be redacted: %s", redacted)
	}
	if strings.Contains(redacted, "[CODE]") {
		t.Errorf("static override must not be used in tokenize mode: %s", redacted)
	}

	restored, err := Rehydrate(redacted, tm)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if restored != input {
		t.Errorf("round-trip failed:\n  input:    %q\n  restored: %q", input, restored)
	}
}

func TestSaveAndLoadTokenMap(t *testing.T) {
	input := "Contact admin@acme.com from 10.0.1.42"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)

	_, tm, err := Dehydrate(input)
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

	_, tm, _ := Dehydrate(input)
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use Unix file modes")
	}
	input := "admin@acme.com"
	key, _ := GenerateKey()
	keyBytes, _ := DecodeKey(key)
	_, tm, _ := Dehydrate(input)

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

	redacted, tm, err := Dehydrate(input)
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

func TestDehydrate_WithTokenMap(t *testing.T) {
	_, first, err := Dehydrate("contact a@acme.com")
	if err != nil {
		t.Fatal(err)
	}

	redacted, merged, err := Dehydrate("cc b@acme.com and a@acme.com", WithTokenMap(first))
	if err != nil {
		t.Fatal(err)
	}
	if want := "cc [EMAIL-2] and [EMAIL-1]"; redacted != want {
		t.Errorf("got %q, want %q", redacted, want)
	}

	restored, err := Rehydrate("[EMAIL-1] wrote to [EMAIL-2]", merged)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a@acme.com wrote to b@acme.com"; restored != want {
		t.Errorf("got %q, want %q", restored, want)
	}
}

func TestSaveTokenMap_Mode(t *testing.T) {
	key, _ := DecodeKey(mustGenerateKey(t))
	_, tm, _ := Dehydrate("contact a@acme.com")
	path := filepath.Join(t.TempDir(), "tokens.enc")
	for range 2 {
		if err := SaveTokenMap(tm, key, path); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); runtime.GOOS != "windows" && mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 1 {
		t.Errorf("temporary files left behind: %v", files)
	}
}

func mustGenerateKey(t *testing.T) string {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestUnknownTokens(t *testing.T) {
	_, tm, err := Dehydrate("from a@acme.com via 10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	input := "[EMAIL-1] [EMAIL-3] [EMAIL-2] [EMAIL-3] [IPV4-1] [IPV4-7] [ERROR-404] [CVE-2024-1234]"
	got := UnknownTokens(input, tm)
	want := []string{"[EMAIL-2]", "[EMAIL-3]", "[IPV4-7]"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := UnknownTokens("[EMAIL-1]", TokenMap{}); got != nil {
		t.Errorf("empty token map: got %v", got)
	}
}

package wick

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// TokenEntry records a single redacted value and its replacement.
type TokenEntry struct {
	Original    string `json:"original"`
	Replacement string `json:"replacement"`
	Category    string `json:"category"`
	RuleID      string `json:"rule_id"`
	Count       int    `json:"count"`
}

// TokenMap holds the mapping from replacement tokens back to original values.
// It is produced by Dehydrate and consumed by Rehydrate.
type TokenMap struct {
	entries map[string]*TokenEntry // keyed by replacement token
}

// GenerateKey generates a random 256-bit AES key, returning it as a
// base64-encoded string suitable for use with Dehydrate and Rehydrate.
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generating key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// DecodeKey decodes a base64-encoded key string into raw bytes.
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 256 bits (32 bytes), got %d", len(key))
	}
	return key, nil
}

// SaveTokenMap encrypts the token map with AES-256-GCM and writes it to path.
func SaveTokenMap(tm TokenMap, key []byte, path string) error {
	data, err := json.Marshal(tm.entries)
	if err != nil {
		return fmt.Errorf("marshaling token map: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}
	return nil
}

// LoadTokenMap reads and decrypts a token map file produced by SaveTokenMap.
func LoadTokenMap(key []byte, path string) (TokenMap, error) {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return TokenMap{}, fmt.Errorf("reading token file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return TokenMap{}, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return TokenMap{}, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return TokenMap{}, fmt.Errorf("token file too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return TokenMap{}, fmt.Errorf("decrypting token map (wrong key?): %w", err)
	}

	var entries map[string]*TokenEntry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return TokenMap{}, fmt.Errorf("parsing token map: %w", err)
	}
	return TokenMap{entries: entries}, nil
}

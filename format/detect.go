// Package format provides format-aware detection and redaction for JSON, YAML, .env, and plaintext.
package format

import (
	"encoding/json"
	"strings"
)

// Format represents a detected input format.
type Format int

// Supported input formats.
const (
	FormatPlain Format = iota
	FormatJSON
	FormatYAML
	FormatEnv
)

// Detect auto-detects the format of the input content.
func Detect(content string) Format {
	trimmed := strings.TrimSpace(content)
	if len(trimmed) == 0 {
		return FormatPlain
	}

	// JSON: starts with { or [ and is valid JSON
	if (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(trimmed)) {
		return FormatJSON
	}

	// .env: all non-empty, non-comment lines match KEY=VALUE
	if looksLikeEnv(trimmed) {
		return FormatEnv
	}

	// YAML: contains "key: value" patterns
	if looksLikeYAML(trimmed) {
		return FormatYAML
	}

	return FormatPlain
}

func looksLikeEnv(content string) bool {
	lines := strings.Split(content, "\n")
	envLines := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "=") {
			return false
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		if key == "" || strings.Contains(key, " ") {
			return false
		}
		envLines++
	}
	return envLines > 0
}

func looksLikeYAML(content string) bool {
	lines := strings.Split(content, "\n")
	yamlIndicators := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "---") {
			yamlIndicators++
			continue
		}
		if strings.Contains(trimmed, ": ") || strings.HasSuffix(trimmed, ":") {
			yamlIndicators++
		}
		if strings.HasPrefix(trimmed, "- ") {
			yamlIndicators++
		}
	}
	return yamlIndicators >= 2
}

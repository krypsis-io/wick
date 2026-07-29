package redact

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/krypsis-io/wick/detect"
)

// Hash is a Replacer that produces deterministic output for correlation.
// Each value is replaced with a bracketed tag containing the finding's rule ID
// and a truncated SHA-256 hash of the original value:
//
//	admin@acme.com  →  [EMAIL:a1b2c3d4]
//	10.0.1.42       →  [IPV4:e5f6a7b8]
//
// The same input value always produces the same replacement, enabling log
// correlation across records.
//
// Security note: this is a correlation identifier, not confidential
// pseudonymization. The hash is unkeyed and truncated to 32 bits, so
// low-entropy values (emails, IPs, SSNs) can be recovered by dictionary or
// brute-force search, and collisions are possible. Do not rely on it to hide
// the underlying values; use --tokenize (reversible, encrypted token map) when
// the originals must stay secret.
var Hash Replacer = hashReplacer{}

type hashReplacer struct{}

func (hashReplacer) Replace(value string, finding detect.Finding) string {
	sum := sha256.Sum256([]byte(value))
	h := fmt.Sprintf("%x", sum[:4]) // 8 hex chars from first 4 bytes
	tag := strings.ToUpper(finding.RuleID)
	return fmt.Sprintf("[%s:%s]", tag, h)
}

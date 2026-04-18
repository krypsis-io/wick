package redact

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/krypsis-io/wick/detect"
)

// Hash is a Replacer that produces deterministic, one-way pseudonymized output.
// Each value is replaced with a bracketed tag containing the detection category
// and a truncated SHA-256 hash of the original value:
//
//	admin@acme.com  →  [EMAIL:a1b2c3d4]
//	10.0.1.42       →  [IPV4:e5f6a7b8]
//
// The same input value always produces the same replacement, enabling log
// correlation without exposing the underlying data.
var Hash Replacer = hashReplacer{}

type hashReplacer struct{}

func (hashReplacer) Replace(value string, finding detect.Finding) string {
	sum := sha256.Sum256([]byte(value))
	h := fmt.Sprintf("%x", sum[:4]) // 8 hex chars from first 4 bytes
	tag := strings.ToUpper(finding.RuleID)
	return fmt.Sprintf("[%s:%s]", tag, h)
}

package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/krypsis-io/wick/internal/detect"
)

// Summary writes a human-readable summary of findings to the given writer (typically stderr).
func Summary(w io.Writer, findings []detect.Finding) {
	if len(findings) == 0 {
		_, _ = fmt.Fprintln(w, "wick: no secrets or PII detected")
		return
	}

	byCategory := make(map[string]int)
	byRule := make(map[string]int)
	for _, f := range findings {
		byCategory[f.Category]++
		byRule[f.RuleID]++
	}

	var parts []string
	if n := byCategory["secret"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d secret(s)", n))
	}
	if n := byCategory["pii"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d PII", n))
	}
	if n := byCategory["custom"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d custom", n))
	}
	_, _ = fmt.Fprintf(w, "wick: redacted %d finding(s) — %s\n", len(findings), strings.Join(parts, ", "))

	// Detail by rule.
	rules := make([]string, 0, len(byRule))
	for r := range byRule {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	for _, r := range rules {
		_, _ = fmt.Fprintf(w, "  %s: %d\n", r, byRule[r])
	}
}

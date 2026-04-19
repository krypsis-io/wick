package detect

import (
	"regexp"
	"strconv"
	"strings"
)

type piiPattern struct {
	ID       string
	Regex    *regexp.Regexp
	Validate func(match string) bool // optional post-match validation
}

var piiPatterns = []piiPattern{
	{
		ID:    "email",
		Regex: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	},
	{
		ID: "ipv4",
		Regex: regexp.MustCompile(
			`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
		),
	},
	{
		ID: "ipv6",
		Regex: regexp.MustCompile(
			`(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}` +
				`|(?i)(?:[0-9a-f]{1,4}:){1,7}:` +
				`|(?i)(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}` +
				`|(?i)::(?:ffff:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`,
		),
	},
	{
		ID: "us-phone",
		Regex: regexp.MustCompile(
			`(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}`,
		),
	},
	{
		// Match any XXX-XX-XXXX, then validate to exclude invalid prefixes.
		ID:    "us-ssn",
		Regex: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Validate: func(match string) bool {
			parts := strings.SplitN(match, "-", 3)
			if len(parts) != 3 {
				return false
			}
			area, _ := strconv.Atoi(parts[0])
			group, _ := strconv.Atoi(parts[1])
			serial, _ := strconv.Atoi(parts[2])
			// Invalid: 000, 666, 900-999 area; 00 group; 0000 serial.
			return area != 0 && area != 666 && area < 900 &&
				group != 0 && serial != 0
		},
	},
}

// matchPII runs all PII patterns against a single line and returns findings.
// disabled is an optional set of rule IDs to skip (may be nil).
func matchPII(line string, lineNum int, disabled map[string]bool) []Finding {
	var findings []Finding
	for _, p := range piiPatterns {
		if disabled[p.ID] {
			continue
		}
		matches := p.Regex.FindAllStringIndex(line, -1)
		for _, m := range matches {
			value := line[m[0]:m[1]]
			if p.Validate != nil && !p.Validate(value) {
				continue
			}
			findings = append(findings, Finding{
				Category: "pii",
				RuleID:   p.ID,
				Value:    value,
				Start:    m[0],
				End:      m[1],
				Line:     lineNum,
			})
		}
	}
	return findings
}

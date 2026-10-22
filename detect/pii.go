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
	// InContext optionally rejects a match based on the text around it.
	InContext func(before, after string) bool
	// RescanInside searches again one byte after a match InContext rejects,
	// instead of after its end. Use it when a rejected match can hide a real
	// one: in "21 415-555-0132" the rejected "1 415-555-0132" hides the
	// phone number.
	RescanInside bool
}

// urlUserinfoPrefix matches text that ends inside the password of a URL
// (postgres://user: or postgres://user:pa), so a match starting there is
// pass@host rather than an email address.
var urlUserinfoPrefix = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s/?#@:]*:[^\s/?#@]*$`)

var piiPatterns = []piiPattern{
	{
		ID:    "email",
		Regex: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		// In scheme://user:pass@host the "pass@host" part is URL userinfo,
		// not an address. Matching it would redact the host along with the
		// password; the url-credentials rule redacts just the password.
		InContext: func(before, _ string) bool { return !urlUserinfoPrefix.MatchString(before) },
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
		// Ten digits inside a hex hash, UUID, longer number, or dotted or
		// dashed ID are not a phone number.
		InContext:    standalonePhone,
		RescanInside: true,
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

// phoneExtension matches an extension written directly after a phone
// number, as in 415-555-0132x12 or 415-555-0132ext.12.
var phoneExtension = regexp.MustCompile(`^(?i)(?:x|ext\.?)\d{1,6}`)

func standalonePhone(before, after string) bool {
	if ext := phoneExtension.FindString(after); ext != "" {
		after = after[len(ext):]
	}
	return standaloneNumber(before, after)
}

// standaloneNumber reports whether a match is not part of a longer token:
// no letter, digit, or underscore touches it, and no "-" or "." joins it to
// one (20231115-4155550132, 10.234.567.8901, 415-555-0132-77).
func standaloneNumber(before, after string) bool {
	if n := len(before); n > 0 {
		if isTokenChar(before[n-1]) {
			return false
		}
		if n > 1 && isJoiner(before[n-1]) && isTokenChar(before[n-2]) {
			return false
		}
	}
	if len(after) > 0 {
		if isTokenChar(after[0]) {
			return false
		}
		if len(after) > 1 && isJoiner(after[0]) && isTokenChar(after[1]) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func isJoiner(c byte) bool { return c == '-' || c == '.' }

// matchPII runs all PII patterns against a single line and returns findings.
// disabled is an optional set of rule IDs to skip (may be nil).
func matchPII(line string, lineNum int, disabled map[string]bool) []Finding {
	var findings []Finding
	for _, p := range piiPatterns {
		if disabled[p.ID] {
			continue
		}
		for pos := 0; pos <= len(line); {
			loc := p.Regex.FindStringIndex(line[pos:])
			if loc == nil {
				break
			}
			start, end := pos+loc[0], pos+loc[1]
			if p.InContext != nil && !p.InContext(line[:start], line[end:]) {
				pos = end
				if p.RescanInside {
					pos = start + 1
				}
				continue
			}
			pos = max(end, start+1)
			value := line[start:end]
			if p.Validate != nil && !p.Validate(value) {
				continue
			}
			findings = append(findings, Finding{
				Category: "pii",
				RuleID:   p.ID,
				Value:    value,
				Start:    start,
				End:      end,
				Line:     lineNum,
			})
		}
	}
	return findings
}

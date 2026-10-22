package detect

import "regexp"

// CookieRuleID identifies cookie values in Cookie and Set-Cookie headers.
// Session cookie names are arbitrary (connect.sid, _gh_sess, AWSALB), so
// every value is redacted and the names are kept. A Cookie header holds many
// name=value pairs and a regex rule yields one secret per match, so this rule
// parses the header in code.
const CookieRuleID = "cookie-header"

// cookieMinLen skips short values such as theme=dark or lang=en. A value this
// short is too easy to guess to work as a session credential.
const cookieMinLen = 8

// cookieHeader matches up to the start of a Cookie or Set-Cookie header value:
// raw (Cookie: a=b), quoted or escaped in logfmt and JSON ("Cookie":"a=b"),
// and as a HAR {"name": "Cookie", "value": "a=b"} entry. Group 1 or 2 is set
// for Set-Cookie, which carries one cookie followed by attributes.
var cookieHeader = regexp.MustCompile(`(?i)(?:\b(set-)?cookie\\?["']?[ \t]{0,3}(?:=>|:=|=|:)|\\?"name\\?"[ \t]*:[ \t]*\\?"(set-)?cookie\\?"[ \t]*,[ \t]*\\?"value\\?"[ \t]*:)[ \t]{0,32}\\?["']?\[?`)

// cookiePair matches one name=value pair at the start of the remaining header
// value. Group 2 holds a quoted value without its quotes, group 3 an unquoted
// one. Values stop at brackets so Go header dumps (Cookie:[a=b]) and wick's
// own [REDACTED] markers are not captured.
var cookiePair = regexp.MustCompile(`^[ \t]*([!#$%&*+.^_|~0-9A-Za-z-]+)[ \t]*=[ \t]*(?:"([^"\\;]*)"|([^;\s"'\x60\\,\[\]]*))[ \t]*`)

var cookiePlaceholder = regexp.MustCompile(`^(?:\$\{.*\}|\$[A-Za-z_]\w*|\{\{.*\}\}|<[^>]*>|[*•x.]+)$`)

// matchCookies returns a finding for each cookie value in the Cookie and
// Set-Cookie headers on line.
func (d *Detector) matchCookies(line string, lineNum int) []Finding {
	if d.disabled[CookieRuleID] {
		return nil
	}
	var findings []Finding
	pos := 0
	for pos < len(line) {
		loc := cookieHeader.FindStringSubmatchIndex(line[pos:])
		if loc == nil {
			break
		}
		setCookie := loc[2] >= 0 || loc[4] >= 0
		pos += loc[1]
		for {
			m := cookiePair.FindStringSubmatchIndex(line[pos:])
			if m == nil {
				break
			}
			vs, ve := m[4], m[5]
			if vs < 0 {
				vs, ve = m[6], m[7]
			}
			if val := line[pos+vs : pos+ve]; len(val) >= cookieMinLen &&
				!cookiePlaceholder.MatchString(val) && !replacementMarker.MatchString(val) {
				findings = append(findings, Finding{
					Category: "secret",
					RuleID:   CookieRuleID,
					Value:    val,
					Start:    pos + vs,
					End:      pos + ve,
					Line:     lineNum,
				})
			}
			pos += m[1]
			// Set-Cookie attributes (Path, Expires, ...) follow the cookie.
			if setCookie || pos >= len(line) || line[pos] != ';' {
				break
			}
			pos++
		}
	}
	return findings
}

package wick_test

import (
	"strings"
	"testing"

	"github.com/krypsis-io/wick"
)

// TestHTTPHeaderCredentials covers credentials in HTTP headers as they appear
// in curl -v output, HTTP client debug logs, and structured log lines. Opaque
// tokens with no vendor format must be redacted while the header name, the
// auth scheme, and the cookie names stay readable.
func TestHTTPHeaderCredentials(t *testing.T) {
	tok, basic, sess, key := randAlnum(t, 32), randB64(t, 21), randAlnum(t, 27), randHex(t, 16)

	cases := []struct {
		name, input, want string
	}{
		{"bearer", "Authorization: Bearer " + tok, "Authorization: Bearer [REDACTED]"},
		{"curl -v", "> Authorization: Bearer " + tok, "> Authorization: Bearer [REDACTED]"},
		{"basic", "Authorization: Basic " + basic, "Authorization: Basic [REDACTED]"},
		{"proxy basic", "> Proxy-Authorization: Basic " + basic, "> Proxy-Authorization: Basic [REDACTED]"},
		{"logfmt", `authorization="Bearer ` + tok + `"`, `authorization="Bearer [REDACTED]"`},
		{"header in logfmt value", `level=debug headers="Authorization: Bearer ` + tok + `"`, `level=debug headers="Authorization: Bearer [REDACTED]"`},
		{"json", `{"headers":{"Authorization":"Bearer ` + tok + `"}}`, `{"headers":{"Authorization":"Bearer [REDACTED]"}}`},
		{"yaml", "headers:\n  Authorization: Bearer " + tok + "\n", "headers:\n  Authorization: Bearer [REDACTED]\n"},
		{"cookie", "Cookie: session=" + sess + "; theme=dark", "Cookie: session=[REDACTED]; theme=dark"},
		{"set-cookie", "< Set-Cookie: sid=" + sess + "; Path=/; HttpOnly", "< Set-Cookie: sid=[REDACTED]; Path=/; HttpOnly"},
		{"json cookie", `{"Cookie":"sid=` + sess + `; lang=en"}`, `{"Cookie":"sid=[REDACTED]; lang=en"}`},
		{"x-api-key", "X-Api-Key: " + key, "X-Api-Key: [REDACTED]"},
		{"x-auth-token", "X-Auth-Token: " + key, "X-Auth-Token: [REDACTED]"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := wick.Redact(c.input)
			if err != nil {
				t.Fatal(err)
			}
			if out != c.want {
				t.Errorf("got  %q\nwant %q", out, c.want)
			}
		})
	}
}

// TestHTTPHeaderPlaceholders checks that header examples in docs and
// templates pass through unchanged.
func TestHTTPHeaderPlaceholders(t *testing.T) {
	inputs := []string{
		"Authorization: Bearer [REDACTED]",
		"Authorization: Bearer <token>",
		"Authorization: Bearer ${TOKEN}",
		"Authorization: Bearer $TOKEN",
		"Authorization: Bearer {{ .Values.token }}",
		"Authorization: Bearer YOUR_TOKEN_HERE",
		`curl -H "Authorization: Bearer <masked>" https://api.example.com`,
		"Send a Bearer token in the Authorization header.",
		"Cookie: session=${SESSION}; theme=dark",
		"X-Api-Key: <your-api-key>",
	}
	for _, in := range inputs {
		out, report, err := wick.Redact(in)
		if err != nil {
			t.Fatal(err)
		}
		if out != in || report.Total != 0 {
			t.Errorf("changed %q to %q (findings: %+v)", in, out, report.Findings)
		}
	}
	// Running wick on its own output must not change it again.
	in := "Authorization: Bearer " + randAlnum(t, 32) + "\nCookie: sid=" + randAlnum(t, 27)
	once, _, err := wick.Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	twice, _, err := wick.Redact(once)
	if err != nil {
		t.Fatal(err)
	}
	if once != twice || strings.Count(once, "[REDACTED]") != 2 {
		t.Errorf("not idempotent:\n%s\n---\n%s", once, twice)
	}
}

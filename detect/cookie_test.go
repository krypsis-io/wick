package detect

import (
	"reflect"
	"testing"
)

func TestCookieHeader(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	const v1, v2 = "Zx81kQp2Lm9vRt4Ws7Yb3Nc6Hq0", "7f3a9c2e1b8d4f6a0e5c9b2d"
	tests := []struct {
		name  string
		input string
		want  []string // cookie values that must be found, in order
	}{
		{"raw cookie", `Cookie: session=` + v1, []string{v1}},
		{"curl -v cookie", `> Cookie: sid=` + v1 + `; theme=dark; csrftoken=` + v2, []string{v1, v2}},
		{"set-cookie skips attributes", `Set-Cookie: sid=` + v1 + `; Path=/; Domain=example.com; Max-Age=31536000; HttpOnly`, []string{v1}},
		{"http/2 lower case", `< set-cookie: __Host-sess=` + v1 + `; Secure`, []string{v1}},
		{"quoted cookie value", `Set-Cookie: JSESSIONID="` + v1 + `"; Path=/`, []string{v1}},
		{"base64 padding", `Cookie: auth=` + v2 + `==`, []string{v2 + "=="}},
		{"logfmt header", `msg="request" headers="Cookie: sid=` + v1 + `; lang=en"`, []string{v1}},
		{"json header", `{"Cookie":"sid=` + v1 + `; theme=dark","Accept":"*/*"}`, []string{v1}},
		{"escaped json header", `msg="{\"Cookie\":\"sid=` + v1 + `\"}"`, []string{v1}},
		{"go header dump", `map[Cookie:[sid=` + v1 + `]]`, []string{v1}},
		{"har entry", `{"name": "Cookie", "value": "sid=` + v1 + `; a=` + v2 + `"}`, []string{v1, v2}},
		{"key context from json processing", `Cookie=sid=` + v1, []string{v1}},
		{"short values are kept", `Cookie: theme=dark; lang=en-US; consent=true`, nil},
		{"deleted cookie", `Set-Cookie: sid=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT`, nil},
		{"already redacted", `Cookie: sid=[REDACTED]; csrf=[COOKIE-HEADER:1a2b3c4d]`, nil},
		{"env reference", `Cookie: sid=${SESSION_COOKIE}`, nil},
		{"angle placeholder", `Cookie: sid=<session-id>`, nil},
		{"template", `Cookie: sid={{.Session}}`, nil},
		{"mask", `Cookie: sid=****************`, nil},
		{"prose", `Clear the cookie: then sign in again.`, nil},
		{"cookie name in prose", `the session cookie expired`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.Detect(tt.input) {
				if f.RuleID != CookieRuleID {
					continue
				}
				if tt.input[f.Start:f.End] != f.Value {
					t.Errorf("offsets [%d:%d] do not cover value %q", f.Start, f.End, f.Value)
				}
				got = append(got, f.Value)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCookieHeader_Disabled(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}
	d.DisableRules([]string{CookieRuleID})
	for _, f := range d.Detect(`Cookie: session=Zx81kQp2Lm9vRt4Ws7Yb3Nc6Hq0`) {
		if f.RuleID == CookieRuleID {
			t.Errorf("disabled rule still matched: %+v", f)
		}
	}
}

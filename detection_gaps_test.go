package wick_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/krypsis-io/wick"
)

// randHex and randB64 generate fresh values on every run so these cases test
// detection of real-looking secrets, not memorised fixtures.
func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func randB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return strings.NewReplacer("+", "", "/", "", "=", "").Replace(base64.StdEncoding.EncodeToString(b))
}

// randAlnum returns exactly n alphanumeric characters. Stripping +/= from
// base64 shortens it unpredictably, so draw until there are enough.
func randAlnum(t *testing.T, n int) string {
	t.Helper()
	var sb strings.Builder
	for sb.Len() < n {
		sb.WriteString(randB64(t, n))
	}
	return sb.String()[:n]
}

// TestDetectionGaps reproduces the cases from the 0.3.1 detection-gaps report:
// secrets in Portainer-style {"name","value"} env JSON, low-entropy passwords,
// and Portainer ptr_ tokens all leaked through. Every secret must be gone from
// the output, in both a mixed log and as standalone input.
func TestDetectionGaps(t *testing.T) {
	r1, r2, r3 := randHex(t, 16), randHex(t, 20), randB64(t, 24)
	gh := "ghp_" + randAlnum(t, 36)

	cases := []struct {
		name   string
		input  string
		secret string
	}{
		{"portainer env json key", `{"env":[{"name":"FINNHUB_KEY","value":"` + r1 + `"}]}`, r1},
		{"portainer env json password", `{"env":[{"name":"POSTGRES_PASSWORD","value":"` + r3 + `"}]}`, r3},
		{"name/value token", `{"name":"GITEA_TOKEN","value":"` + r2 + `"}`, r2},
		{"env key", "FINNHUB_KEY=" + r1, r1},
		{"env password", "POSTGRES_PASSWORD=" + r3, r3},
		{"weak password", "password=hunter2horse", "hunter2horse"},
		{"portainer token", "ptr_" + r3, "ptr_" + r3},
		{"github pat", gh, gh},
	}

	var mixed []string
	for _, c := range cases {
		mixed = append(mixed, c.input)
		t.Run(c.name, func(t *testing.T) {
			out, _, err := wick.Redact(c.input)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, c.secret) {
				t.Errorf("secret leaked: %s", out)
			}
		})
	}

	t.Run("mixed log", func(t *testing.T) {
		out, _, err := wick.Redact(strings.Join(mixed, "\n"))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			if strings.Contains(out, c.secret) {
				t.Errorf("%s: secret leaked in mixed log:\n%s", c.name, out)
			}
		}
	})
}

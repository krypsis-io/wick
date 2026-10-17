package detect

import (
	"strings"
	"testing"
)

// Rules with an invalid regex are skipped silently at load time, so assert
// that every rule in wick.toml actually made it into the detector.
func TestWickRules_AllCompile(t *testing.T) {
	data, err := embeddedPatterns.ReadFile("patterns/wick.toml")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := LoadSecretRulesFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Count(string(data), "[[rules]]"); len(parsed) != want {
		t.Fatalf("loaded %d wick rules, want %d: a regex likely failed to compile", len(parsed), want)
	}
}

func TestWickRules(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	tests := []struct {
		name      string
		input     string
		wantRule  string // empty means no wick rule should match
		wantValue string
	}{
		// password-assignment: no entropy threshold.
		{"low-entropy password", `password=hunter2horse`, "password-assignment", "hunter2horse"},
		{"password with symbols", `password=Xk9#mQ2!vL`, "password-assignment", "Xk9#mQ2!vL"},
		{"json password", `{"password":"hunter2horse"}`, "password-assignment", "hunter2horse"},
		{"quoted password with spaces", `db_password: "correct horse battery"`, "password-assignment", "correct horse battery"},
		{"single-quoted password", `passwd = 'letmein99'`, "password-assignment", "letmein99"},
		{"_PASS suffix", `DB_PASS=letmein99`, "password-assignment", "letmein99"},
		{"escaped json password", `{\"password\":\"hunter2horse\"}`, "password-assignment", "hunter2horse"},
		{"semicolon inside password", `password=P@ss;word1`, "password-assignment", "P@ss;word1"},
		{"comma inside password", `password=hunter,2horse`, "password-assignment", "hunter,2horse"},
		{"ampersand inside password", `password=hunter2&horse`, "password-assignment", "hunter2&horse"},
		{"env reference", `password=${DB_PASSWORD}`, "", ""},
		{"env reference with terminator", `password=${DB_PASSWORD};`, "", ""},
		{"bare env reference", `password=$DB_PASSWORD`, "", ""},
		{"template", `password: {{.Values.pw}}`, "", ""},
		{"angle placeholder", `password: <your-password>`, "", ""},
		{"mask", `password: ********`, "", ""},
		{"changeme", `PASSWORD=changeme`, "", ""},
		{"already redacted", `password=[REDACTED]`, "", ""},
		{"hash-style marker", `password=[PASSWORD-ASSIGNMENT:1a2b3c4d]`, "", ""},
		{"function call", `password=os.getenv("X")`, "", ""},
		{"shell PWD is a path", `PWD=/home/user/project`, "", ""},
		{"prose without assignment", `Password authentication failed for user postgres`, "", ""},
		{"bypass is not pass", `bypass=something1`, "", ""},
		{"too short", `password=abc12`, "", ""},

		// env-secret-assignment: upper-case secret-named vars, entropy 3.0.
		{"hex api key", `FINNHUB_KEY=6320eaa997719c9109d247c040d7414e`, "env-secret-assignment", "6320eaa997719c9109d247c040d7414e"},
		{"env token", `GITEA_TOKEN: 9f8e7d6c5b4a39281706f5e4d3c2b1a0`, "env-secret-assignment", "9f8e7d6c5b4a39281706f5e4d3c2b1a0"},
		{"ampersand inside token", `DB_TOKEN=a8f3k2&m9x7q1z4`, "env-secret-assignment", "a8f3k2&m9x7q1z4"},
		{"low-entropy word", `SORT_KEY=timestamp`, "", ""},
		{"key id is not a key", `AWS_ACCESS_KEY_ID=notasecretvalue1`, "", ""},

		// name-value-secret: keyword in a sibling field.
		{"portainer env pair", `{"name":"FINNHUB_KEY","value":"abc123def456"}`, "name-value-secret", "abc123def456"},
		{"reversed pair", `{"value":"abc123def456","name":"GITEA_TOKEN"}`, "name-value-secret", "abc123def456"},
		{"key/value pair", `{"Key":"DbSecret","Value":"abc123def456"}`, "name-value-secret", "abc123def456"},
		{"escaped pair in log", `msg="{\"name\":\"API_KEY\",\"value\":\"abc123def456\"}"`, "name-value-secret", "abc123def456"},
		{"non-secret name", `{"name":"LOG_LEVEL","value":"debugging"}`, "", ""},
		{"pair placeholder", `{"name":"DB_TOKEN","value":"${DB_TOKEN}"}`, "", ""},

		// portainer-api-token.
		{"portainer token", `ptr_CHPWxQ9aZ1kLm2Nb3Vc4Xz5Lk6Jh7Gf8Ds9Aa0=`, "portainer-api-token", "ptr_CHPWxQ9aZ1kLm2Nb3Vc4Xz5Lk6Jh7Gf8Ds9Aa0="},
		{"ptr identifier", `ptr_to_buffer_element_count_value`, "", ""},
	}

	wickRules := map[string]bool{
		"password-assignment": true, "env-secret-assignment": true,
		"name-value-secret": true, "portainer-api-token": true,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.input)
			var got *Finding
			for i := range findings {
				if wickRules[findings[i].RuleID] {
					got = &findings[i]
					break
				}
			}
			if tt.wantRule == "" {
				if got != nil {
					t.Errorf("expected no wick rule match, got %s=%q", got.RuleID, got.Value)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %s, got findings: %+v", tt.wantRule, findings)
			}
			if got.RuleID != tt.wantRule || got.Value != tt.wantValue {
				t.Errorf("got %s=%q, want %s=%q", got.RuleID, got.Value, tt.wantRule, tt.wantValue)
			}
		})
	}
}

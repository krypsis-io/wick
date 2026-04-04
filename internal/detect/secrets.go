package detect

import (
	"embed"
	"math"
	"regexp"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

//go:embed patterns/gitleaks.toml
var embeddedPatterns embed.FS

// gitleaksConfig is the top-level TOML structure.
type gitleaksConfig struct {
	Title     string         `toml:"title"`
	Rules     []gitleaksRule `toml:"rules"`
	Allowlist *gitleaksAllow `toml:"allowlist"`
}

type gitleaksRule struct {
	ID          string          `toml:"id"`
	Description string          `toml:"description"`
	Regex       string          `toml:"regex"`
	Keywords    []string        `toml:"keywords"`
	Entropy     float64         `toml:"entropy"`
	SecretGroup int             `toml:"secretGroup"`
	Path        string          `toml:"path"`
	Allowlists  []gitleaksAllow `toml:"allowlists"`
}

type gitleaksAllow struct {
	Description string   `toml:"description"`
	Paths       []string `toml:"paths"`
	Regexes     []string `toml:"regexes"`
	StopWords   []string `toml:"stopwords"`
	RegexTarget string   `toml:"regexTarget"`
	Condition   string   `toml:"condition"`
}

// SecretRule is a compiled, ready-to-match secret detection rule.
type SecretRule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	Keywords    []string // lowercase
	Entropy     float64
	SecretGroup int
	Allowlists  []compiledAllow
	Multiline   bool // true if the regex spans multiple lines (contains \s)
}

type compiledAllow struct {
	Regexes     []*regexp.Regexp
	StopWords   []string
	RegexTarget string // "line" or "match"
	Condition   string // "AND" or "OR"
}

// LoadSecretRules parses the embedded gitleaks.toml and returns compiled rules.
func LoadSecretRules() ([]SecretRule, error) {
	data, err := embeddedPatterns.ReadFile("patterns/gitleaks.toml")
	if err != nil {
		return nil, err
	}
	return parseGitleaksTOML(data)
}

// LoadSecretRulesFromBytes parses a gitleaks-compatible TOML and returns compiled rules.
func LoadSecretRulesFromBytes(data []byte) ([]SecretRule, error) {
	return parseGitleaksTOML(data)
}

func parseGitleaksTOML(data []byte) ([]SecretRule, error) {
	var cfg gitleaksConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	rules := make([]SecretRule, 0, len(cfg.Rules))
	for _, raw := range cfg.Rules {
		if raw.Regex == "" {
			// Path-only rules (e.g., pkcs12-file) don't match content.
			continue
		}
		re, err := regexp.Compile(raw.Regex)
		if err != nil {
			// Skip rules with invalid regexes rather than failing entirely.
			continue
		}

		keywords := make([]string, len(raw.Keywords))
		for i, kw := range raw.Keywords {
			keywords[i] = strings.ToLower(kw)
		}

		var allows []compiledAllow
		for _, a := range raw.Allowlists {
			ca := compiledAllow{
				StopWords:   a.StopWords,
				RegexTarget: a.RegexTarget,
				Condition:   a.Condition,
			}
			for _, r := range a.Regexes {
				if compiled, err := regexp.Compile(r); err == nil {
					ca.Regexes = append(ca.Regexes, compiled)
				}
			}
			allows = append(allows, ca)
		}

		rules = append(rules, SecretRule{
			ID:          raw.ID,
			Description: raw.Description,
			Regex:       re,
			Keywords:    keywords,
			Entropy:     raw.Entropy,
			SecretGroup: raw.SecretGroup,
			Allowlists:  allows,
			Multiline:   strings.Contains(raw.Regex, `\s`) || strings.Contains(raw.Regex, `\n`),
		})
	}
	return rules, nil
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// matchSecretRules runs all secret rules against a single line and returns findings.
func matchSecretRules(rules []SecretRule, line string, lineNum int) []Finding {
	lower := strings.ToLower(line)
	var findings []Finding

	for i := range rules {
		rule := &rules[i]

		// Keyword pre-filter: skip if none of the rule's keywords appear.
		if len(rule.Keywords) > 0 {
			found := false
			for _, kw := range rule.Keywords {
				if strings.Contains(lower, kw) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		matches := rule.Regex.FindAllStringSubmatchIndex(line, -1)
		for _, match := range matches {
			// Determine the secret value based on secretGroup.
			group := rule.SecretGroup
			startIdx := group * 2
			endIdx := startIdx + 1
			if startIdx >= len(match) || match[startIdx] < 0 {
				startIdx = 0
				endIdx = 1
			}
			start := match[startIdx]
			end := match[endIdx]
			value := line[start:end]

			// Entropy check.
			if rule.Entropy > 0 && shannonEntropy(value) < rule.Entropy {
				continue
			}

			// Allowlist check.
			if isAllowed(rule.Allowlists, line, value) {
				continue
			}

			findings = append(findings, Finding{
				Category: "secret",
				RuleID:   rule.ID,
				Value:    value,
				Start:    start,
				End:      end,
				Line:     lineNum,
			})
		}
	}
	return findings
}

func isAllowed(allows []compiledAllow, line, value string) bool {
	for _, a := range allows {
		target := value
		if a.RegexTarget == "line" {
			target = line
		}

		if a.Condition == "AND" {
			allMatch := true
			for _, re := range a.Regexes {
				if !re.MatchString(target) {
					allMatch = false
					break
				}
			}
			if len(a.Regexes) > 0 && allMatch {
				return true
			}
		} else {
			// Default OR
			for _, re := range a.Regexes {
				if re.MatchString(target) {
					return true
				}
			}
		}

		for _, sw := range a.StopWords {
			if strings.Contains(strings.ToLower(value), strings.ToLower(sw)) {
				return true
			}
		}
	}
	return false
}

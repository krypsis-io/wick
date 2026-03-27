package detect

import (
	"fmt"
	"regexp"
)

// CustomPattern is a user-defined detection pattern from .wick.yaml.
type CustomPattern struct {
	Name        string `yaml:"name"`
	Regex       string `yaml:"regex"`
	Replacement string `yaml:"replacement,omitempty"` // TODO: wire per-pattern replacements into redact.Redact
}

type compiledCustom struct {
	Name        string
	Regex       *regexp.Regexp
	Replacement string
}

func compileCustomPatterns(patterns []CustomPattern) ([]compiledCustom, error) {
	compiled := make([]compiledCustom, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p.Name, err)
		}
		compiled = append(compiled, compiledCustom{
			Name:        p.Name,
			Regex:       re,
			Replacement: p.Replacement,
		})
	}
	return compiled, nil
}

func matchCustom(patterns []compiledCustom, line string, lineNum int) []Finding {
	var findings []Finding
	for _, p := range patterns {
		matches := p.Regex.FindAllStringIndex(line, -1)
		for _, m := range matches {
			findings = append(findings, Finding{
				Category: "custom",
				RuleID:   p.Name,
				Value:    line[m[0]:m[1]],
				Start:    m[0],
				End:      m[1],
				Line:     lineNum,
			})
		}
	}
	return findings
}

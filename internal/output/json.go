package output

import (
	"encoding/json"

	"github.com/krypsis-io/wick/internal/detect"
)

type jsonOutput struct {
	Redacted string        `json:"redacted"`
	Findings []jsonFinding `json:"findings"`
	Summary  jsonSummary   `json:"summary"`
}

type jsonFinding struct {
	Category string `json:"category"`
	RuleID   string `json:"rule_id"`
	Line     int    `json:"line"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

type jsonSummary struct {
	Total   int            `json:"total"`
	ByType  map[string]int `json:"by_type"`
}

// JSON formats the redacted output and findings as a JSON string.
func JSON(redacted string, findings []detect.Finding) (string, error) {
	jf := make([]jsonFinding, len(findings))
	byType := make(map[string]int)

	for i, f := range findings {
		jf[i] = jsonFinding{
			Category: f.Category,
			RuleID:   f.RuleID,
			Line:     f.Line,
			Start:    f.Start,
			End:      f.End,
		}
		byType[f.RuleID]++
	}

	out := jsonOutput{
		Redacted: redacted,
		Findings: jf,
		Summary: jsonSummary{
			Total:  len(findings),
			ByType: byType,
		},
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

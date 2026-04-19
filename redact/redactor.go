// Package redact replaces detected findings with configurable replacement strings.
package redact

import (
	"sort"

	"github.com/krypsis-io/wick/detect"
)

// Redact replaces all finding matches in the input line using the given Replacer.
// Findings must all belong to the same line. Overlapping ranges are merged.
func Redact(line string, findings []detect.Finding, replacer Replacer) string {
	if len(findings) == 0 {
		return line
	}

	// Build replacement strings per finding before merging spans.
	type replacementSpan struct {
		start       int
		end         int
		replacement string
	}

	spans := make([]replacementSpan, len(findings))
	for i, f := range findings {
		spans[i] = replacementSpan{
			start:       f.Start,
			end:         f.End,
			replacement: replacer.Replace(line[f.Start:f.End], f),
		}
	}

	// Sort and merge overlapping spans. For merged spans, use the first replacement.
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].start < spans[j].start
	})
	merged := []replacementSpan{spans[0]}
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
		} else {
			merged = append(merged, s)
		}
	}

	var result []byte
	prev := 0
	for _, s := range merged {
		result = append(result, line[prev:s.start]...)
		result = append(result, s.replacement...)
		prev = s.end
	}
	result = append(result, line[prev:]...)
	return string(result)
}


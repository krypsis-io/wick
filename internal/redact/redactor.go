// Package redact replaces detected findings with configurable replacement strings.
package redact

import (
	"sort"

	"github.com/krypsis-io/wick/internal/detect"
)

// span represents a byte range to redact within a single line.
type span struct {
	start int
	end   int
}

// Redact replaces all finding matches in the input line with the style's replacement string.
// Findings must all belong to the same line. Overlapping ranges are merged.
func Redact(line string, findings []detect.Finding, style Style) string {
	if len(findings) == 0 {
		return line
	}

	spans := make([]span, len(findings))
	for i, f := range findings {
		spans[i] = span{start: f.Start, end: f.End}
	}
	merged := mergeSpans(spans)

	replacement := style.Replacement()
	var result []byte
	prev := 0
	for _, s := range merged {
		result = append(result, line[prev:s.start]...)
		result = append(result, replacement...)
		prev = s.end
	}
	result = append(result, line[prev:]...)
	return string(result)
}

// mergeSpans sorts and merges overlapping byte ranges.
func mergeSpans(spans []span) []span {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].start < spans[j].start
	})
	merged := []span{spans[0]}
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
	return merged
}

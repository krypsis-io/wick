package wick

// Report summarizes the results of a redaction operation.
type Report struct {
	// Findings is the list of individual detections.
	Findings []Finding

	// Total is the number of findings.
	Total int

	// ByRule maps rule IDs to their occurrence count.
	ByRule map[string]int
}

// Finding represents a single detected secret, PII, or custom pattern match.
type Finding struct {
	// Category is the detection category: "secret", "pii", or "custom".
	Category string

	// RuleID identifies the specific detection rule (e.g., "aws-access-token", "email").
	RuleID string

	// Value is the matched sensitive text.
	Value string

	// Start is the byte offset within the line where the match begins.
	Start int

	// End is the byte offset within the line where the match ends (exclusive).
	End int

	// Line is the 1-based line number of the match.
	Line int
}

package detect

// Finding represents a detected secret or PII match in the input.
type Finding struct {
	Category string // "secret", "pii"
	RuleID   string // e.g., "aws-access-token", "email"
	Value    string // the matched sensitive value
	Start    int    // byte offset in the line
	End      int    // byte offset in the line (exclusive)
	Line     int    // 1-based line number
}

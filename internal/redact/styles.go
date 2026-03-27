package redact

// Style determines how redacted values are replaced.
type Style int

// Built-in redaction styles.
const (
	StyleRedacted Style = iota // [REDACTED]
	StyleStars                 // ***
)

// CustomStyle returns a Style that uses a custom replacement string.
// Stored as a negative value to distinguish from named styles.
// Use Replacement() to get the actual string.
func CustomStyle() Style { return Style(-1) }

var customReplacement string

// SetCustomReplacement sets the string used by CustomStyle.
func SetCustomReplacement(s string) {
	customReplacement = s
}

// Replacement returns the replacement string for a style.
func (s Style) Replacement() string {
	switch s {
	case StyleStars:
		return "***"
	case Style(-1):
		return customReplacement
	default:
		return "[REDACTED]"
	}
}

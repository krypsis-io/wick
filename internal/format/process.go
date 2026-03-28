package format

import (
	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// Process auto-detects the input format and applies the appropriate redaction strategy.
func Process(input string, detector *detect.Detector, style redact.Style) (string, []detect.Finding) {
	detected := Detect(input)
	switch detected {
	case FormatJSON:
		return ProcessJSON(input, detector, style)
	case FormatYAML:
		return ProcessYAML(input, detector, style)
	case FormatEnv:
		return ProcessEnv(input, detector, style)
	default:
		return ProcessPlain(input, detector, style)
	}
}

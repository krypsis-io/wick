package format

import (
	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
)

// Process auto-detects the input format and applies the appropriate redaction strategy.
func Process(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
	detected := Detect(input)
	switch detected {
	case FormatJSON:
		return ProcessJSON(input, detector, replacer)
	case FormatYAML:
		return ProcessYAML(input, detector, replacer)
	case FormatEnv:
		return ProcessEnv(input, detector, replacer)
	default:
		return ProcessPlain(input, detector, replacer)
	}
}

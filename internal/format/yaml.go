package format

import (
	"bytes"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
	"gopkg.in/yaml.v3"
)

// ProcessYAML parses YAML, redacts string values, and preserves structure/comments.
func ProcessYAML(input string, detector *detect.Detector, style redact.Style) (string, []detect.Finding) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(input), &doc); err != nil {
		return ProcessPlain(input, detector, style)
	}

	var allFindings []detect.Finding
	walkYAML(&doc, detector, style, &allFindings)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return ProcessPlain(input, detector, style)
	}
	enc.Close()
	return buf.String(), allFindings
}

func walkYAML(node *yaml.Node, d *detect.Detector, style redact.Style, findings *[]detect.Finding) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walkYAML(child, d, style, findings)
		}
	case yaml.MappingNode:
		// Content alternates: key, value, key, value...
		for i := 0; i+1 < len(node.Content); i += 2 {
			// Don't redact keys, only values.
			walkYAML(node.Content[i+1], d, style, findings)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			walkYAML(child, d, style, findings)
		}
	case yaml.ScalarNode:
		if node.Tag == "!!str" || node.Tag == "" {
			if result, changed := redactString(node.Value, d, style, findings); changed {
				node.Value = result
			}
		}
	}
}

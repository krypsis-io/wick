package format

import (
	"bytes"

	"github.com/krypsis-io/wick/internal/detect"
	"github.com/krypsis-io/wick/internal/redact"
	"gopkg.in/yaml.v3"
)

// ProcessYAML parses YAML, redacts string values, and preserves structure/comments.
func ProcessYAML(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(input), &doc); err != nil {
		return ProcessPlain(input, detector, replacer)
	}

	var allFindings []detect.Finding
	walkYAML(&doc, detector, replacer, &allFindings)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return ProcessPlain(input, detector, replacer)
	}
	if err := enc.Close(); err != nil {
		return ProcessPlain(input, detector, replacer)
	}
	return buf.String(), allFindings
}

func walkYAML(node *yaml.Node, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walkYAML(child, d, replacer, findings)
		}
	case yaml.MappingNode:
		// Content alternates: key, value, key, value...
		for i := 0; i+1 < len(node.Content); i += 2 {
			// Don't redact keys, only values.
			walkYAML(node.Content[i+1], d, replacer, findings)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			walkYAML(child, d, replacer, findings)
		}
	case yaml.ScalarNode:
		if node.Tag == "!!str" || node.Tag == "" {
			if result, changed := redactString(node.Value, d, replacer, findings); changed {
				node.Value = result
			}
		}
	}
}

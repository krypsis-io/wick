package format

import (
	"bytes"

	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
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
		name, isPair := pairName(func(k string) (string, bool) {
			for i := 0; i+1 < len(node.Content); i += 2 {
				if node.Content[i].Value == k && isStringScalar(node.Content[i+1]) {
					return node.Content[i+1].Value, true
				}
			}
			return "", false
		})
		// Content alternates: key, value, key, value...
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			// Don't redact keys, only values. For scalar string values, pass the
			// key as detection context so keyword-anchored rules match.
			if isStringScalar(valNode) {
				redactFn := redactKeyedString
				ctxKey := keyNode.Value
				if isPair && isPairValueKey(keyNode.Value) {
					redactFn, ctxKey = redactPairValue, name
				}
				if result, changed := redactFn(ctxKey, valNode.Value, d, replacer, findings); changed {
					valNode.Value = result
				}
				continue
			}
			walkYAML(valNode, d, replacer, findings)
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

func isStringScalar(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && (n.Tag == "!!str" || n.Tag == "")
}

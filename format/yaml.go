package format

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
	"gopkg.in/yaml.v3"
)

// ProcessYAML parses YAML, redacts string values, and preserves structure/comments.
func ProcessYAML(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
	docs, err := decodeYAMLStream(input)
	if err != nil {
		return ProcessPlain(input, detector, replacer)
	}

	var allFindings []detect.Finding
	for _, doc := range docs {
		walkYAML(doc, detector, replacer, &allFindings)
	}

	out, err := encodeYAMLStream(docs)
	if err != nil {
		return ProcessPlain(input, detector, replacer)
	}
	return out, allFindings
}

// decodeYAMLStream decodes every document in input; yaml.Unmarshal would
// keep only the first.
func decodeYAMLStream(input string) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(input))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		docs = append(docs, &doc)
	}
	if len(docs) == 0 {
		return nil, errors.New("no YAML documents")
	}
	return docs, nil
}

func encodeYAMLStream(docs []*yaml.Node) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	for _, doc := range docs {
		if err := enc.Encode(doc); err != nil {
			return "", err
		}
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
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

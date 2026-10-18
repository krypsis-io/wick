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
// keep only the first. Input with an unquoted mapping key containing
// whitespace is rejected: that is how log lines with ": " parse, and
// re-encoding them would rewrite the text (long keys become "? key"). A
// stream with a Kubernetes Secret in it is kept as YAML regardless, since
// its values are only recognized structurally.
func decodeYAMLStream(input string) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(input))
	var docs []*yaml.Node
	prose, secret := false, false
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		prose = prose || hasProseKey(&doc)
		secret = secret || hasSecret(&doc)
		docs = append(docs, &doc)
	}
	if len(docs) == 0 {
		return nil, errors.New("no YAML documents")
	}
	if prose && !secret {
		return nil, errors.New("mapping key contains whitespace; not treating input as YAML")
	}
	return docs, nil
}

func hasProseKey(n *yaml.Node) bool {
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == yaml.ScalarNode && k.Style == 0 && strings.ContainsAny(k.Value, " \t") {
				return true
			}
		}
	}
	for _, c := range n.Content {
		if hasProseKey(c) {
			return true
		}
	}
	return false
}

func hasSecret(n *yaml.Node) bool {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "kind" && n.Content[i+1].Value == "Secret" {
				return true
			}
		}
	}
	for _, c := range n.Content {
		if hasSecret(c) {
			return true
		}
	}
	return false
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
		kind := ""
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "kind" && isStringScalar(node.Content[i+1]) {
				kind = node.Content[i+1].Value
			}
		}
		// Content alternates: key, value, key, value...
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			key := keyNode.Value
			if payload := resolveAlias(valNode); payload.Kind == yaml.MappingNode && isSecretPayload(kind, key) {
				redactSecretPayloadYAML(payload, d, replacer, findings)
				continue
			}
			// A key can hold a secret too, e.g. a token used as a map key.
			if isStringScalar(keyNode) {
				if result, changed := redactString(keyNode.Value, d, replacer, findings); changed {
					keyNode.Value = result
				}
			}
			// For scalar string values, pass the key as detection context so
			// keyword-anchored rules match.
			if isStringScalar(valNode) {
				if key == lastAppliedAnnotation {
					if result, changed := redactLastApplied(valNode.Value, d, replacer, findings); changed {
						valNode.Value = result
					}
				}
				redactFn := redactKeyedString
				ctxKey := key
				if isPair && isPairValueKey(key) {
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

func redactSecretPayloadYAML(payload *yaml.Node, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) {
	for i := 0; i+1 < len(payload.Content); i += 2 {
		valNode := resolveAlias(payload.Content[i+1])
		if valNode.Kind != yaml.ScalarNode {
			walkYAML(valNode, d, replacer, findings)
			continue
		}
		// Unquoted stringData values such as PIN: 1234 are ints to YAML but
		// still secrets.
		if result, changed := redactSecretPayloadValue(valNode.Value, d, replacer, findings); changed {
			valNode.Value, valNode.Tag = result, "!!str"
		}
	}
}

// resolveAlias returns the node an alias refers to. A Secret value given as
// an alias is redacted at its anchor, so the value appears nowhere in the
// output, including under the anchor's own key.
func resolveAlias(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

func isStringScalar(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && (n.Tag == "!!str" || n.Tag == "")
}

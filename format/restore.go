package format

import (
	"bytes"
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

// Restore replaces each token in input with its original value. For JSON and
// YAML the original is encoded for the document, so values that need escaping
// (newlines, quotes) still produce a valid document.
func Restore(input string, originals map[string]string) string {
	if len(originals) == 0 {
		return input
	}
	plain := newReplacer(originals, func(s string) string { return s })
	switch Detect(input) {
	case FormatJSON:
		// Tokens only ever stand for parts of decoded string values, so
		// escaping the original as string content is correct at any nesting.
		return newReplacer(originals, jsonStringContent).Replace(input)
	case FormatYAML:
		if out, ok := restoreYAML(input, plain); ok {
			return out
		}
	}
	return plain.Replace(input)
}

func newReplacer(originals map[string]string, encode func(string) string) *strings.Replacer {
	pairs := make([]string, 0, 2*len(originals))
	for token, orig := range originals {
		pairs = append(pairs, token, encode(orig))
	}
	return strings.NewReplacer(pairs...)
}

// jsonStringContent returns s escaped for use between the quotes of a JSON
// string, without HTML escaping.
func jsonStringContent(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return s
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	return out[1 : len(out)-1]
}

// restoreYAML substitutes originals into scalar values and re-encodes the
// documents. The final plain pass covers tokens in keys and comments.
func restoreYAML(input string, plain *strings.Replacer) (string, bool) {
	docs, err := decodeYAMLStream(input)
	if err != nil {
		return "", false
	}
	changed := false
	for _, doc := range docs {
		changed = restoreYAMLNode(doc, plain) || changed
	}
	if !changed {
		return plain.Replace(input), true
	}
	out, err := encodeYAMLStream(docs)
	if err != nil {
		return "", false
	}
	return plain.Replace(out), true
}

func restoreYAMLNode(n *yaml.Node, plain *strings.Replacer) bool {
	changed := false
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			changed = restoreYAMLNode(c, plain) || changed
		}
	case yaml.SequenceNode:
		// An unquoted token such as [EMAIL-1] parses as a one-item flow
		// sequence; turn it back into the scalar it stood for.
		if n.Style&yaml.FlowStyle != 0 && len(n.Content) == 1 && n.Content[0].Kind == yaml.ScalarNode {
			token := "[" + n.Content[0].Value + "]"
			if v := plain.Replace(token); v != token {
				*n = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
				return true
			}
		}
		for _, c := range n.Content {
			changed = restoreYAMLNode(c, plain) || changed
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			changed = restoreYAMLNode(n.Content[i], plain) || changed
		}
	case yaml.ScalarNode:
		if !isStringScalar(n) {
			return false
		}
		if v := plain.Replace(n.Value); v != n.Value {
			n.Value = v
			// The token's style (usually single-quoted) may not fit the
			// original, e.g. a multi-line value.
			n.Style = 0
			changed = true
		}
	}
	return changed
}

package format

import (
	"bytes"
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

// Restore puts original values back in place of tokens in input, using
// originals (token → original value). Plain substitution is not enough for
// structured input: an original containing a newline, quote, or backslash
// would produce invalid JSON or YAML wherever its token sat inside a string.
//
//   - JSON: each original is escaped as JSON string content before
//     substitution, so the document's formatting is otherwise untouched.
//     Tokens only ever replace parts of decoded string values, so the
//     escaped form is correct even for JSON nested inside a JSON string.
//   - YAML: originals are substituted into the parsed scalar values and the
//     document is re-encoded, letting the encoder pick a style (for example
//     a literal block for multi-line values) that represents them exactly.
//   - Anything else: plain substitution.
func Restore(input string, originals map[string]string) string {
	if len(originals) == 0 {
		return input
	}
	plain := newReplacer(originals, func(s string) string { return s })
	switch Detect(input) {
	case FormatJSON:
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
// string, without HTML escaping so characters like < and & stay as written.
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

// restoreYAML substitutes originals into the string scalars of a YAML
// document and re-encodes it. A final plain pass covers tokens outside
// scalar values (keys, comments). It reports false if input is not YAML.
func restoreYAML(input string, plain *strings.Replacer) (string, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(input), &doc); err != nil {
		return "", false
	}
	if !restoreYAMLNode(&doc, plain) {
		return plain.Replace(input), true
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", false
	}
	if err := enc.Close(); err != nil {
		return "", false
	}
	return plain.Replace(buf.String()), true
}

// restoreYAMLNode replaces tokens in string scalar values below n and
// reports whether any value changed.
func restoreYAMLNode(n *yaml.Node, plain *strings.Replacer) bool {
	changed := false
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			changed = restoreYAMLNode(c, plain) || changed
		}
	case yaml.MappingNode:
		// Content alternates key, value; only values carry tokens.
		for i := 1; i < len(n.Content); i += 2 {
			changed = restoreYAMLNode(n.Content[i], plain) || changed
		}
	case yaml.ScalarNode:
		if !isStringScalar(n) {
			return false
		}
		if v := plain.Replace(n.Value); v != n.Value {
			n.Value = v
			// The style chosen for the token (often single-quoted, because
			// [TOKEN] would otherwise parse as a sequence) may not fit the
			// original, e.g. a multi-line key. Let the encoder choose.
			n.Style = 0
			changed = true
		}
	}
	return changed
}

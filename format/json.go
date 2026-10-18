package format

import (
	"encoding/json"
	"strings"

	"github.com/krypsis-io/wick/detect"
	"github.com/krypsis-io/wick/redact"
)

// redactString detects and redacts secrets/PII in a string value line by line,
// so that multi-line strings have correct byte offsets for redaction.
func redactString(val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	val, changed := redactMultilineInto(val, d, replacer, findings)
	lines := strings.Split(val, "\n")
	for i, line := range lines {
		found := d.Detect(line)
		if len(found) > 0 {
			for j := range found {
				found[j].Line = i + 1
			}
			*findings = append(*findings, found...)
			lines[i] = redact.Redact(line, found, replacer)
			changed = true
		}
	}
	if changed {
		return strings.Join(lines, "\n"), true
	}
	return val, false
}

// redactMultilineInto runs the multiline rules over a whole string value
// before it is split into lines, so a PEM block stored as a YAML block scalar,
// a JSON string, or an escaped JSON document inside a string (such as
// kubectl's last-applied-configuration annotation) is still caught. The
// line-by-line pass that follows sees the already-redacted value.
func redactMultilineInto(val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	red, found := redactMultiline(val, d, replacer)
	if len(found) == 0 {
		return val, false
	}
	*findings = append(*findings, found...)
	return red, true
}

// detectContext is synthetic text placed around a value so that rules which
// need the key name (or the surrounding quotes) can match. Only matches that
// fall entirely within the value are kept.
type detectContext struct{ prefix, suffix string }

// keyContexts returns the contexts for a value under key. The parser has
// already stripped the value's quotes, so the value is tried both bare and
// re-quoted: bare for rules that stop at whitespace, quoted so a value with
// spaces (e.g. a passphrase) is captured whole.
func keyContexts(key string) []detectContext {
	return []detectContext{{key + "=", ""}, {key + `="`, `"`}}
}

// redactKeyedString redacts a scalar value that appears under the mapping key
// key. The key is prepended as detection context on the first line so that
// keyword-anchored rules (e.g. aws_secret_access_key, whose regex requires the
// key name adjacent to the value) still fire, but only the value is redacted.
// Offsets from matches within the value are translated back to be value-relative.
func redactKeyedString(key, val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	if key == "" {
		return redactString(val, d, replacer, findings)
	}
	return redactInContext(keyContexts(key), val, d, replacer, findings)
}

// redactPairValue redacts the value half of a {name: ..., value: ...} pair
// (Portainer, Kubernetes env, ECS, CloudFormation tags). The sibling name is
// the real key, so it is used as detection context instead of "value": as
// NAME=value for keyword-anchored rules, and as the JSON pair itself so the
// name-value-secret rule can match regardless of the value's entropy.
func redactPairValue(name, val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	contexts := keyContexts(name)
	if !strings.ContainsAny(name, `"\`) {
		contexts = append(contexts, detectContext{`{"name":"` + name + `","value":"`, `"`})
	}
	return redactInContext(contexts, val, d, replacer, findings)
}

// redactInContext detects against each context wrapped around the first line
// of val, keeping only matches that fall entirely within the value, remapped
// to value-relative offsets. Where findings from different contexts overlap,
// the widest wins so a value is counted once and never partially redacted.
// Later lines are detected without context.
func redactInContext(contexts []detectContext, val string, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) (string, bool) {
	val, changed := redactMultilineInto(val, d, replacer, findings)
	lines := strings.Split(val, "\n")
	for i, line := range lines {
		var found []detect.Finding
		if i == 0 {
			for _, c := range contexts {
				for _, f := range d.Detect(c.prefix + line + c.suffix) {
					if f.Start < len(c.prefix) || f.End > len(c.prefix)+len(line) {
						continue // match touches the synthetic context; ignore it
					}
					f.Start -= len(c.prefix)
					f.End -= len(c.prefix)
					found = mergeWidest(found, f)
				}
			}
		} else {
			found = d.Detect(line)
		}
		if len(found) > 0 {
			for j := range found {
				found[j].Line = i + 1
			}
			*findings = append(*findings, found...)
			lines[i] = redact.Redact(line, found, replacer)
			changed = true
		}
	}
	if changed {
		return strings.Join(lines, "\n"), true
	}
	return val, false
}

// mergeWidest adds f to kept unless an overlapping finding already covers at
// least as much; a wider f replaces the narrower findings it overlaps.
func mergeWidest(kept []detect.Finding, f detect.Finding) []detect.Finding {
	out := make([]detect.Finding, 0, len(kept)+1)
	for _, k := range kept {
		if f.Start < k.End && k.Start < f.End {
			if k.End-k.Start >= f.End-f.Start {
				return kept
			}
			continue
		}
		out = append(out, k)
	}
	return append(out, f)
}

// pairName returns the sibling name of a {name, value} style object, given a
// lookup of the object's string fields. It reports false when the object has
// no value field or no name/key field.
func pairName(field func(string) (string, bool)) (string, bool) {
	if _, ok := field("value"); !ok {
		if _, ok := field("Value"); !ok {
			return "", false
		}
	}
	for _, k := range []string{"name", "Name", "key", "Key"} {
		if n, ok := field(k); ok && n != "" {
			return n, true
		}
	}
	return "", false
}

// isPairValueKey reports whether k is the value field of a {name, value} pair.
func isPairValueKey(k string) bool {
	return k == "value" || k == "Value"
}

// ProcessJSON parses JSON, redacts string values, and preserves structure.
func ProcessJSON(input string, detector *detect.Detector, replacer redact.Replacer) (string, []detect.Finding) {
	var data any
	dec := json.NewDecoder(strings.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		// Fall back to plaintext if JSON parsing fails.
		return ProcessPlain(input, detector, replacer)
	}

	var allFindings []detect.Finding
	redacted := walkJSON(data, detector, replacer, &allFindings)

	indent := indentOf(input)
	var (
		out []byte
		err error
	)
	if indent == "" {
		out, err = json.Marshal(redacted)
	} else {
		out, err = json.MarshalIndent(redacted, "", indent)
	}
	if err != nil {
		return ProcessPlain(input, detector, replacer)
	}
	return string(out), allFindings
}

func walkJSON(v any, d *detect.Detector, replacer redact.Replacer, findings *[]detect.Finding) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any, len(val))
		name, isPair := pairName(func(k string) (string, bool) {
			s, ok := val[k].(string)
			return s, ok
		})
		for k, child := range val {
			// Redact string values with their key as detection context so
			// keyword-anchored rules match; recurse into everything else.
			if s, ok := child.(string); ok {
				redactFn := redactKeyedString
				ctxKey := k
				if isPair && isPairValueKey(k) {
					redactFn, ctxKey = redactPairValue, name
				}
				if red, changed := redactFn(ctxKey, s, d, replacer, findings); changed {
					result[k] = red
				} else {
					result[k] = s
				}
				continue
			}
			result[k] = walkJSON(child, d, replacer, findings)
		}
		return result
	case []any:
		result := make([]any, len(val))
		for i, child := range val {
			result[i] = walkJSON(child, d, replacer, findings)
		}
		return result
	case string:
		if result, changed := redactString(val, d, replacer, findings); changed {
			return result
		}
		return val
	default:
		return val
	}
}

// indentOf tries to detect the indentation used in the original JSON.
// Returns "" for single-line/minified input.
func indentOf(input string) string {
	lines := strings.Split(input, "\n")
	if len(lines) <= 1 {
		return ""
	}
	second := lines[1]
	trimmed := strings.TrimLeft(second, " \t")
	if len(second) > len(trimmed) {
		return second[:len(second)-len(trimmed)]
	}
	return ""
}

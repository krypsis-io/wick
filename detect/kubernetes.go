package detect

import "regexp"

// KubernetesSecretRuleID identifies values from the data or stringData of a
// Kubernetes Secret. Their key names are arbitrary (DATABASE_URL, config.json)
// and data values are base64, so no pattern can recognize them; their position
// in the document is what marks them as secret.
const KubernetesSecretRuleID = "kubernetes-secret"

// replacementMarker matches the output of wick's replacers, so redacting an
// already-redacted document leaves it unchanged.
var replacementMarker = regexp.MustCompile(`^\[[A-Z0-9_-]+(?:[:-][0-9a-f]+|-\d+)?\]$`)

// KubernetesSecretValue returns a finding covering all of val, a value from
// the data or stringData of a Kubernetes Secret. It reports false for empty
// values, wick's own replacement markers, allowlisted values, and when the
// kubernetes-secret rule is disabled.
func (d *Detector) KubernetesSecretValue(val string) (Finding, bool) {
	if val == "" || d.disabled[KubernetesSecretRuleID] || replacementMarker.MatchString(val) || d.isProjectAllowed(val) {
		return Finding{}, false
	}
	return Finding{
		Category: "secret",
		RuleID:   KubernetesSecretRuleID,
		Value:    val,
		End:      len(val),
		Line:     1,
	}, true
}

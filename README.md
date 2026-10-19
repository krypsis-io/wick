<div align="center">

# wick

**Redact secrets and PII from logs, config files, and command output.**

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Release](https://img.shields.io/github/v/release/krypsis-io/wick?sort=semver&color=blue)](https://github.com/krypsis-io/wick/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/krypsis-io/wick)](go.mod)
[![Go Reference](https://pkg.go.dev/badge/github.com/krypsis-io/wick.svg)](https://pkg.go.dev/github.com/krypsis-io/wick)
[![Go Report Card](https://goreportcard.com/badge/github.com/krypsis-io/wick)](https://goreportcard.com/report/github.com/krypsis-io/wick)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/krypsis-io/wick/badge)](https://securityscorecards.dev/viewer/?uri=github.com/krypsis-io/wick)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

[Quick start](#quick-start) · [Install](#install) · [Usage](#usage) · [Detection](#detection) · [Configuration](#configuration) · [Go library](#go-library)

![wick redacting kubectl logs and a Kubernetes Secret](assets/demo.gif)

</div>

wick is a filter for text that you share. Use it before you paste logs into an AI assistant, a GitHub issue, or a support ticket. It replaces secrets and personal data with placeholders. It keeps the rest of the text, so the output is still useful for debugging.

```diff
- level=info msg="loaded config" github_token=ghp_R7mK2xQ9vLp4TzW8nDj3bY5cH6fA0sGtE1uN
+ level=info msg="loaded config" github_token=[REDACTED]
- level=info msg="order placed" order=8812 user=jordan.lee@shopco.io ip=203.0.113.42
+ level=info msg="order placed" order=8812 user=[REDACTED] ip=[REDACTED]
- level=error msg="db dial failed" url=postgres://checkout:Xk9vQ2mLp7Rt@db.shop.svc:5432/orders
+ level=error msg="db dial failed" url=postgres://checkout:[REDACTED]@db.shop.svc:5432/orders
```

- **228 secret rules and 5 PII detectors.** The secret rules are the 223 rules from [Gitleaks](https://github.com/gitleaks/gitleaks), plus 5 rules for secrets that appear in logs.
- **Structure-aware.** wick finds JSON, YAML, and `.env` input from its content. Keys stay readable. Only values change.
- **Kubernetes-aware.** wick redacts every value in a Secret's `data` and `stringData`, whatever the key name.
- **Reversible.** Tokenize mode saves the original values in an encrypted file. You can put them back later.
- **One static binary.** No configuration, no network access, no runtime dependencies.

## Quick start

```bash
brew install krypsis-io/tap/wick

kubectl logs deploy/api | wick              # redact a stream
wick app.log .env > shared.txt              # redact files
kubectl logs deploy/api | wick | pbcopy     # redact to the macOS clipboard
```

wick writes the redacted text to stdout. It writes notices, summaries, and reports to stderr, so a pipe gets only the redacted text.

## Install

### Homebrew (macOS, Linux)

```bash
brew install krypsis-io/tap/wick
```

### Go

```bash
go install github.com/krypsis-io/wick/cmd/wick@latest
```

### Install script (macOS, Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/krypsis-io/wick/main/install.sh | sh
```

The script downloads the latest release for your platform and verifies its SHA-256 checksum. It installs to `/usr/local/bin` if that directory is writable. If not, it installs to `~/.local/bin`.

| Variable | Effect |
|---|---|
| `WICK_INSTALL_DIR` | Install to a different directory. |
| `WICK_VERSION` | Install a specific version, without the leading `v` (for example, `0.4.0`). |

### Prebuilt binaries

Download an archive for Linux, macOS, or Windows (`amd64`, `arm64`) from [Releases](https://github.com/krypsis-io/wick/releases). Each release includes checksums.

## Usage

### Redact files, stdin, or a directory

```bash
wick app.log                          # one file
wick .env config.yaml                 # several files
kubectl get secret db -o yaml | wick  # stdin
wick --dir ./configs --out ./configs-safe
```

`--dir` redacts every file in the directory tree and writes it to the same path under `--out`. The `--out` directory must not be inside `--dir`.

### See what wick redacted

| Flag | Output to stderr |
|---|---|
| `--summary` | The number of findings for each rule. |
| `--report` | One line for each finding: rule ID, location, and a masked preview. |
| `--report-unsafe` | The same as `--report`, but with the raw values. **This prints secrets.** |

```console
$ kubectl -n demo get secret checkout-db -o yaml | wick --summary > /dev/null
wick: redacted 2 finding(s) — 2 secret(s)
  kubernetes-secret: 2
wick: redaction is best-effort; review the output before sharing it
```

### Get JSON output

```bash
wick app.log --format json
```

```json
{
  "redacted": "email [REDACTED]\n",
  "findings": [
    { "category": "pii", "rule_id": "email", "line": 1, "start": 6, "end": 20 }
  ],
  "summary": { "total": 1, "by_type": { "email": 1 } }
}
```

### Change the replacement style

| Flag | Output |
|---|---|
| `--style redacted` (default) | `[REDACTED]` |
| `--style stars` | `***` |
| `--style hash` | `[EMAIL:0f3306f4]`. The same value always gets the same hash, so you can still match values. |
| `--style 'custom=<removed>'` | `<removed>` |

### Redact now, restore later

Tokenize mode replaces each value with a numbered token, such as `[EMAIL-1]`. The same value always gets the same token. wick writes the original values to an AES-256-GCM encrypted file. It prints the key to stderr one time.

```bash
# 1. Redact. Save the key that wick prints.
wick --tokenize < app.log > app.safe.log

# 2. Share app.safe.log. Get a reply that contains the tokens.

# 3. Put the original values back into the reply.
wick --rehydrate --key <KEY> < reply.txt
```

The encrypted file is `.wick-tokens.enc` by default. Use `--token-file` to change the path. Both modes read from stdin only. Rehydrated JSON and YAML stay valid, also when an original value contains newlines or quotes.

## Detection

| Category | What wick finds |
|---|---|
| Gitleaks rules | Cloud provider keys, API tokens, private keys, JWTs, webhook URLs, and more. |
| Passwords | Values of password-like keys (`password=`, `DB_PASS:`). There is no entropy threshold, so wick also finds weak passwords. |
| Secret-named variables | Values of `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, and similar names. |
| Name/value pairs | `{"name": "DB_PASSWORD", "value": "..."}` in Kubernetes, ECS, Portainer, and `docker inspect` output. |
| URL credentials | The password in `scheme://user:password@host`. The user and the host stay readable. |
| Kubernetes Secrets | All `data` and `stringData` values, also the copy in the `kubectl.kubernetes.io/last-applied-configuration` annotation. |
| PII | Email addresses, IPv4 and IPv6 addresses, US phone numbers, US Social Security numbers. |
| Custom | Your `patterns` and `blocklist` entries. See [Configuration](#configuration). |

To see the rule ID for each finding, use `--report`. To turn off a rule, add its ID to `disable_rules`.

## Configuration

wick works without configuration. To add rules for a project, create a `.wick.yaml` file:

```yaml
style: redacted
format: text

# Patterns to redact, in addition to the built-in rules
patterns:
  - name: internal-ticket
    regex: "ACME-\\d{4}"
  - name: internal-hostname
    regex: "\\w+\\.internal\\.acme\\.com"
    replacement: "[INTERNAL-HOST]"   # optional

# Values to never redact
allowlist:
  - pattern: "test@example\\.com"
    regex: true
    reason: "Test fixture email"

# Values to always redact
blocklist:
  - pattern: "ACME-INTERNAL-[A-Z0-9]+"
    category: "custom"
    reason: "Internal project codes"

# More rules in Gitleaks TOML format
rules_file: "./my-rules.toml"

# Built-in rules to turn off, by rule ID
disable_rules:
  - "generic-api-key"
```

wick reads configuration from these locations:

1. `~/.config/wick/config.yaml` (global)
2. The nearest `.wick.yaml`, found from the current directory upward (project)
3. Command-line flags

For `style`, `format`, and `rules_file`, a later location overrides an earlier one. The lists (`patterns`, `allowlist`, `blocklist`, `disable_rules`) add together: the project file adds entries to the global file and does not replace them.

For all options, see [`.wick.yaml.example`](.wick.yaml.example).

## Go library

```bash
go get github.com/krypsis-io/wick
```

```go
import (
	"fmt"

	"github.com/krypsis-io/wick"
	"github.com/krypsis-io/wick/redact"
)

func main() {
	input := "user=jordan.lee@shopco.io ip=203.0.113.42"
	out, report, err := wick.Redact(input,
		wick.WithReplacer(redact.Stars),
		wick.WithDisabledRules([]string{"ipv4"}),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(out)                      // user=*** ip=203.0.113.42
	fmt.Println(report.Total, "findings") // 1 findings
}
```

For reversible redaction, use `wick.Dehydrate` and `wick.Rehydrate`. For the full API, see [pkg.go.dev](https://pkg.go.dev/github.com/krypsis-io/wick).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | wick found nothing to redact. `--rehydrate` also exits `0` when it succeeds. |
| `1` | wick redacted one or more values, or an error occurred. |

## Limitations

- **Detection is best-effort.** wick finds only what its rules describe. It does not know your internal token formats, ticket IDs, or hostnames. Add them with `patterns` or `blocklist`. When wick redacts something, it prints a reminder to stderr. Always read the output before you share it.
- **wick is not a secrets manager.** It does not replace secret storage, rotation, or leak prevention in Git. For Git history, use a scanner such as Gitleaks.
- **JSON output is re-encoded.** The values and the nesting stay the same, but the keys are sorted.
- **stdin is limited to 10 MB.** For larger input, pass the file as an argument.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE). The bundled Gitleaks rules are MIT-licensed. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

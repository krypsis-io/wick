<div align="center">

# wick

**Redact secrets and PII from logs, config files, and command output.**

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Release](https://img.shields.io/github/v/release/krypsis-io/wick?sort=semver&color=blue)](https://github.com/krypsis-io/wick/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/krypsis-io/wick.svg)](https://pkg.go.dev/github.com/krypsis-io/wick)
[![Go Report Card](https://goreportcard.com/badge/github.com/krypsis-io/wick)](https://goreportcard.com/report/github.com/krypsis-io/wick)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/krypsis-io/wick/badge)](https://securityscorecards.dev/viewer/?uri=github.com/krypsis-io/wick)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

[Install](#install) · [Usage](#usage) · [Detection](#detection) · [Configuration](#configuration) · [Go library](#go-library)

![wick redacting kubectl output](assets/demo.gif)

</div>

wick reads text from files or stdin. It replaces secrets and personal data with placeholders and writes the result to stdout. All other text stays the same, so you can still use the output to debug a problem.

Use wick before you paste logs into an AI assistant, a GitHub issue, or a support ticket.

```console
$ kubectl logs deploy/ledger-api | wick
2026-10-18T04:10:01Z config: github_token=[REDACTED]
2026-10-18T04:10:03Z ERROR dial postgres://ledger:[REDACTED]@postgres.payments.svc:5432/ledger: ECONNREFUSED
wick: redaction is best-effort; review the output before sharing it
```

## Features

| | |
|---|---|
| **228 secret rules** | 223 rules from [Gitleaks](https://github.com/gitleaks/gitleaks), plus 5 rules for secrets that appear in logs. |
| **5 PII detectors** | Email addresses, IPv4 and IPv6 addresses, US phone numbers, US SSNs. |
| **Structure-aware** | JSON, YAML, and `.env` input keep their structure. Keys stay readable. Only values change. |
| **Kubernetes-aware** | Every value in a Secret's `data` and `stringData` is redacted, including the copy in `kubectl.kubernetes.io/last-applied-configuration`. |
| **Reversible** | Tokenize mode writes an AES-256 encrypted map of the original values. Restore them later with `--rehydrate`. |
| **Extensible** | Add your own patterns, allowlists, blocklists, and Gitleaks-format rule files. |
| **Script-friendly** | Exit code `1` when wick redacts something. Notices go to stderr, so stdout stays clean for pipes. |

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

The script downloads the latest release for your platform and verifies its SHA-256 checksum. It installs to `/usr/local/bin`. If that directory is not writable, it installs to `~/.local/bin`.

| Variable | Effect |
|---|---|
| `WICK_INSTALL_DIR` | Install to a different directory. |
| `WICK_VERSION` | Install a specific version, without the leading `v` (for example, `0.4.0`). |

### Prebuilt binaries

Download an archive for Linux, macOS, or Windows (`amd64`, `arm64`) from [Releases](https://github.com/krypsis-io/wick/releases). Each release includes checksums.

## Usage

### Redact files or stdin

```bash
wick app.log                        # one file
wick .env config.yaml               # several files
kubectl logs deploy/api | wick      # stdin
kubectl logs deploy/api | wick | pbcopy   # to the clipboard
wick app.log > app.safe.log         # to a new file
```

### Redact a directory

```bash
wick --dir ./configs --out ./configs-safe
```

### Get a summary or a report

All reports go to stderr.

| Flag | Output |
|---|---|
| `--summary` | The number of redactions. |
| `--report` | One line per finding: rule ID, location, and a masked preview. |
| `--report-unsafe` | The same as `--report`, but with the raw values. **This prints secrets to stderr.** |

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

```bash
wick app.log --style redacted       # [REDACTED] (default)
wick app.log --style stars          # ***
wick app.log --style hash           # [EMAIL:1a2b3c4d], the same input gives the same hash
wick app.log --style 'custom=<removed>'
```

### Redact and restore later

Tokenize mode replaces each value with a token such as `[EMAIL-1]`. The same value always gets the same token. wick writes the original values to an encrypted token map and prints the key to stderr one time.

```bash
# 1. Redact. Save the key that wick prints.
wick --tokenize < app.log > app.safe.log

# 2. Share app.safe.log. Get a reply that contains the tokens.

# 3. Restore the original values.
wick --rehydrate --key <KEY> < reply.txt
```

The token map is `.wick-tokens.enc` by default. Use `--token-file` to change the path. Both modes read from stdin only. Rehydrated JSON and YAML stay valid, also when an original value contains newlines or quotes.

## Detection

| Category | What wick finds |
|---|---|
| Secrets (Gitleaks rules) | Cloud provider keys, API tokens, private keys, JWTs, webhook URLs, and more. |
| Passwords | Values assigned to password-like keys (`password=`, `DB_PASS:`). No entropy threshold, so weak passwords are also found. |
| Secret-named variables | `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, and similar names. |
| Name/value pairs | `{"name": "DB_PASSWORD", "value": "..."}` in Kubernetes, ECS, Portainer, and `docker inspect` output. |
| URL credentials | The password in `scheme://user:password@host`. The user and host stay readable. |
| Kubernetes Secrets | All `data` and `stringData` values, whatever the key name. |
| PII | Email addresses, IPv4, IPv6, US phone numbers, US SSNs. |
| Custom | Your own `patterns` and `blocklist` entries. See [Configuration](#configuration). |

Use `--report` to see the rule ID for each finding. Use the rule ID to disable a rule.

## Configuration

wick needs no configuration. To add rules for your project, create a `.wick.yaml` file:

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

# Built-in rules to disable, by rule ID
disable_rules:
  - "generic-api-key"
```

wick loads configuration in this order. Each level overrides the one before it.

1. `~/.config/wick/config.yaml` (global)
2. The nearest `.wick.yaml`, found from the current directory upward (project)
3. Command-line flags

For all options, see [`.wick.yaml.example`](.wick.yaml.example).

## Go library

```bash
go get github.com/krypsis-io/wick
```

```go
out, report, err := wick.Redact(input)
if err != nil {
	return err
}
fmt.Println(out)
fmt.Println(report.Total, "findings")
```

Use options to change the behavior:

```go
out, report, err := wick.Redact(input,
	wick.WithReplacer(redact.Stars),
	wick.WithDisabledRules([]string{"ipv4"}),
)
```

For reversible redaction, use `wick.Dehydrate` and `wick.Rehydrate`. For the full API, see [pkg.go.dev](https://pkg.go.dev/github.com/krypsis-io/wick).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | wick found nothing to redact. |
| `1` | wick redacted one or more values, or an error occurred. |

## Limitations

wick is a filter for text that you share. It is not a secrets manager. It does not replace secret storage, rotation, or leak prevention.

Detection is best-effort. wick finds only what its rules describe. It does not find formats that it has no rule for, such as internal token formats, ticket IDs, and internal hostnames. Add these with `patterns` or `blocklist` in `.wick.yaml`.

Always read the output before you share it. When wick redacts something, it prints a reminder to stderr.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request. To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE). The bundled Gitleaks rules are MIT-licensed. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

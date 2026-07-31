# Wick

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/krypsis-io/wick)](https://goreportcard.com/report/github.com/krypsis-io/wick)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/krypsis-io/wick/badge)](https://securityscorecards.dev/viewer/?uri=github.com/krypsis-io/wick)

Wick redacts secrets and PII from text so it is safe to share — with an LLM, a forum, or a teammate.

Logs, configs, and stack traces routinely contain API keys, internal hostnames, and personal data. Wick strips them out while preserving the surrounding content, so the result is still useful for troubleshooting: `kubectl logs` before they go into an AI chat, a `.env` before it lands in a gist, a stack trace before it hits a GitHub issue.

![Wick demo](assets/demo.gif)

- Detects secrets with bundled Gitleaks-derived rules, plus common PII (emails, IP addresses, US phone numbers, US SSNs)
- Preserves structure for JSON, YAML, and `.env` input
- Extensible with custom patterns, allowlists, and blocklists
- Reversible mode: share redacted text, then restore the originals from an encrypted token map
- Exits non-zero when findings are present, so it can gate scripts and CI

## Install

**Homebrew** (macOS, Linux):

```bash
brew install krypsis-io/tap/wick
```

**Go**:

```bash
go install github.com/krypsis-io/wick/cmd/wick@latest
```

**Shell installer** (Linux, macOS):

```bash
curl -fsSL https://raw.githubusercontent.com/krypsis-io/wick/main/install.sh | sh
```

The script downloads the latest release for your platform, verifies its SHA-256 checksum, and installs to `/usr/local/bin` (falling back to `~/.local/bin`). Set `WICK_INSTALL_DIR` to change the destination or `WICK_VERSION` to pin a version.

**Prebuilt binary** — archives for Linux, macOS, and Windows (`amd64`/`arm64`) with checksums are on [Releases](https://github.com/krypsis-io/wick/releases).

## Usage

```bash
# Redact files
wick app.log
wick .env config.yaml

# Redact anything on stdin
kubectl logs deploy/api | wick
env | wick

# Straight to the clipboard, ready to paste into an LLM
kubectl logs deploy/api | wick | pbcopy

# Save a shareable copy
wick app.log > issue-safe.log

# Redact an entire directory into a safe copy
wick --dir ./configs --out ./safe-configs
```

Exit code `1` means Wick found and redacted something; `0` means the input was clean.

### Output options

```bash
wick app.log --format json    # sanitized text plus machine-readable findings
wick app.log --summary        # count of redactions, printed to stderr
wick app.log --report         # per-finding detail (rule ID, location), printed to stderr
wick app.log --style stars    # replacement style: redacted (default), stars, hash, custom="..."
```

JSON output contains `redacted` (the sanitized content), `findings` (category, rule ID, and location for each match), and `summary` (counts by rule).

### Reversible redaction

Tokenize mode replaces each finding with a unique token and writes an encrypted map of the originals. Share the redacted text, then rehydrate the response to restore the real values.

```bash
# Redact with reversible tokens; the AES-256 key is printed once to stderr
wick --tokenize < app.log > safe.log

# Restore the original values
wick --rehydrate --key <KEY> < safe.log
```

The token map is written to `.wick-tokens.enc` by default (`--token-file` to change it). Both modes read from stdin only.

## Configuration

Wick works with zero configuration. To add project-specific rules, create a `.wick.yaml`:

```yaml
style: redacted
format: text

# Custom patterns, in addition to the built-in rules
patterns:
  - name: internal-ticket
    regex: "ACME-\\d{4}"
  - name: internal-hostname
    regex: "\\w+\\.internal\\.acme\\.com"
    replacement: "[INTERNAL-HOST]"   # optional per-pattern replacement

# Known-safe values that should never be redacted
allowlist:
  - pattern: "test@example\\.com"
    regex: true
    reason: "Test fixture email"

# Values that must always be redacted, even if no built-in rule matches
blocklist:
  - pattern: "ACME-INTERNAL-[A-Z0-9]+"
    category: "custom"
    reason: "Internal project codes"

# Extra Gitleaks-compatible rules from a TOML file
rules_file: "./my-rules.toml"

# Disable built-in rules by ID (use --report to see rule IDs)
disable_rules:
  - "generic-api-key"
```

Config is loaded from `~/.config/wick/config.yaml` (global), then the nearest `.wick.yaml` walking up from the current directory (project). Project settings override global; CLI flags override both. See [.wick.yaml.example](.wick.yaml.example) for the full reference.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No secrets or PII detected |
| `1` | Secrets or PII detected, or command error |

## Scope

Wick is a last-mile filter for text you are about to share. It is not a secrets manager and does not replace proper secret storage, rotation, or leak prevention.

## License

[AGPL-3.0](LICENSE)

# Wick

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/krypsis-io/wick)](https://goreportcard.com/report/github.com/krypsis-io/wick)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/krypsis-io/wick/badge)](https://securityscorecards.dev/viewer/?uri=github.com/krypsis-io/wick)

Fast, zero-config secret and PII redaction for any text stream. Pipe anything through it.

## Install

```bash
brew install krypsis-io/tap/wick
```

Or download a binary from [Releases](https://github.com/krypsis-io/wick/releases).

## Usage

```bash
# Pipe anything through wick
cat logs.txt | wick
env | wick
terraform plan -no-color | wick > safe-plan.txt
kubectl logs pod-name | wick > safe-logs.txt

# File input
wick --file .env --file config.yaml

# Batch redact a directory
wick --dir ./configs/ --out ./safe-configs/

# Redaction styles
echo "secret text" | wick --style stars      # ***
echo "secret text" | wick --style custom="[REMOVED]"

# JSON output for programmatic use
echo "secret text" | wick --format json

# Summary of what was redacted
echo "secret text" | wick --summary
```

## What It Detects

- **Secrets**: AWS keys, API tokens, JWTs, private keys, connection strings, and 800+ patterns via bundled [Gitleaks](https://github.com/gitleaks/gitleaks) rules
- **PII**: Email addresses, IPv4/IPv6 addresses, US phone numbers, US SSNs
- **Custom patterns**: Define your own via `.wick.yaml`

## Format Awareness

Wick auto-detects JSON, YAML, and `.env` files. It redacts values while preserving keys and structure.

## Configuration

Create `.wick.yaml` in your project root (or `~/.config/wick/config.yaml` for global defaults):

```yaml
# Redaction style: redacted (default), stars, or custom="..."
style: redacted

# Output format: text (default) or json
format: text

# Custom detection patterns
patterns:
  - name: internal-code
    regex: "ACME-\\d{4}"
  - name: internal-ip
    regex: "192\\.168\\.\\d+\\.\\d+"
```

Project config overrides global. CLI flags override both. All fields are optional.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no secrets or PII detected |
| 1 | Secrets or PII detected |

## License

[AGPL-3.0](LICENSE)

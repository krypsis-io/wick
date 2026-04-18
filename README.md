# Wick

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/krypsis-io/wick)](https://goreportcard.com/report/github.com/krypsis-io/wick)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/krypsis-io/wick/badge)](https://securityscorecards.dev/viewer/?uri=github.com/krypsis-io/wick)

Wick makes sensitive troubleshooting output safe to share with AI and humans.

When you are troubleshooting, you often need to paste logs, configs, stack traces, or command output into ChatGPT or Claude to get unstuck. The problem is that the raw text usually contains secrets, internal identifiers, IP addresses, or other data you should not leak. The same problem shows up when you want to post those logs or config fragments into a public forum, a GitHub issue, or a PR thread to get help from other people. Most people handle this by eyeballing the text and manually find-and-replacing values, which is tedious and error-prone — or they skip it entirely and hope nothing sensitive slips through.

Wick sits in that path. Pipe text through it, or point it at files and directories, and it will redact sensitive values while preserving the surrounding content so the result is still useful.

## Why It Exists

Most teams do not need another secret scanner dashboard. They need a fast way to sanitize raw troubleshooting output before it gets pasted into an LLM or posted somewhere other people can see it.

Wick is built for that moment:

- `kubectl logs` or stack traces before pasting them into ChatGPT or Claude
- prompts or context blocks that include company-specific names, domains, or IP ranges
- `kubectl describe` or `kubectl get` output before sending a snippet to someone else
- logs or config fragments before posting on GitHub Issues, PR threads, Reddit, Discord, or Stack Overflow
- `.env`, YAML, or JSON config before sharing it internally
- ad hoc terminal output that is too risky to trust by inspection

## What Wick Does

- Detects secrets using bundled Gitleaks-derived rules
- Detects common PII including emails, IP addresses, US phone numbers, and US SSNs
- Supports custom patterns for internal project names, customer identifiers, hostnames, and other proprietary terms
- Redacts values while keeping the rest of the text intact
- Preserves structure for JSON, YAML, and `.env`-style input
- Works as a Unix-style filter, on files, or across directories
- Returns a non-zero exit code when findings are present, so it can gate automation

## Install

```bash
brew install krypsis-io/tap/wick
```

Or download a binary from [Releases](https://github.com/krypsis-io/wick/releases).

## Quick Start

```bash
# Redact anything coming through stdin
kubectl logs deploy/api | wick
env | wick

# Sanitize before pasting into ChatGPT or Claude
kubectl logs deploy/api | wick | pbcopy

# Sanitize before posting publicly
kubectl logs deploy/api | wick > forum-post.txt

# Sanitize before dropping logs into a PR or issue thread
cat app.log | wick > pr-comment-safe.log

# Redact one or more files
wick --file .env --file config.yaml

# Redact an entire directory into a safe copy
wick --dir ./configs --out ./safe-configs
```

If Wick finds secrets or PII, it redacts them and exits with code `1`. If nothing is found, it exits `0`.

That makes it useful both as a sharing tool and as a guardrail in scripts or CI.

## Examples

```bash
# Human-readable redaction
cat logs.txt | wick

# Prep debugging context for an LLM
cat app.log | wick | pbcopy

# Prep logs for a public bug report
cat app.log | wick > issue-safe.log

# Prep logs or config snippets for a PR discussion
cat app.log | wick > pr-safe.log

# JSON output for automation
cat logs.txt | wick --format json

# Print a summary to stderr
cat logs.txt | wick --summary

# Change replacement style
cat logs.txt | wick --style stars
cat logs.txt | wick --style custom="[REMOVED]"
```

## Output Modes

### Default text output

Wick prints the redacted content directly, so it still reads like the original input.

```bash
cat logs.txt | wick > safe-logs.txt
```

### JSON output

Use JSON when you need both the sanitized output and machine-readable finding metadata.

```bash
kubectl logs deploy/api | wick --format json
```

The JSON includes:

- `redacted`: the sanitized content
- `findings`: each finding with category, rule id, and location
- `summary`: total findings and counts by rule

### Summary output

Use `--summary` to print a compact count of what Wick redacted to stderr.

```bash
kubectl logs deploy/api | wick --summary > safe-logs.txt
```

## Structured Input

Wick auto-detects and preserves structure for:

- JSON
- YAML
- `.env`
- plain text

That means the output stays useful after redaction instead of turning into a blob of broken formatting.

## Configuration

Wick works without configuration, but you can add project-specific rules with `.wick.yaml`.

This is the part that makes Wick useful for troubleshooting with AI or asking for help in public. Built-in rules catch common secrets and PII, while custom patterns let you redact internal names and identifiers that only matter in your environment.

Wick loads:

1. Global config from `~/.config/wick/config.yaml`
2. Project config from the nearest `.wick.yaml` in the current directory or a parent directory

Project config overrides global config. CLI flags override both.

Example:

```yaml
style: redacted
format: text

patterns:
  - name: internal-ticket
    regex: "ACME-\\d{4}"
  - name: proprietary-project-name
    regex: "\\bProject Lantern\\b"
  - name: private-ip
    regex: "192\\.168\\.\\d+\\.\\d+"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No secrets or PII detected |
| `1` | Secrets or PII detected, or command error |

## When To Use It

Use Wick when you already have troubleshooting output and need to make it safe now, especially before pasting it into an LLM, posting it publicly, or dropping it into an issue or PR discussion.

If the real problem is broader secret hygiene, storage, rotation, or prevention, Wick is not a substitute for that. It is the last-mile safety layer for text you are about to share, save, inspect, or feed into AI tooling.

## License

[AGPL-3.0](LICENSE)

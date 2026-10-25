# wick

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Release](https://img.shields.io/github/v/release/krypsis-io/wick?sort=semver)](https://github.com/krypsis-io/wick/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/krypsis-io/wick)](go.mod)
[![Go Reference](https://pkg.go.dev/badge/github.com/krypsis-io/wick.svg)](https://pkg.go.dev/github.com/krypsis-io/wick)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/krypsis-io/wick/badge)](https://securityscorecards.dev/viewer/?uri=github.com/krypsis-io/wick)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

wick removes secrets and personal data from logs, config files, and command output.
It replaces each value it finds with `[REDACTED]` and keeps the rest of the text, so you can paste the output into an AI assistant, a GitHub issue, or a support ticket.
Tokenize mode is reversible: wick replaces each value with a token such as `[EMAIL-1]`, and rehydrate mode puts the original values back into the reply.

![wick redacting kubectl logs and a Kubernetes Secret](assets/demo.gif)

## Installation

```bash
brew install krypsis-io/tap/wick
```

Or use `go install github.com/krypsis-io/wick/cmd/wick@latest`, the [install script](install.sh), or a binary from the [Releases](https://github.com/krypsis-io/wick/releases) page (Linux, macOS, and Windows).

To use wick as a Go library, run `go get github.com/krypsis-io/wick`. See the [package documentation](https://pkg.go.dev/github.com/krypsis-io/wick).

## Usage

```bash
kubectl logs deploy/api | wick | pbcopy     # redact, then copy to the clipboard
wick app.log .env > shared.txt              # redact files
wick --dir ./configs --out ./configs-safe   # redact a directory tree
wick --report app.log > /dev/null           # list each finding and its rule
```

wick writes the redacted text to stdout and everything else to stderr, so a pipe gets only the redacted text. It exits with `0` when nothing was redacted, `1` when something was redacted, and `2` on an error.

`--style` changes the placeholder: `redacted` (the default, `[REDACTED]`), `stars` (`***`), `hash` (`[EMAIL:63fe8938]`, the same for the same value), or `custom=<text>`.

### Tokenize and rehydrate

```bash
wick --tokenize app.log > safe.log          # replace each value with a token
wick --rehydrate reply.txt                  # put the original values back
wick --forget                               # delete the token map and its key
```

`--tokenize` replaces each value with a numbered token, such as `[EMAIL-1]`, and saves the original values in an encrypted token map. Send `safe.log` to an AI assistant, then run its reply through `--rehydrate` to see the real values. Both modes also read stdin.

The token map is `~/.local/state/wick/tokens.enc`, or `$XDG_STATE_HOME/wick/tokens.enc` if that is set, or `%LOCALAPPDATA%\wick\tokens.enc` on Windows. Its key is in the system keychain: macOS Keychain, Secret Service on Linux, or Windows Credential Manager. If there is no keychain, wick prints the key once. Set `WICK_KEY` to it.

All runs add to the same token map, so a value gets the same token in every log until you run `--forget`. Use `--token-file` to keep a separate token map for each task. `--rehydrate` leaves tokens that are not in the token map unchanged and lists them on stderr. Tokenize mode does not use `style` and `format` from `.wick.yaml`.

## What wick detects

| Category | Examples |
|---|---|
| Known secret formats | The [Gitleaks](https://github.com/gitleaks/gitleaks) rule set: cloud provider keys, API tokens, private keys, JWTs, webhook URLs |
| Keyed secrets | Values of `password`, `*_TOKEN`, `*_SECRET`, and similar keys, and `{"name": ..., "value": ...}` env pairs |
| HTTP headers | `Authorization`, `Cookie`, `Set-Cookie`, and API key headers such as `X-Api-Key` |
| URL credentials | The password in `postgres://user:password@host` |
| Kubernetes Secrets | Every value in `data` and `stringData` |
| Personal data | Email addresses, IPv4 and IPv6 addresses, US phone numbers, US Social Security numbers |

JSON, YAML, and `.env` input is parsed, so only the values change. JSON keys come out sorted.

Detection is rule-based. wick does not find formats it has no rule for, such as your internal token formats, ticket IDs, or hostnames, until you add them to `.wick.yaml`. Always read the output before you share it. wick is not a Git history scanner; for that, use Gitleaks or [TruffleHog](https://github.com/trufflesecurity/trufflehog).

## Configuration

wick needs no configuration. To add rules for a project, create `.wick.yaml`:

```yaml
patterns:                 # also redact these
  - name: internal-ticket
    regex: "ACME-\\d{4}"
allowlist:                # never redact these
  - pattern: "test@example.com"
disable_rules:            # turn off built-in rules by ID
  - generic-api-key
```

wick also reads `~/.config/wick/config.yaml`. Settings in `.wick.yaml` override it, and list entries from both files are combined. See [`.wick.yaml.example`](.wick.yaml.example) for every option.

## License

[AGPL-3.0](LICENSE). The bundled Gitleaks rules are MIT-licensed; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

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

wick reads text from files or from a pipe. It prints the same text with the secrets and personal data replaced.

Redact a file:

```bash
wick app.log
```

Redact the output of a command:

```bash
kubectl logs deploy/api | wick
```

```text
user=alice@example.com src=10.0.4.12   →   user=[REDACTED] src=[REDACTED]
```

wick prints only the redacted text. Messages go to stderr. So you can save the result to a file or copy it to the clipboard:

```bash
wick app.log > app-safe.log
kubectl logs deploy/api | wick | pbcopy
```

### Options

| Option | What it does |
|---|---|
| `--dir <dir> --out <dir>` | Redacts every file in a directory and writes the results to a new directory. |
| `--summary` | Prints the number of redactions for each type on stderr. |
| `--report` | Prints each finding, its location and its rule on stderr. |
| `--style <style>` | Changes the placeholder: `redacted` (`[REDACTED]`, the default), `stars` (`***`), `hash` (`[EMAIL:63fe8938]`), or `custom=<text>`. |
| `--format json` | Prints the redacted text and the findings as JSON. |

Run `wick --help` to see all options.

The exit code is `0` when wick redacts nothing, `1` when wick redacts a value, and `2` on an error.

### Get the real values back

Use tokenize mode when you ask an AI assistant about a log and you want its answer to show the real values.

1. Replace each value with a numbered token:

   ```bash
   wick --tokenize app.log > safe.log
   ```

   ```text
   user=alice@example.com src=10.0.4.12   →   user=[EMAIL-1] src=[IPV4-1]
   ```

2. Paste `safe.log` into the AI assistant, and save its answer as `reply.txt`.

3. Put the real values back into the answer:

   ```bash
   wick --rehydrate reply.txt
   ```

4. When you are done, delete the saved values:

   ```bash
   wick --forget
   ```

`--tokenize` and `--rehydrate` also read from a pipe, for example `pbpaste | wick --rehydrate`.

<details>
<summary>Where wick saves the values</summary>

wick saves the original values in an encrypted token map:

- Linux and macOS: `~/.local/state/wick/tokens.enc`, or `$XDG_STATE_HOME/wick/tokens.enc` if `XDG_STATE_HOME` is set
- Windows: `%LOCALAPPDATA%\wick\tokens.enc`

The key is in the system keychain: macOS Keychain, Secret Service on Linux, or Windows Credential Manager. If there is no keychain, wick prints the key one time. Set `WICK_KEY` to that key.

Each `--tokenize` run adds to the same token map, so a value gets the same token in every log until you run `--forget`. To keep a separate token map for each task, use `--token-file <path>`.

If the answer contains a token that is not in the token map, `--rehydrate` does not change it and prints it on stderr.

Tokenize mode does not use `style` and `format` from `.wick.yaml`.

</details>

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

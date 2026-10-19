# wick

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Release](https://img.shields.io/github/v/release/krypsis-io/wick?sort=semver)](https://github.com/krypsis-io/wick/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/krypsis-io/wick.svg)](https://pkg.go.dev/github.com/krypsis-io/wick)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

wick removes secrets and personal data from logs, config files, and command output.
It replaces each value it finds with a placeholder and keeps the rest of the text, so the output is still useful for debugging.
Use it before you paste output into an AI assistant, a GitHub issue, or a support ticket.

```console
$ kubectl logs deploy/checkout | wick
level=info msg="checkout v3.2.0 starting" port=8080
level=info msg="loaded config" api_key=[REDACTED]
level=info msg="order placed" order=8812 user=[REDACTED] ip=[REDACTED]
level=error msg="db dial failed" url=postgres://checkout:[REDACTED]@db.shop.svc:5432/orders
```

[Installation](#installation) • [Usage](#usage) • [Detection](#detection) • [Configuration](#configuration) • [Go library](#go-library)

![wick redacting kubectl logs and a Kubernetes Secret](assets/demo.gif)

*Recorded with [VHS](https://github.com/charmbracelet/vhs) from [`assets/demo.tape`](assets/demo.tape).*

## Why use wick?

* It finds 228 kinds of secrets (the 223 [Gitleaks](https://github.com/gitleaks/gitleaks) rules plus 5 of its own) and 5 kinds of personal data: email addresses, IPv4 and IPv6 addresses, US phone numbers, and US Social Security numbers.
* It understands JSON, YAML, and `.env` input. Keys stay readable and only values change.
* It knows Kubernetes. Every value in a Secret's `data` and `stringData` is redacted, whatever the key is called.
* It keeps context. In `postgres://user:password@host`, only the password is removed.
* It is reversible. Tokenize mode writes the original values to an encrypted file, so you can put them back into a reply.
* It is a single static binary. It needs no configuration and makes no network requests.

## Why not use wick?

* wick finds only what its rules describe. It does not know your internal token formats, ticket IDs, or hostnames until you add them to `.wick.yaml`. Always read the output before you share it.
* wick filters text that you are about to share. It does not scan Git history or block commits. For that, use [Gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog).
* The personal data detectors are US-centric. Phone numbers and national ID numbers from other countries are not detected.
* wick re-encodes JSON input, so keys come out sorted.
* stdin input is limited to 10 MB. Pass larger input as a file.

## Installation

| Method | Command |
|---|---|
| Homebrew (macOS, Linux) | `brew install krypsis-io/tap/wick` |
| Go | `go install github.com/krypsis-io/wick/cmd/wick@latest` |
| Install script (macOS, Linux) | `curl -fsSL https://raw.githubusercontent.com/krypsis-io/wick/main/install.sh \| sh` |

Prebuilt binaries for Linux, macOS, and Windows (`amd64`, `arm64`) are on the [Releases](https://github.com/krypsis-io/wick/releases) page, with checksums.

The install script verifies the SHA-256 checksum of the download. It installs to `/usr/local/bin` if that directory is writable, and to `~/.local/bin` if not. Set `WICK_INSTALL_DIR` to choose a different directory, or `WICK_VERSION` (for example, `0.4.0`) to choose a version.

## Usage

wick reads files or stdin and writes the redacted text to stdout. Summaries, reports, and other messages go to stderr, so a pipe gets only the redacted text.

The first time wick redacts something on a machine, it prints a one-time reminder that redaction is best-effort.

### Redact a command's output

```bash
kubectl logs deploy/api | wick
docker inspect my-container | wick
kubectl logs deploy/api | wick | pbcopy     # copy to the clipboard on macOS
```

### Redact files and directories

```bash
wick app.log
wick .env config.yaml > shared.txt
wick --dir ./configs --out ./configs-safe
```

`--dir` redacts every file in the directory tree and writes it to the same path under `--out`. The `--out` directory must not be inside `--dir`.

### See what was redacted

```console
$ kubectl get secret checkout-db -o yaml | wick --summary > /dev/null
wick: redacted 2 finding(s) — 2 secret(s)
  kubernetes-secret: 2
```

`--summary` prints the number of findings for each rule. `--report` prints one line for each finding, with the rule ID, the location, and a masked preview. `--report-unsafe` prints the raw values, which puts the secrets on stderr. Use `--format json` to get the redacted text and the findings as one JSON object.

### Change the placeholder

| Flag | Placeholder |
|---|---|
| `--style redacted` (default) | `[REDACTED]` |
| `--style stars` | `***` |
| `--style hash` | `[EMAIL:0f3306f4]`. The same value always gets the same hash. |
| `--style 'custom=<removed>'` | `<removed>` |

### Redact now, restore later

```bash
wick --tokenize < app.log > app.safe.log        # prints a key to stderr; save it
wick --rehydrate --key <KEY> < reply.txt        # puts the original values back
```

Tokenize mode replaces each value with a numbered token such as `[EMAIL-1]`. The same value always gets the same token. The original values are stored in `.wick-tokens.enc`, encrypted with AES-256-GCM. Use `--token-file` to change the path. Both modes read from stdin only. Rehydrated JSON and YAML stay valid, also when an original value contains newlines or quotes.

## Detection

| Category | What wick finds |
|---|---|
| Gitleaks rules | Cloud provider keys, API tokens, private keys, JWTs, webhook URLs, and more. |
| Passwords | Values of password-like keys (`password=`, `DB_PASS:`). There is no entropy threshold, so weak passwords are also found. |
| Secret-named variables | Values of `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, and similar names. |
| Name/value pairs | `{"name": "DB_PASSWORD", "value": "..."}` in Kubernetes, ECS, Portainer, and `docker inspect` output. |
| URL credentials | The password in `scheme://user:password@host`. |
| Kubernetes Secrets | All `data` and `stringData` values, also the copy in the `kubectl.kubernetes.io/last-applied-configuration` annotation. |
| Personal data | Email addresses, IPv4 and IPv6 addresses, US phone numbers, US Social Security numbers. |
| Custom | Your `patterns` and `blocklist` entries. |

Run with `--report` to see the rule ID of each finding. To turn off a rule, add its ID to `disable_rules`.

## Configuration

wick works without configuration. To add rules for a project, create a `.wick.yaml` file:

```yaml
patterns:                       # redact these, in addition to the built-in rules
  - name: internal-ticket
    regex: "ACME-\\d{4}"
  - name: internal-hostname
    regex: "\\w+\\.internal\\.acme\\.com"
    replacement: "[INTERNAL-HOST]"

allowlist:                      # never redact these
  - pattern: "test@example\\.com"
    regex: true

blocklist:                      # always redact these
  - pattern: "ACME-INTERNAL-[A-Z0-9]+"

disable_rules:                  # built-in rules to turn off
  - generic-api-key

rules_file: ./my-rules.toml     # more rules, in Gitleaks TOML format
```

wick reads `~/.config/wick/config.yaml` first, then the nearest `.wick.yaml` in the current directory or a parent. For `style`, `format`, and `rules_file`, the project file overrides the global file. The `--style` and `--format` flags override both files. The lists add together: project entries are added to the global entries.

See [`.wick.yaml.example`](.wick.yaml.example) for every option.

## Go library

```go
import (
	"github.com/krypsis-io/wick"
	"github.com/krypsis-io/wick/redact"
)

out, report, err := wick.Redact("user=jordan.lee@shopco.io ip=203.0.113.42",
	wick.WithReplacer(redact.Stars),
	wick.WithDisabledRules([]string{"ipv4"}),
)
// out == "user=*** ip=203.0.113.42", report.Total == 1
```

`wick.Dehydrate` and `wick.Rehydrate` do reversible redaction. See the [package documentation](https://pkg.go.dev/github.com/krypsis-io/wick) for the full API.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing was redacted, or `--rehydrate` succeeded. |
| `1` | One or more values were redacted, or an error occurred. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

wick is licensed under [AGPL-3.0](LICENSE). The bundled Gitleaks rules are MIT-licensed; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

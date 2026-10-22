# wick

[![CI](https://github.com/krypsis-io/wick/actions/workflows/pr.yml/badge.svg)](https://github.com/krypsis-io/wick/actions/workflows/pr.yml)
[![Release](https://img.shields.io/github/v/release/krypsis-io/wick?sort=semver)](https://github.com/krypsis-io/wick/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/krypsis-io/wick.svg)](https://pkg.go.dev/github.com/krypsis-io/wick)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

wick removes secrets and personal data from logs, config files, and command output.
Each value it finds becomes a placeholder, and the rest of the text stays the same.
Pipe output through wick before you paste it into an AI assistant, a GitHub issue, or a support ticket.

```console
$ kubectl logs deploy/checkout
level=info msg="order placed" order=8812 user=jordan.lee@shopco.io ip=203.0.113.42
level=debug msg="GET /v1/rates?currency=usd&api_key=Qm2LvX7pT4wRn8dJ3bY5cH6f"
level=error msg="payment failed" order=8812 customer=jordan.lee@shopco.io

$ kubectl logs deploy/checkout | wick
level=info msg="order placed" order=8812 user=[REDACTED] ip=[REDACTED]
level=debug msg="GET /v1/rates?currency=usd&api_key=[REDACTED]"
level=error msg="payment failed" order=8812 customer=[REDACTED]
```

![wick redacting kubectl logs and a Kubernetes Secret](assets/demo.gif)

[Installation](#installation) • [Usage](#usage) • [Detection](#detection) • [Configuration](#configuration) • [Go library](#go-library)

## Why use wick?

* 228 secret rules: the 223 [Gitleaks](https://github.com/gitleaks/gitleaks) rules plus 5 of wick's own. 5 personal data detectors: email addresses, IPv4 and IPv6 addresses, US phone numbers, and US Social Security numbers.
* JSON, YAML, and `.env` input is parsed, not only matched as text. Keys stay readable and only the values change.
* Every value in a Kubernetes Secret's `data` and `stringData` is redacted, whatever the key is called.
* In `postgres://user:password@host`, only the password is removed. The user and host stay, so you can still see which database failed.
* Tokenize mode is reversible. You can send redacted text to an assistant and put the real values back into its answer.
* A single static binary with no configuration and no network requests.

## Why not use wick?

* Detection is rule-based. Your internal token formats, ticket IDs, and hostnames are not found until you add them to `.wick.yaml`. Always read the output before you share it.
* wick filters text that you are about to share. It does not scan Git history or block commits. For that, use [Gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog).
* The personal data detectors are US-centric. Phone numbers and national ID numbers from other countries are not found.
* JSON input is re-encoded, so keys come out sorted.
* stdin input is limited to 10 MB. Pass larger input as a file.

## Installation

| Method | Command |
|---|---|
| Homebrew (macOS, Linux) | `brew install krypsis-io/tap/wick` |
| Go | `go install github.com/krypsis-io/wick/cmd/wick@latest` |
| Install script (macOS, Linux) | `curl -fsSL https://raw.githubusercontent.com/krypsis-io/wick/main/install.sh \| sh` |

On Windows, or for a manual install, download an archive from the [Releases](https://github.com/krypsis-io/wick/releases) page. Builds are available for Linux, macOS, and Windows on `amd64` and `arm64`, with checksums.

The install script checks the SHA-256 checksum of the download. Set `WICK_INSTALL_DIR` to choose where it installs, or `WICK_VERSION` (for example, `0.4.0`) to choose a version.

## Usage

wick reads files or stdin and writes the redacted text to stdout. Everything else, such as summaries and reports, goes to stderr, so a pipe gets only the redacted text. The first time wick redacts something on a machine, it also prints a one-time reminder to stderr that redaction is best-effort.

```bash
kubectl logs deploy/api | wick
docker inspect my-container | wick
kubectl logs deploy/api | wick | pbcopy     # copy to the clipboard on macOS
wick app.log
wick .env config.yaml > shared.txt
wick --dir ./configs --out ./configs-safe
```

`--dir` redacts every file in the directory tree and writes it to the same path under `--out`. The `--out` directory must not be inside `--dir`.

wick exits with `0` when nothing was redacted, `1` when something was redacted, and `2` on an error. A script that uses `set -e` stops when wick finds something. To stop only on errors, write `wick app.log > safe.log || [ $? -eq 1 ]`.

### See what was redacted

```console
$ kubectl get secret checkout-db -o yaml | wick --summary > /dev/null
wick: redacted 2 finding(s) — 2 secret(s)
  kubernetes-secret: 2

$ kubectl logs deploy/checkout | wick --report > /dev/null
wick: 4 finding(s)
  line 1 col 47  pii       email                           … (20 chars)
  line 1 col 71  pii       ipv4                            … (12 chars)
  line 2 col 53  secret    generic-api-key                 Qm2L…cH6f (24 chars)
  line 3 col 54  pii       email                           … (20 chars)
```

`--summary` counts the findings for each rule. `--report` lists each finding with its location, rule ID, and a masked preview. `--report-unsafe` shows the raw values, which puts the secrets on stderr. `--format json` writes the redacted text and the findings as one JSON object.

### Change the placeholder

| Flag | Placeholder |
|---|---|
| `--style redacted` (default) | `[REDACTED]` |
| `--style stars` | `***` |
| `--style hash` | `[EMAIL:63fe8938]`. The same value always gets the same hash, so you can still tell values apart. |
| `--style 'custom=<removed>'` | `<removed>` |

### Restore the original values

Use `--tokenize` when you send redacted text to someone, such as an AI assistant, and want to put the real values back into the answer.

```console
$ echo 'contact jordan.lee@shopco.io ip=203.0.113.42' | wick --tokenize
wick: key: agfT4oMCxPE8UIppUtcGwDcPAVrbR/StBynXen3EW3o=
wick: WARNING: store this key securely — it is required to rehydrate and will not be shown again
wick: token map written to .wick-tokens.enc
contact [EMAIL-1] ip=[IPV4-1]

$ echo 'Email [EMAIL-1] about the outage from [IPV4-1].' | wick --rehydrate --key agfT4oMCxPE8UIppUtcGwDcPAVrbR/StBynXen3EW3o=
Email jordan.lee@shopco.io about the outage from 203.0.113.42.
```

Each value gets a numbered token, and the same value always gets the same token. The original values are written to `.wick-tokens.enc` in the current directory, encrypted with AES-256-GCM. Use `--token-file` to change the path. Without the key, the values cannot be restored. `--tokenize` and `--rehydrate` read from stdin only.

## Detection

| Category | What wick finds |
|---|---|
| Gitleaks rules | Cloud provider keys, API tokens, private keys, JWTs, webhook URLs, and more. |
| Passwords | Values of password-like keys (`password=`, `DB_PASS:`). There is no entropy threshold, so weak passwords are found too. |
| Secret-named variables | Values of `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, and similar names. |
| Name/value pairs | `{"name": "DB_PASSWORD", "value": "..."}` in Kubernetes, ECS, Portainer, and `docker inspect` output. |
| URL credentials | The password in `scheme://user:password@host`. |
| Kubernetes Secrets | All `data` and `stringData` values, including the copy in the `kubectl.kubernetes.io/last-applied-configuration` annotation. |
| Personal data | Email addresses, IPv4 and IPv6 addresses, US phone numbers, US Social Security numbers. |
| Custom | Your own patterns from `.wick.yaml`. |

To turn off a rule, find its ID with `--report` and add it to `disable_rules`.

## Configuration

wick needs no configuration. To add rules for a project, create a `.wick.yaml` file:

```yaml
style: hash                     # default placeholder style

patterns:                       # also redact these regular expressions
  - name: internal-ticket
    regex: "ACME-\\d{4}"
  - name: internal-hostname
    regex: "\\w+\\.internal\\.acme\\.com"
    replacement: "[INTERNAL-HOST]"

allowlist:                      # never redact these values
  - pattern: "test@example\\.com"
    regex: true

disable_rules:                  # built-in rules to turn off
  - generic-api-key

rules_file: ./my-rules.toml     # more rules, in Gitleaks TOML format
```

wick reads `~/.config/wick/config.yaml` first, then the nearest `.wick.yaml` in the current directory or a parent. A setting in the project file overrides the same setting in the global file, and the `--style` and `--format` flags override both. List entries from both files are combined.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

wick is licensed under [AGPL-3.0](LICENSE). The bundled Gitleaks rules are MIT-licensed; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

# Wick

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

Create `.wick.yaml` in your project root:

```yaml
style: redacted
patterns:
  - name: internal-code
    regex: "ACME-\\d{4}"
```

## License

[AGPL-3.0](LICENSE) — free for CLI usage and open-source projects. [Commercial license](mailto:licensing@krypsis.io) available for proprietary embedding.

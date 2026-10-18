# Contributing to Wick

Thank you for your interest in contributing to Wick! This document outlines the process for contributing.

## Contributor License Agreement (CLA)

All contributors must sign a CLA before their contributions can be merged. This allows us to maintain the dual-license model (AGPL-3.0 + commercial). You will be prompted to sign the CLA when you open your first pull request.

## Getting Started

1. Fork the repository
2. Create a feature branch: `feat/your-feature` or `fix/your-bug`
3. Make your changes
4. Run tests: `make test`
5. Run linting: `make lint`
6. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
7. Open a pull request against `main`

## Branch Naming

Use the format `<type>/<short-description>`:

- `feat/` — new functionality
- `fix/` — bug fixes
- `chore/` — CI, config, dependencies, tooling
- `docs/` — documentation only
- `refactor/` — code changes that are not features or fixes

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/). PRs are squash-merged, so the PR title becomes the commit and decides the version bump:

- `feat: add IPv6 detection`: minor bump
- `fix: handle empty input gracefully`: patch bump
- `feat!: change default redaction style`: major bump (a minor bump while wick is 0.x)
- `deps: update module ...`: patch bump (Renovate uses this for Go module updates)
- `chore`, `ci`, `docs`, `test`, `build`, `style`: no release on their own

## Releases

Releases are cut with [release-please](https://github.com/googleapis/release-please). Merging releasable commits to `main` opens or updates a `chore: release x.y.z` PR with the version and changelog. Nothing is published until a maintainer merges that PR, which tags the release, and GoReleaser then builds and attaches the binaries.

## Easy First Contributions

Adding new detection patterns is the easiest way to contribute:

- Secret patterns: Add to `detect/patterns/wick.toml` (Gitleaks-compatible format). `detect/patterns/gitleaks.toml` is generated upstream; don't edit it by hand
- PII patterns: Add to `detect/pii.go`
- Include tests for any new patterns

## Development

```bash
# Build
make build

# Test
make test

# Lint
make lint

# Test coverage
make coverage
```

## Code Review

All pull requests require review before merging. PRs should:

- Pass all CI checks (lint, test, govulncheck)
- Include tests for new functionality
- Follow existing code patterns
- Have clear commit messages

## Questions?

Open a [GitHub Discussion](https://github.com/krypsis-io/wick/discussions) for questions or ideas.

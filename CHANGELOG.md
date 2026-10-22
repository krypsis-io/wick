## [0.4.0](https://github.com/krypsis-io/wick/compare/v0.3.1...v0.4.0) (2026-10-17)

### Features

* close secret detection gaps and mask --report values ([#39](https://github.com/krypsis-io/wick/issues/39)) ([19818de](https://github.com/krypsis-io/wick/commit/19818dede49dc7586cb1be9c43307cc3a1c85f53))

## [0.5.0](https://github.com/krypsis-io/wick/compare/v0.4.0...v0.5.0) (2026-10-22)


### Features

* remind on stderr that redaction is best-effort ([#42](https://github.com/krypsis-io/wick/issues/42)) ([ada114b](https://github.com/krypsis-io/wick/commit/ada114b1e38ec5eb6c41b8c1fb653398cf82f84d))
* show the best-effort reminder once per machine, in a terminal only ([#49](https://github.com/krypsis-io/wick/issues/49)) ([0dd06b6](https://github.com/krypsis-io/wick/commit/0dd06b6373554bd27b43f5d4ec2f5661f057ca10))


### Bug Fixes

* catch private keys inside JSON/YAML values and column-aligned env values ([#44](https://github.com/krypsis-io/wick/issues/44)) ([dfc4111](https://github.com/krypsis-io/wick/commit/dfc411167f598311977c079c58644be95c3744ab))
* exit 1 from --tokenize when it redacts values ([#48](https://github.com/krypsis-io/wick/issues/48)) ([294bfa3](https://github.com/krypsis-io/wick/commit/294bfa32a46d3421b60392651ba09a33cc53f9f1))
* exit 2 on errors so scripts can tell them apart from findings ([#51](https://github.com/krypsis-io/wick/issues/51)) ([237b489](https://github.com/krypsis-io/wick/commit/237b4895b8983a29fc3631b7840fd66f72f7a30e))
* redact credentials in Authorization, Cookie and API key headers ([#50](https://github.com/krypsis-io/wick/issues/50)) ([f34526e](https://github.com/krypsis-io/wick/commit/f34526e2e8fbd0aa580dc95990c4cfc1ee8ebcc5))
* redact URL passwords and Kubernetes Secret values ([#46](https://github.com/krypsis-io/wick/issues/46)) ([3ac0a6c](https://github.com/krypsis-io/wick/commit/3ac0a6c4acb2a1bb50201731a8dbe4a3d5c9804d))
* rehydrate JSON and YAML into valid documents ([#45](https://github.com/krypsis-io/wick/issues/45)) ([3de0b2b](https://github.com/krypsis-io/wick/commit/3de0b2b9d5421545c98658648124b31e9dd97633))
* stop reporting hex strings and IDs as US phone numbers ([#52](https://github.com/krypsis-io/wick/issues/52)) ([3010364](https://github.com/krypsis-io/wick/commit/3010364b34c99f19ff25a33a8dc6beb3f34ee909))

## [0.3.1](https://github.com/krypsis-io/wick/compare/v0.3.0...v0.3.1) (2026-08-12)

## [0.3.0](https://github.com/krypsis-io/wick/compare/v0.2.0...v0.3.0) (2026-07-31)

## [0.2.0](https://github.com/krypsis-io/wick/compare/v0.1.12...v0.2.0) (2026-07-29)

## [0.1.12](https://github.com/krypsis-io/wick/compare/v0.1.11...v0.1.12) (2026-07-05)

## [0.1.11](https://github.com/krypsis-io/wick/compare/v0.1.10...v0.1.11) (2026-07-03)

## [0.1.10](https://github.com/krypsis-io/wick/compare/v0.1.9...v0.1.10) (2026-06-24)

## [0.1.9](https://github.com/krypsis-io/wick/compare/v0.1.8...v0.1.9) (2026-06-23)

## [0.1.8](https://github.com/krypsis-io/wick/compare/v0.1.7...v0.1.8) (2026-06-17)

## [0.1.7](https://github.com/krypsis-io/wick/compare/v0.1.6...v0.1.7) (2026-06-12)

## [0.1.6](https://github.com/krypsis-io/wick/compare/v0.1.5...v0.1.6) (2026-05-02)

## [0.1.5](https://github.com/krypsis-io/wick/compare/v0.1.4...v0.1.5) (2026-04-14)

## [0.1.4](https://github.com/krypsis-io/wick/compare/v0.1.3...v0.1.4) (2026-04-04)

## [0.1.3](https://github.com/krypsis-io/wick/compare/v0.1.2...v0.1.3) (2026-04-04)

## [0.1.2](https://github.com/krypsis-io/wick/compare/v0.1.1...v0.1.2) (2026-04-04)

### Bug Fixes

* detect multiline secrets (PEM private key blocks) ([#7](https://github.com/krypsis-io/wick/issues/7)) ([27405a7](https://github.com/krypsis-io/wick/commit/27405a79f58b790b1d7ca5445251662eb3760f25))

## [0.1.1](https://github.com/krypsis-io/wick/compare/v0.1.0...v0.1.1) (2026-03-28)

### Code Refactoring

* reduce cmd complexity and release refactors ([#3](https://github.com/krypsis-io/wick/issues/3)) ([2e148fe](https://github.com/krypsis-io/wick/commit/2e148fe4edaa0cbc3f6b430b22201e4909be6519))

# [0.1.0](https://github.com/krypsis-io/wick/compare/v0.0.0...v0.1.0) (2026-03-28)


### Features

* wick v0.1 — zero-config secret and PII redaction engine ([#1](https://github.com/krypsis-io/wick/issues/1)) ([76d6522](https://github.com/krypsis-io/wick/commit/76d6522d5614f6e65519def4a081423c7e7b29a0))

# Changelog

All notable changes are documented here. CloudPen has not reached a stable public release.

## Unreleased

### Added

- Private identity integration with application-level `admin`, `operator`, `reviewer`, and `viewer` roles.
- D1-backed validation plans, guardrails, rate limits, memberships, and tamper-evident audit chaining.
- Server-generated HMAC-SHA-256 plan receipts and evidence integrity envelopes.
- Same-origin mutation enforcement, bounded JSON bodies, field validation, sanitized API errors, and security headers.
- Loopback-only local startup with persistent project-local D1 state.
- Adversarial integration tests and pinned CI security gates.
- Architecture, API, security, deployment, operations, runner, testing, and contribution documentation.

### Changed

- Validation actions now create non-executable server-owned plans instead of simulating runs in browser storage.
- Active-canary requests now stop in `Awaiting approval` and cannot reach a runner.
- Connector submissions record a request and External ID digest without creating AWS trust or storing credentials.
- Evidence export is server-owned, redacted, signed, non-cacheable, and audit logged.
- Dependencies were upgraded and the vulnerable legacy Drizzle generation toolchain was removed.

### Removed

- Browser-local authoritative run history.
- Hard-coded operator identity.
- Unsafe dormant example API routes.
- Stale starter build artifacts.

### Security

- Known dependency vulnerabilities reduced to zero at the time of validation.
- Host-header-derived social metadata removed.
- Local listener restricted from `0.0.0.0` to `127.0.0.1`.
- Core approval, canary-only, evidence-redaction, and cleanup guardrails made non-disableable.

## 0.1.0 — Prototype baseline

- Synthetic cloud exposure dashboard and attack-path exploration experience.
- No real cloud discovery, credential handling, or execution.

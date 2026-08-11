# Changelog

All notable changes are documented here. CloudPen has not reached a stable public release.

## Unreleased

No changes yet.

## 0.2.0-rc.1 — 2026-08-11

> Synthetic/private evaluation prerelease. CloudPen remains a non-executable control plane: it does not connect to AWS APIs, hold cloud credentials, or authorize a runner. It is not approved for production tenants or real customer data.

### Added

- Private identity integration with application-level `admin`, `operator`, `reviewer`, and `viewer` roles.
- D1-backed validation plans, guardrails, rate limits, memberships, and tamper-evident audit chaining.
- Server-generated HMAC-SHA-256 plan receipts and evidence integrity envelopes.
- Same-origin mutation enforcement, bounded JSON bodies, field validation, sanitized API errors, and security headers.
- Loopback-only local startup with persistent project-local D1 state.
- Adversarial integration tests and pinned CI security gates.
- Architecture, API, security, deployment, operations, runner, testing, and contribution documentation.
- Durable connectors, approval decisions, evidence manifests, remediation workflows, signed reports, and pending runner enrollment records.
- D1-owned exposure snapshots, cloud accounts, assets, attack paths, and graph edges with explicit demo provenance.
- Shareable view URLs, authoritative empty states, a real help surface, audit-chain verification, and signed guardrail export.

### Changed

- Validation actions now create non-executable server-owned plans instead of simulating runs in browser storage.
- Active-canary requests now stop in `Awaiting approval` and cannot reach a runner.
- Connector submissions validate a one-time External ID and immediately discard it without retaining the raw value, a display hint, or a reusable digest.
- Reviewer/admin decisions now enforce requester/approver separation and remain non-executable.
- Placeholder remediation, approval, help, report, connector, and policy-export actions now invoke durable server workflows.
- Evidence export is server-owned, redacted, signed, non-cacheable, and audit logged.
- Dependencies were upgraded and the vulnerable legacy Drizzle generation toolchain was removed.

### Removed

- Browser-local authoritative run history.
- Hard-coded operator identity.
- Unsafe dormant example API routes.
- Stale starter build artifacts.

### Security

- Production dependency vulnerabilities were reduced to zero at validation; two build-only Vinext `image-size` advisories are tracked with an artifact-reachability guard.
- Host-header-derived social metadata removed.
- Local listener restricted from `0.0.0.0` to `127.0.0.1`.
- Core approval, canary-only, evidence-redaction, and cleanup guardrails made non-disableable.
- Runner enrollment and discovery-plan schemas enforce `executable = 0` at the database boundary.

## 0.1.0 — Prototype baseline

- Synthetic cloud exposure dashboard and attack-path exploration experience.
- No real cloud discovery, credential handling, or execution.

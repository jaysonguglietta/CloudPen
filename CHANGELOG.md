# Changelog

All notable changes are documented here. CloudPen has not reached a stable public release.

## Unreleased

### Added

- Versioned PS256 artifact protocol with KMS signer adapter, deployable AWS KMS/Lambda signer stack, pinned public-key registry, independent verifier CLI, and tamper/replay/expiry/downgrade test vectors.
- Membership-derived multi-workspace context and two-tenant isolation tests.
- Signed approval envelopes bound to stored, reverified plan payloads and atomic mutation/audit commits.
- Signed audit-chain anchors, signed logical workspace backup manifests, legal holds, and lifecycle maintenance.
- Exact-endpoint SIEM delivery with privacy-minimized events, durable D1 outbox, bounded retry, and backoff.
- Fail-closed production readiness endpoint and GitHub release/SBOM provenance attestations.

### Security

- Removed shared HMAC signing from the deployed application path.
- Production configuration now fails readiness when local/ephemeral signing, KMS signer, pinned public key, HTTPS origin, SIEM, or durable state requirements are not satisfied.

### Release status

- Source-side hardening is implemented, but production promotion remains blocked until the KMS stack and independent SIEM are provisioned, a platform restore drill and tagged attestation verification are recorded, and an independent assessment is complete. Cloud execution remains disabled.

## 0.2.0-rc.2 — 2026-08-12

> Synthetic/private evaluation prerelease. CloudPen remains a non-executable control plane and is not approved for production tenants, real customer data, or active cloud testing.

### Changed

- Upgraded Next.js, Tailwind CSS, TypeScript, React type definitions, ESLint React tooling, Vinext, and the pinned GitHub checkout/setup-node actions.
- Restarted the local Miniflare Worker between connector mutation phases while preserving isolated D1 state, removing nondeterministic CI connection loss.
- Hardened integration-process shutdown by escalating to `SIGKILL` only when a Worker ignores the bounded graceful-stop window.

### Security

- Added pinned CodeQL JavaScript/TypeScript analysis for pull requests, `main`, and a weekly scheduled scan.
- Added executable release checks that require CodeQL publication permission, JavaScript/TypeScript coverage, immutable action pins, and npm/GitHub Actions Dependabot coverage.
- Enabled GitHub Dependabot vulnerability alerts and automatic security updates at the repository level.
- Preserved secret scanning and push protection; expanded non-provider patterns and validity checks remain unavailable in the current repository feature set.

### Release status

- All pull requests open at the start of this release cycle were repaired, passed the protected `verify` gate, and merged.
- Production rollout remains blocked on KMS/HSM-backed asymmetric signing, independently administered SIEM delivery, retention and recovery validation, tenant-isolation design, and independent runner assessment.

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

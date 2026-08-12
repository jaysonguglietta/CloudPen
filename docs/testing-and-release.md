# Testing and release gates

## Local quality gates

Run from a clean checkout with Node.js 22.13.0 or later:

```bash
npm ci
npm run lint
npm run typecheck
npm run docs:check
npm test
npm run security:check
npm run security:audit
npm run build
npm run security:audit:exceptions
```

`security:audit` checks deployable production dependencies. `security:audit:exceptions` runs the full audit and permits only GHSA-w3rx-r6r6-pgpr and GHSA-5p2g-fcmc-qvqq through the build-only Vinext/image-size path. The exception is owned by the CloudPen maintainers, expires on 2026-09-30, asserts that Vinext remains a development dependency, and fails if `image-size` enters the Worker bundle or any other High/Critical advisory appears. CI bounds the complete build/test process to five minutes. Upgrade immediately when upstream publishes a compatible fix.

Generate an SBOM for release evidence:

```bash
npm run sbom
```

The generated CycloneDX file is ignored by Git and should be attached to the controlled release record, not silently committed as a stale snapshot.

## Current automated security coverage

The integration suite builds the app, starts the built Worker on a temporary loopback port, uses isolated temporary D1 storage, and verifies:

- unauthenticated redirect to the platform sign-in path;
- authorized server rendering and accessible primary controls;
- per-response CSP script nonces, script-attribute denial, frame denial, and MIME-sniffing protection;
- canonical metadata that ignores attacker-controlled `Host`;
- cross-origin mutation rejection;
- durable signed read-only plan creation with `executable: false`;
- active-canary plans held for separate approval;
- refusal to disable mandatory guardrails;
- application role denial independent of identity authentication.
- explicit demo provenance and authoritative workflow collections;
- connector durability, External ID non-disclosure, and non-executable discovery plans;
- requester/approver separation and approved intent remaining non-executable;
- evidence-manifest retention and remediation state transitions;
- pending runner enrollment constrained to `executable: false`;
- signed assessment export and audit-chain verification.
- correlated structured telemetry with request-body, External ID, and evidence-secret non-disclosure.

`scripts/security-check.mjs` also verifies that clean builds do not package stale starter assets, the old hard-coded operator identity is absent, security-header code is present, and the local launcher cannot bind to all interfaces.

## CI

`.github/workflows/security.yml` runs on pull requests and pushes to `main`. It uses read-only repository permissions, cancels superseded runs, limits execution time, pins GitHub Actions to full commit SHAs, installs from the lockfile, audits dependencies, and runs lint, type checking, documentation-link checks, tests, and artifact checks.

`.github/workflows/codeql.yml` performs JavaScript/TypeScript CodeQL analysis on pull requests, pushes to `main`, and a weekly schedule. Its actions are pinned to immutable commit SHAs, its default permissions are read-only, and only the analysis job receives `security-events: write` so results can reach GitHub code scanning. Dependabot monitors both npm and GitHub Actions dependencies; repository vulnerability alerts and automatic security updates must remain enabled.

## Manual release review

Automation does not replace review. Before a hosted release, confirm:

- [ ] Diff contains no unrelated or generated local state.
- [ ] No secrets, tokens, credentials, customer identifiers, evidence, or internal URLs are present.
- [ ] Sites access remains private/custom.
- [ ] Production role allowlists and canonical origin are correct.
- [ ] A unique production signing key is stored as a secret.
- [ ] `CLOUDPEN_LOCAL_MODE` is absent.
- [ ] D1 migration and runtime initialization match.
- [ ] Every new mutation has capability, origin, body, validation, rate-limit, error, and audit controls.
- [ ] Security headers still allow the app to function without widening sources unnecessarily.
- [ ] Production dependency audit is clean; every full-audit exception is documented with reachability, upstream status, and compensating controls.
- [ ] SBOM and source commit are recorded.
- [ ] Synthetic smoke tests pass after deployment.
- [ ] Rollback version and database compatibility are known.
- [ ] Documentation and changelog match behavior.

## Additional tests required before real customer data

- Audit-chain corruption tests and external anchoring tests; runtime verification is implemented.
- Retention, deletion, backup, and restoration tests.
- Multi-workspace isolation tests after tenancy is designed.
- Load and abuse testing for large authenticated request volumes.
- Full browser CSP injection testing for script elements, event attributes, JavaScript URLs, styles, and Trusted Types compatibility.
- Privacy review of topology and evidence fields.

## Additional tests required before a runner

All protocol, policy, isolation, cloud, cleanup, evidence, update, and independent-assessment tests in `runner-security-design.md` are blocking. A passing web-app suite alone is not sufficient.

## Release evidence

Retain:

- commit SHA and dependency lockfile digest;
- CI results and test summary;
- `npm audit` result and SBOM;
- migration review and backup/restore evidence when applicable;
- deployment environment revision without secret values;
- access-policy review;
- synthetic post-deployment test results;
- approver and rollback decision.

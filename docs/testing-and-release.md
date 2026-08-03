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
```

Generate an SBOM for release evidence:

```bash
npm run sbom
```

The generated CycloneDX file is ignored by Git and should be attached to the controlled release record, not silently committed as a stale snapshot.

## Current automated security coverage

The integration suite builds the app, starts the built Worker on a temporary loopback port, uses isolated temporary D1 storage, and verifies:

- unauthenticated redirect to the platform sign-in path;
- authorized server rendering and accessible primary controls;
- CSP, frame denial, and MIME-sniffing protection;
- canonical metadata that ignores attacker-controlled `Host`;
- cross-origin mutation rejection;
- durable signed read-only plan creation with `executable: false`;
- active-canary plans held for separate approval;
- refusal to disable mandatory guardrails;
- application role denial independent of identity authentication.

`scripts/security-check.mjs` also verifies that clean builds do not package stale starter assets, the old hard-coded operator identity is absent, security-header code is present, and the local launcher cannot bind to all interfaces.

## CI

`.github/workflows/security.yml` runs on pull requests and pushes to `main`. It uses read-only repository permissions, cancels superseded runs, limits execution time, pins GitHub Actions to full commit SHAs, installs from the lockfile, audits dependencies, and runs lint, type checking, documentation-link checks, tests, and artifact checks.

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
- [ ] Dependency audit is clean or every exception is documented with reachability and compensating controls.
- [ ] SBOM and source commit are recorded.
- [ ] Synthetic smoke tests pass after deployment.
- [ ] Rollback version and database compatibility are known.
- [ ] Documentation and changelog match behavior.

## Additional tests required before real customer data

- Automated audit-chain verification and corruption tests.
- Retention, deletion, backup, and restoration tests.
- Multi-workspace isolation tests after tenancy is designed.
- Load and abuse testing for large authenticated request volumes.
- Browser CSP regression testing with nonce-based policy.
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

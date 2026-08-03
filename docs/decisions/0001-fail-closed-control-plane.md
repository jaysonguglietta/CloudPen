# ADR 0001: Keep cloud execution fail-closed

- **Status:** Accepted
- **Date:** 2026-07-31
- **Decision owners:** CloudPen maintainers

## Context

Cloud penetration testing requires privileged credentials, potentially destructive APIs, sensitive topology, reliable authorization, and evidence with defensible provenance. A browser prototype cannot safely establish those properties. Simulating successful cloud actions would also train users to trust unauthoritative results.

## Decision

The current release is a control plane only:

- it may create and persist validation plans;
- every plan is signed, expires, and contains `executable: false`;
- active-canary plans stop in `Awaiting approval`;
- no approval endpoint, runner enrollment, command channel, AWS credential exchange, or AWS SDK execution is present;
- connector requests record intent but create no trust relationship;
- the UI explicitly reports that the runner is disabled.

## Consequences

### Positive

- Compromising the current application cannot directly cause AWS API execution.
- Server behavior matches the product's actual capabilities.
- Runner design can be reviewed as a separate high-risk system.
- Tests can assert that plans remain non-executable.

### Negative

- The product does not yet validate real attack paths.
- Several user workflows terminate in a planned or provisioning state.
- HMAC receipts demonstrate control-plane integrity but not independent attestation.

## Reconsideration criteria

This decision may be extended only after every mandatory gate in `docs/runner-security-design.md` is implemented, tested in an isolated synthetic account, threat-modeled, and independently assessed. Enabling an AWS SDK in the web control plane does not satisfy the criteria.

# CloudPen

CloudPen is a security-first control-plane prototype for cloud attack-path validation. It helps cloud security engineers, red teams, and platform owners review identity chains, create constrained validation plans, preserve evidence integrity, and verify remediation.

This release intentionally does **not** execute AWS APIs. It creates server-owned, signed, non-executable plans and records connector requests while the customer-hosted runner boundary is designed and independently reviewed.

## Product brief

- **Target users:** cloud security engineers, authorized red teams, IAM/platform owners, and security reviewers.
- **Core problem:** policy findings do not prove whether an attacker can traverse a complete cloud identity path; unsafe validation can create a larger incident than the exposure it measures.
- **Primary workflows:** review exposure, inspect an attack chain, create a read-only or active-canary plan, review run history, export signed evidence, and administer immutable safety controls.
- **Main views:** exposure overview, attack paths, assets and identities, validation runs, and guardrails.
- **Key models:** workspace membership, attack path, validation plan/run, guardrail policy, audit event, and rate-limit bucket.
- **Important edge cases:** unauthenticated or unauthorized users, cross-origin mutations, oversized or malformed bodies, duplicate/racing audit writes, unavailable durable state, unsigned plans, disabled guardrails, and attempts to treat the browser as authoritative.
- **Assumptions:** the hosted Sites access policy remains private; Sites identity headers are injected by the trusted dispatcher; local mode is loopback-only; displayed cloud resources are synthetic sample data.
- **Done for this version:** the control plane is usable locally and deployable behind private Sites access, state-changing decisions are server-owned, production blockers are fail-closed, and cloud execution remains impossible.

## Security architecture

The trust boundary is split into three layers:

1. Sites authenticates the external user and restricts access to approved visitors.
2. CloudPen maps the verified email to an explicit `admin`, `operator`, `reviewer`, or `viewer` role and enforces capabilities again in every API route.
3. D1 owns plans, guardrails, rate limits, and a hash-chained audit log. The browser is only a presentation client.

Mutation endpoints require same-origin JSON requests, enforce an 8 KiB body limit, validate fields, apply per-user rate limits, and return sanitized errors. Evidence exports and plans use HMAC-SHA-256 integrity envelopes. Production safety controls cannot be disabled.

See [SECURITY.md](./SECURITY.md) for the implemented boundary and prerequisites for a future AWS runner.

## Documentation

- [Documentation index](./docs/README.md)
- [Architecture and trust boundaries](./docs/architecture.md)
- [Threat model and adversarial security review](./docs/security-review.md)
- [API reference](./docs/api.md)
- [Configuration and deployment](./docs/deployment.md)
- [Operations and incident response](./docs/operations.md)
- [Runner security design](./docs/runner-security-design.md)
- [Testing and release gates](./docs/testing-and-release.md)
- [Contributing](./CONTRIBUTING.md)
- [Changelog](./CHANGELOG.md)

## Run locally

Prerequisites: Node.js `>=22.13.0`.

```bash
npm install
npm run build
npm start
```

Open `http://127.0.0.1:8787`. The local command runs the built Worker through Wrangler with a project-local D1 database and an explicit loopback-only development identity. It does not expose the service on the LAN.

For UI development with hot reload:

```bash
npm run dev
```

Copy `.env.example` to an ignored local environment file if you need to customize the development identity. Never reuse the development signing key or local mode in production.

## Production environment

The Sites runtime must provide:

- `CLOUDPEN_ADMIN_EMAILS` and optional operator/reviewer/viewer lists
- `CLOUDPEN_PLAN_SIGNING_KEY` as a unique secret with at least 32 characters
- `PUBLIC_APP_ORIGIN` as the canonical HTTPS origin
- D1 binding `DB`

Keep Sites access in private/custom mode. A user must pass both the Sites access policy and application role checks.

## Verification

```bash
npm run lint
npm run typecheck
npm test
npm run security:check
npm run security:audit
```

`npm test` builds from a clean output directory, starts the Worker with temporary loopback D1 state, and exercises authentication, security headers, canonical metadata, CSRF rejection, and durable signed plan creation. CI runs the same gates. `npm run sbom` creates an ignored CycloneDX SBOM for a release artifact.

## Project status

CloudPen is a pre-production security control-plane prototype. It is suitable for local evaluation and continued engineering, but it must not be represented as a functioning cloud penetration-testing service until the runner prerequisites in [the runner security design](./docs/runner-security-design.md) are complete and independently assessed.

## Known limitations

- Attack paths, accounts, and assets are synthetic sample data still delivered to the client.
- There is no AWS discovery or execution runner, approval endpoint, KMS asymmetric signing, SSO/SCIM administration, SIEM export, or external penetration-test attestation yet.
- HMAC proves server possession of a shared secret; production evidence should move to KMS-backed asymmetric signatures before third-party verification.
- The CSP permits inline framework bootstrap code. A nonce-based CSP is the next browser-hardening step.

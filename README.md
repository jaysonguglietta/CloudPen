# CloudPen

CloudPen is a security-first control-plane prototype for cloud attack-path validation. It helps cloud security engineers, red teams, and platform owners review identity chains, create constrained validation plans, preserve evidence integrity, and verify remediation.

This release intentionally does **not** execute AWS APIs. It now provides durable connector, approval, evidence, remediation, reporting, exposure-snapshot, and runner-enrollment workflows while keeping every discovery and execution artifact explicitly non-executable.

## Product brief

- **Target users:** cloud security engineers, authorized red teams, IAM/platform owners, and security reviewers.
- **Core problem:** policy findings do not prove whether an attacker can traverse a complete cloud identity path; unsafe validation can create a larger incident than the exposure it measures.
- **Primary workflows:** review exposure, inspect an attack chain, create and independently review a validation plan, manage connector/discovery intent, export signed evidence and reports, assign remediation, verify audit integrity, and stage runner enrollment.
- **Main views:** exposure overview, attack paths, assets and identities, validation runs and approvals, connectors, remediation, evidence/audit, reports, administration, and guardrails.
- **Key models:** workspace membership, exposure snapshot/graph, connector, validation plan/run, evidence package, remediation, runner enrollment, guardrail policy, audit event, and rate-limit bucket.
- **Important edge cases:** unauthenticated or unauthorized users, cross-origin mutations, oversized or malformed bodies, duplicate/racing audit writes, unavailable durable state, unsigned plans, disabled guardrails, and attempts to treat the browser as authoritative.
- **Assumptions:** the hosted Sites access policy remains private; Sites identity headers are injected by the trusted dispatcher; local mode is loopback-only; displayed cloud resources are synthetic sample data.
- **Done for this version:** visible control-plane workflows are backed by D1, demo/live provenance is explicit, exposure records are server-delivered from a D1 snapshot, approval separation is enforced, reports and policies are signed, and cloud execution remains impossible.

## Security architecture

The trust boundary is split into three layers:

1. Sites authenticates the external user and restricts access to approved visitors.
2. CloudPen maps the verified email to an explicit `admin`, `operator`, `reviewer`, or `viewer` role and enforces capabilities again in every API route.
3. D1 owns exposure snapshots, connectors, plans, approvals, evidence manifests, remediation, pending runner enrollment, guardrails, rate limits, and a hash-chained audit log. The browser is only a presentation client.

Mutation endpoints require same-origin requests, validate fields, apply per-user rate limits, and return sanitized errors. JSON bodies are limited to 8 KiB. Evidence, plans, approvals, policies, reports, audit anchors, and backup manifests use versioned PS256 integrity envelopes. Production safety controls cannot be disabled.

See [SECURITY.md](./SECURITY.md) for the implemented boundary and prerequisites for a future AWS runner.

## Documentation

- [Documentation index](./docs/README.md)
- [Architecture and trust boundaries](./docs/architecture.md)
- [Threat model and adversarial security review](./docs/security-review.md)
- [API reference](./docs/api.md)
- [Configuration and deployment](./docs/deployment.md)
- [Operations and incident response](./docs/operations.md)
- [Runner security design](./docs/runner-security-design.md)
- [Feature delivery status](./docs/feature-roadmap.md)
- [Testing and release gates](./docs/testing-and-release.md)
- [Production hardening status](./docs/production-hardening.md)
- [Signed artifact protocol](./docs/cryptographic-protocol.md)
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

Copy `.env.example` to an ignored local environment file if you need to customize the development identity. The launcher enables local mode only on loopback and creates an ephemeral signing key when none is configured. Never use local mode in production.

## Production environment

The production Sites runtime must provide:

- `CLOUDPEN_ADMIN_EMAILS` and optional operator/reviewer/viewer lists
- `CLOUDPEN_PRODUCTION_MODE=1`
- `CLOUDPEN_SIGNER_URL`, secret `CLOUDPEN_SIGNER_TOKEN`, `CLOUDPEN_SIGNING_KEY_ID`, and pinned `CLOUDPEN_SIGNING_PUBLIC_JWK`
- `CLOUDPEN_SIEM_URL` and secret `CLOUDPEN_SIEM_TOKEN`
- `PUBLIC_APP_ORIGIN` as the canonical HTTPS origin
- D1 binding `DB`

Keep Sites access in private/custom mode. A user must pass both the Sites access policy and application role checks. `/api/admin/readiness` returns `503` until every mandatory production binding is valid.

## Verification

```bash
npm run lint
npm run typecheck
npm test
npm run security:check
npm run security:audit
```

Use `npm run security:audit:all` to include build-only dependencies; tracked exceptions and reachability are documented in the security review.

`npm test` builds from a clean output directory, starts the Worker with temporary loopback D1 state, and exercises authentication, security headers, CSRF rejection, asymmetric signing and adversarial verification, approval separation, two-tenant isolation, connector secret handling, evidence retention, legal holds, logical backup, audit anchors, remediation, runner staging, reporting, and telemetry. CI runs the same gates. `npm run sbom` creates an ignored CycloneDX SBOM for a release artifact.

## Project status

CloudPen is a pre-production security control-plane prototype. It is suitable for local evaluation and continued engineering, but it must not be represented as a functioning cloud penetration-testing service until the runner prerequisites in [the runner security design](./docs/runner-security-design.md) are complete and independently assessed.

## Known limitations

- The current D1 exposure snapshot is explicitly labeled demo data. The schema supports future read-only snapshot ingestion, but no AWS collector is enrolled.
- Runner enrollment is a fingerprint-pinning review record only. There is no delivery channel, AWS credential exchange, module execution, or active validation.
- The KMS signer and SIEM delivery paths are implemented and fail-closed, but they are not operational until provisioned in the approved external accounts and evidenced by post-deployment tests.
- Workspace data is consistently membership-scoped and tested across two tenants, but self-service tenant lifecycle, invitations, SCIM, and periodic access certification are not implemented.
- Logical signed backup exists; an encrypted platform backup/restore drill and measured recovery objectives remain operational gates.
- The CSP nonces every script and blocks script attributes; inline styles remain allowed for framework compatibility.
- Independent assessment and the customer-hosted runner program remain mandatory before real cloud execution.

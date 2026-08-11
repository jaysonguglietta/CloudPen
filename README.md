# CloudPen

CloudPen is a security-first control-plane prototype for cloud attack-path validation. It helps cloud security engineers, red teams, and platform owners review identity chains, create constrained validation plans, preserve evidence integrity, and verify remediation.

This release intentionally does **not** execute AWS APIs. It now provides durable connector, approval, evidence, remediation, reporting, exposure-snapshot, and runner-enrollment workflows while keeping every discovery and execution artifact explicitly non-executable.

## Product brief

- **Target users:** cloud security engineers, authorized red teams, IAM/platform owners, compliance analysts, and security reviewers.
- **Core problem:** policy findings do not prove whether an attacker can traverse a complete cloud identity path; unsafe validation can create a larger incident than the exposure it measures.
- **Primary workflows:** review exposure, inspect an attack chain, create and independently review a validation plan, capture control-mapped screenshot evidence, manage connector/discovery intent, export signed evidence and reports, assign remediation, verify audit integrity, and stage runner enrollment.
- **Main views:** exposure overview, attack paths, assets and identities, validation runs and approvals, connectors, remediation, screenshot evidence, evidence/audit, reports, administration, and guardrails.
- **Key models:** workspace membership, exposure snapshot/graph, connector, validation plan/run, evidence package, screenshot evidence, remediation, runner enrollment, guardrail policy, audit event, and rate-limit bucket.
- **Important edge cases:** unauthenticated or unauthorized users, cross-origin mutations, oversized or malformed bodies, duplicate/racing audit writes, unavailable durable state, unsigned plans, disabled guardrails, and attempts to treat the browser as authoritative.
- **Assumptions:** the hosted Sites access policy remains private; Sites identity headers are injected by the trusted dispatcher; local mode is loopback-only; displayed cloud resources are synthetic sample data.
- **Done for this version:** visible control-plane workflows are backed by D1, demo/live provenance is explicit, exposure records are server-delivered from a D1 snapshot, approval separation is enforced, reports and policies are signed, and cloud execution remains impossible.

## Security architecture

The trust boundary is split into three layers:

1. Sites authenticates the external user and restricts access to approved visitors.
2. CloudPen maps the verified email to an explicit `admin`, `operator`, `reviewer`, or `viewer` role and enforces capabilities again in every API route.
3. D1 owns exposure snapshots, connectors, plans, approvals, evidence manifests, remediation, pending runner enrollment, guardrails, rate limits, and a hash-chained audit log. The browser is only a presentation client.

Mutation endpoints require same-origin requests, validate fields, apply per-user rate limits, and return sanitized errors. JSON bodies are limited to 8 KiB; screenshot multipart uploads are limited to 12 MiB of validated PNG data. Screenshot metadata is workspace-scoped in D1 and image bytes remain private in R2. Evidence exports and plans use HMAC-SHA-256 integrity envelopes. Production safety controls cannot be disabled.

See [SECURITY.md](./SECURITY.md) for the implemented boundary and prerequisites for a future AWS runner.

## Documentation

- [Documentation index](./docs/README.md)
- [Architecture and trust boundaries](./docs/architecture.md)
- [Threat model and adversarial security review](./docs/security-review.md)
- [API reference](./docs/api.md)
- [Screenshot evidence workflow](./docs/screenshot-evidence.md)
- [Configuration and deployment](./docs/deployment.md)
- [Operations and incident response](./docs/operations.md)
- [Runner security design](./docs/runner-security-design.md)
- [Feature delivery status](./docs/feature-roadmap.md)
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

The runtime must provide:

- `CLOUDPEN_ADMIN_EMAILS` and optional operator/reviewer/viewer lists
- `CLOUDPEN_PLAN_SIGNING_KEY` as a unique secret with at least 32 characters
- `PUBLIC_APP_ORIGIN` as the canonical HTTPS origin
- D1 binding `DB`
- private R2 binding `EVIDENCE`

Keep Sites access in private/custom mode. A user must pass both the Sites access policy and application role checks.

## Verification

```bash
npm run lint
npm run typecheck
npm test
npm run security:check
npm run security:audit
```

Use `npm run security:audit:all` to include build-only dependencies; tracked exceptions and reachability are documented in the security review.

`npm test` builds from a clean output directory, starts the Worker with temporary loopback D1 state, and exercises authentication, security headers, CSRF rejection, plan signing, approval separation, connector secret handling, non-executable discovery, evidence retention, remediation state, runner staging, reporting, and audit integrity. CI runs the same gates. `npm run sbom` creates an ignored CycloneDX SBOM for a release artifact.

## Project status

CloudPen is a pre-production security control-plane prototype. It is suitable for local evaluation and continued engineering, but it must not be represented as a functioning cloud penetration-testing service until the runner prerequisites in [the runner security design](./docs/runner-security-design.md) are complete and independently assessed.

## Known limitations

- The current D1 exposure snapshot is explicitly labeled demo data. The schema supports future read-only snapshot ingestion, but no AWS collector is enrolled.
- Runner enrollment is a fingerprint-pinning review record only. There is no delivery channel, AWS credential exchange, module execution, or active validation.
- There is no KMS asymmetric signing, SCIM administration, SIEM delivery, PDF renderer, or external penetration-test attestation yet.
- Workspace data is consistently scoped by `workspace_id`, but the current deployment exposes one configured organization and has no self-service tenant lifecycle.
- HMAC proves server possession of a shared secret; production evidence should move to KMS-backed asymmetric signatures before third-party verification.
- The CSP permits inline framework bootstrap code. A nonce-based CSP is the next browser-hardening step.

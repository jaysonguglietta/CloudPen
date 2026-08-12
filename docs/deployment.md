# Configuration and deployment

## Supported modes

| Mode | Purpose | Identity | State | Network exposure |
| --- | --- | --- | --- | --- |
| Local evaluation | Developer and product evaluation | Explicit loopback development admin | Local Wrangler D1 | `127.0.0.1:8787` only |
| Development | Hot-reload UI work | Development identity on loopback | Cloudflare plugin local D1 binding | `127.0.0.1` only |
| Hosted private | Controlled workspace evaluation | Sites identity plus CloudPen role allowlist | Sites-managed D1 | HTTPS through Sites access policy |

There is no supported self-hosted public deployment and no production AWS runner deployment in this repository.

## Prerequisites

- Node.js 22.13.0 or later
- npm with lockfile support
- dependencies installed with `npm ci` for reproducible builds
- a supported Sites project for hosted deployment

## Environment variables

| Variable | Required | Secret | Description |
| --- | ---: | ---: | --- |
| `CLOUDPEN_ADMIN_EMAILS` | Hosted | No | Comma-separated administrators |
| `CLOUDPEN_OPERATOR_EMAILS` | Optional | No | Comma-separated operators |
| `CLOUDPEN_REVIEWER_EMAILS` | Optional | No | Comma-separated reviewers |
| `CLOUDPEN_VIEWER_EMAILS` | Optional | No | Comma-separated read-only users |
| `CLOUDPEN_PRODUCTION_MODE` | Production | No | Must be `1`; enables fail-closed readiness expectations |
| `CLOUDPEN_WORKSPACE_ID` | Optional | No | Default workspace slug for single-membership/fallback deployments |
| `CLOUDPEN_SIGNER_URL` | Production | No | Exact HTTPS external KMS signer endpoint ending `/v1/sign` |
| `CLOUDPEN_SIGNER_TOKEN` | Production | Yes | High-entropy external signer bearer credential, minimum 32 characters |
| `CLOUDPEN_SIGNING_KEY_ID` | Production | No | Versioned KMS key ARN/identifier bound into every envelope |
| `CLOUDPEN_SIGNING_PUBLIC_JWK` | Production | No | Independently retrieved public RSA JWK; contains no private material |
| `CLOUDPEN_SIEM_URL` | Production | No | Exact independently administered HTTPS endpoint ending `/v1/events` |
| `CLOUDPEN_SIEM_TOKEN` | Production | Yes | High-entropy SIEM delivery bearer credential, minimum 32 characters |

The repository includes deployable AWS reference boundaries under `infra/aws-kms-signer` and `infra/aws-siem-collector`. The SIEM archive uses 90-day S3 Object Lock `COMPLIANCE` retention; select the account and retention commitment deliberately before deployment.
| `PUBLIC_APP_ORIGIN` | Hosted | No | Exact canonical HTTPS origin, with no path or credentials |
| `CLOUDPEN_LOCAL_DEV_EMAIL` | Local only | No | Optional development identity override |
| `CLOUDPEN_LOCAL_MODE` | Local launcher only | No | Enables loopback-only development identity and local ephemeral asymmetric signing |
| `CLOUDPEN_EPHEMERAL_SIGNER` | Tests/local only | No | Enables an in-memory non-exportable RSA test key only on loopback |

Email matching is case-insensitive. If an email occurs in multiple lists, the first role wins in this order: admin, operator, reviewer, viewer. Avoid duplicate membership to keep intent unambiguous.

Never commit a signer/SIEM token or use local/ephemeral mode in a shared environment. The ephemeral local key changes when the Worker restarts and is not suitable for durable verification. Production private keys remain in KMS and never enter Sites. `.env.example` documents names only; all `.env*` values except the example are ignored.

## Durable binding

`.openai/hosting.json` declares D1 binding `DB`. Hosted resource IDs belong to Sites and must not be copied into source. The migrations under `drizzle/` create the control-plane tables and indexes.

## Local build and startup

```bash
npm ci
npm run build
npm start
```

Open `http://127.0.0.1:8787`.

The launcher:

- applies all pending D1 migrations, then invokes the built Worker through Wrangler;
- binds only to IPv4 loopback;
- persists D1 development state under `.wrangler/state`;
- sets local mode and the canonical local origin;
- leaves the service in the foreground so normal process supervision can stop it.

Stop with `Ctrl-C`. Do not reverse-proxy local mode, bind it to a LAN interface, place it in a shared workstation service, or expose the Wrangler Local Explorer endpoint.

## Development server

```bash
npm run dev
```

The development server is also loopback-bound. Use it for UI iteration, not deployment verification. Use `npm start` to validate the built Worker and D1 integration.

## Hosted private deployment requirements

Before deploying:

1. Keep the Sites access policy `custom` or otherwise private to explicitly approved users.
2. Configure the application role allowlists.
3. Deploy and validate `infra/aws-kms-signer` in the approved AWS account; configure its exact URL/token/key ARN and independently retrieved public JWK.
4. Configure and validate the independently administered SIEM contract in `siem-integration.md`.
5. Set the canonical HTTPS origin and `CLOUDPEN_PRODUCTION_MODE=1`.
6. Confirm logical D1 binding `DB`, inspect migrations, and capture a pre-migration platform backup.
7. Run every release gate in `testing-and-release.md`, including signer tests and provenance.
8. Verify that `CLOUDPEN_LOCAL_MODE` and `CLOUDPEN_EPHEMERAL_SIGNER` are absent.
9. Require `/api/admin/readiness` to return `200` and create/independently verify a synthetic plan and audit anchor.
10. Confirm that no AWS credentials, SDK execution, runner service, or outbound command channel exists in the web application.

After deployment, verify unauthenticated denial, unauthorized-user denial, authorized rendering, security headers, D1 plan creation, audit creation, and evidence export using synthetic paths only.

## Rollback

Application rollback and database rollback are separate decisions.

- Prefer deploying the last known-good application version.
- Do not reverse a database migration blindly. Migration `0001` rebuilds `validation_runs` to expand its state constraint, then adds new workflow and exposure tables; preserve a verified backup and test the migration against a copy before hosted rollout.
- Preserve audit and plan records unless an approved retention or incident procedure requires otherwise.
- Revoke the affected KMS key version and signer credential if compromise is suspected. Retain uncompromised historical public keys and signed cutoff evidence under the documented verification policy.

## Production readiness blockers

A hosted UI is not equivalent to a production penetration-testing service. Real cloud use remains blocked on the runner, cryptographic, tenancy, identity lifecycle, retention, monitoring, recovery, compliance, and independent-assessment controls documented elsewhere.

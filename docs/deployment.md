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
| `CLOUDPEN_PLAN_SIGNING_KEY` | Hosted | Yes | Unique high-entropy HMAC key, minimum 32 characters |
| `PUBLIC_APP_ORIGIN` | Hosted | No | Exact canonical HTTPS origin, with no path or credentials |
| `CLOUDPEN_LOCAL_DEV_EMAIL` | Local only | No | Optional development identity override |
| `CLOUDPEN_LOCAL_MODE` | Local launcher only | No | Enables the loopback development identity and key fallback |

Email matching is case-insensitive. If an email occurs in multiple lists, the first role wins in this order: admin, operator, reviewer, viewer. Avoid duplicate membership to keep intent unambiguous.

Never commit a real signing key or use the local fallback in a shared environment. `.env.example` documents keys only; all `.env*` values except the example are ignored.

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

- invokes the built Worker through Wrangler;
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
3. Generate a unique production signing key with a cryptographically secure generator and store it as a Sites secret.
4. Set the canonical HTTPS origin.
5. Confirm logical D1 binding `DB` and inspect the migrations.
6. Run every release gate in `testing-and-release.md`.
7. Verify that `CLOUDPEN_LOCAL_MODE` is absent.
8. Confirm that no AWS credentials, SDK execution, runner service, or outbound command channel is present.

After deployment, verify unauthenticated denial, unauthorized-user denial, authorized rendering, security headers, D1 plan creation, audit creation, and evidence export using synthetic paths only.

## Rollback

Application rollback and database rollback are separate decisions.

- Prefer deploying the last known-good application version.
- Do not reverse a database migration blindly. Migration `0001` rebuilds `validation_runs` to expand its state constraint, then adds new workflow and exposure tables; preserve a verified backup and test the migration against a copy before hosted rollout.
- Preserve audit and plan records unless an approved retention or incident procedure requires otherwise.
- Rotate the signing key if a rollback was triggered by suspected secret exposure; old HMAC packages then require an explicit historical verification policy.

## Production readiness blockers

A hosted UI is not equivalent to a production penetration-testing service. Real cloud use remains blocked on the runner, cryptographic, tenancy, identity lifecycle, retention, monitoring, recovery, compliance, and independent-assessment controls documented elsewhere.

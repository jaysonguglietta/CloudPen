# API reference

All routes are same-origin application routes. They are not a public API and do not support bearer tokens, cross-origin browser clients, or arbitrary service integrations.

## Authentication and authorization

Hosted requests receive trusted Sites identity headers. CloudPen maps the normalized email to the first matching environment allowlist and enforces a capability in each route.

| Role | Read | Capture screenshot | Create plan/remediation | Request connector | Configure/enroll | Approve |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Admin | Yes | Yes | Yes | Yes | Yes | Yes, except own request |
| Operator | Yes | Yes | Yes | Yes | No | No |
| Reviewer | Yes | Yes | No | No | No | Yes, except own request |
| Viewer | Yes | No | No | No | No | No |

Local mode supplies a loopback-only development administrator. Do not use local mode in a shared or hosted environment.

## Mutation requirements

JSON mutations require:

- `Content-Type: application/json`;
- an `Origin` exactly equal to the request URL origin;
- `Sec-Fetch-Site: same-origin` when the browser sends it;
- a body no larger than 8,192 UTF-8 bytes;
- a top-level JSON object;
- a role with the required capability.

Mutation requests that do not meet these conditions are rejected before business logic. Responses under `/api/` are `Cache-Control: no-store, private` after Worker hardening.

`POST /api/screenshots` instead requires same-origin `multipart/form-data`, a total request below 13 MiB, and a PNG payload no larger than 12 MiB. The same Origin and Fetch Metadata rules apply.

## `GET /api/validation-runs`

Returns up to 100 server-owned runs in descending creation order.

- Capability: `read`
- Rate limit: 120 requests per normalized user email per 60 seconds
- Response: `200`

```json
{
  "runs": [
    {
      "id": "RUN-7A2F81C4",
      "name": "CP-1042 · CI role can become production administrator",
      "mode": "Read-only",
      "status": "Planned",
      "pathCount": 1,
      "findings": 0,
      "requestedBy": "Security Administrator",
      "started": "Jul 31, 2026, 1:20 PM",
      "duration": "Not executed"
    }
  ]
}
```

## `POST /api/validation-runs`

Creates, signs, stores, and audits a non-executable validation plan.

- Capability: `plan`
- Rate limit: 10 plans per normalized user email per 60 seconds
- Success: `201`

Request:

```json
{
  "attackPathId": "CP-1042",
  "mode": "Read-only",
  "acknowledged": false
}
```

Rules:

- `attackPathId` must match `CP-` plus four digits and exist in the server's synthetic catalog.
- `mode` must be `Read-only` or `Active canary`.
- Active canary requires `acknowledged: true` and all core guardrails.
- Read-only returns `Planned`; active canary returns `Awaiting approval`.
- The receipt always returns `executable: false`.

Response excerpt:

```json
{
  "run": {
    "id": "RUN-7A2F81C4",
    "status": "Planned",
    "duration": "Not executed"
  },
  "receipt": {
    "algorithm": "HMAC-SHA-256",
    "keyId": "cloudpen-plan-v1",
    "authorizationDigest": "base64url-sha256",
    "signature": "base64url-hmac",
    "executable": false
  }
}
```

The receipt signature covers the canonical internal plan, including workspace, path, mode, status, requester, creation and expiry timestamps, guardrails, and the non-executable flag.

## `GET /api/guardrails`

Returns the current server-owned guardrail policy.

- Capability: `read`
- Response: `200`

```json
{
  "policy": {
    "requireApproval": true,
    "canaryOnly": true,
    "redactEvidence": true,
    "cleanupRequired": true,
    "maxConcurrency": 2,
    "maxSessionMinutes": 15
  }
}
```

## `PATCH /api/guardrails`

Attempts to change exactly one supported Boolean policy property.

- Capability: `configure` (admin)
- Rate limit: 20 configuration requests per normalized user email per 60 seconds
- Success: `200`

```json
{
  "redactEvidence": true
}
```

This release rejects setting `requireApproval`, `canaryOnly`, `redactEvidence`, or `cleanupRequired` to false. The route exists to preserve a server-owned configuration flow; the production safety floor is immutable through this API.

## `POST /api/connectors`

Records a connector-provisioning request. It does not contact AWS, issue CloudFormation, assume a role, or store credentials.

- Capability: `connect`
- Rate limit: 5 requests per normalized user email per 300 seconds
- Success: `202`

```json
{
  "name": "Payments Production",
  "accountId": "123456789012",
  "externalId": "customer-unique-context"
}
```

Validation:

- name: 2–80 trimmed characters;
- account ID: exactly 12 digits;
- External ID: 8–128 characters from the explicit safe character set.

Only a SHA-256 digest and four-character hint of the External ID are persisted. The raw value is not retained or returned.

Response:

```json
{
  "id": "CON-4D8A21BC",
  "status": "Runner required"
}
```

## `GET /api/evidence/{pathId}`

Generates a redacted signed evidence package for a known synthetic path.

- Capability: `read`
- Rate limit: 20 exports per normalized user email per 60 seconds
- Success: `200 application/json`
- Disposition: attachment
- Caching: disabled

The response contains a `payload` and an `integrity` envelope with SHA-256 digest and HMAC-SHA-256 signature. Credentials, tokens, customer payloads, and raw cloud responses are not part of the package.

The export also creates a retained evidence-manifest row containing package ID, path, classification, digest, key ID, actor, and timestamp. The package body is not retained in D1.

## Screenshot evidence routes

### `GET /api/screenshots`

Returns up to 100 newest workspace-scoped records. Optional parameters are `framework`, `control`, and `q`. A control may only be supplied with its matching framework; free-text search is limited to 100 characters and matches title, filename, notes, and control label.

- Capability: `read`
- Rate limit: 120 requests per user per 60 seconds
- Caching: disabled

### `POST /api/screenshots`

Accepts one browser-generated, banner-stamped PNG as multipart form data.

- Capability: `capture` (admin, operator, reviewer)
- Rate limit: 20 captures per user per 10 minutes
- Success: `201`
- Maximum PNG: 12 MiB, 12,000 pixels on either axis, and 60 megapixels

Required fields are `image`, `frameworkId`, `controlId`, `title`, `customName`, `bannerPosition`, `capturedAt`, and `authorized=true`. Optional/display fields are `notes`, `includeTimestamp`, and `includeActor`. The service validates the framework/control pair against the built-in catalog, checks the PNG signature and IHDR dimensions, restricts the capture clock to ±10 minutes, normalizes the filename, calculates SHA-256, stores the object privately in R2, writes metadata to D1, and appends an audit event.

Storage keys are server-derived and follow this logical layout:

```text
<workspace>/screenshots/<framework>/<control>/<YYYY>/<MM>/<record-id>--<generated-file>.png
```

The returned `folderPath` omits the workspace and internal record prefix so it is safe to show in the UI.

### `GET /api/screenshots/{screenshotId}/content`

Streams an authorized workspace screenshot through the application. `?download=1` changes `Content-Disposition` from inline to attachment. Responses are private, non-cacheable PNGs and include `X-CloudPen-SHA256` for integrity comparison. R2 has no public object URL.

## Additional control-plane routes

| Route | Capability | Behavior |
| --- | --- | --- |
| `GET /api/control-plane` | `read` | Returns workspace provenance, runs, connectors, evidence manifests, remediation, runners, audit events, and chain-verification status |
| `PATCH /api/validation-runs/{runId}` | `approve` or `plan` | Approves, rejects, or cancels an eligible plan with a required reason; never makes it executable |
| `POST /api/remediations` | `plan` | Creates an owned, due-dated remediation linked to a known path |
| `PATCH /api/remediations/{id}` | `plan` | Moves remediation through the supported workflow states |
| `POST /api/connectors/{id}/discovery` | `connect` | Records a bounded AWS metadata-read-only discovery plan with `executable: false` |
| `GET /api/guardrails/export` | `read` | Downloads a signed, non-executable policy envelope |
| `GET /api/reports/export` | `read` | Downloads a signed assessment derived from current exposure and workflow state |
| `POST /api/runners` | `enroll` (admin) | Pins a public-key fingerprint in `Pending` state with database-enforced `executable = 0` |

### Approval rules

- Only `Awaiting approval` plans may be approved or rejected.
- The requester cannot approve or reject their own active plan.
- The decision reason is required and audit logged.
- Approved intent remains non-executable and expires with the original plan.
- The requester or administrator may cancel an eligible plan.

## Errors

| Status | Meaning |
| ---: | --- |
| 400 | Invalid JSON shape, field, path, mode, acknowledgement, or policy transition |
| 404 | Workspace-scoped record does not exist |
| 409 | Duplicate connector/remediation or an invalid state transition |
| 403 | Missing application membership, insufficient role, or cross-origin mutation |
| 413 | JSON exceeds 8 KiB or screenshot upload exceeds its multipart/PNG limit |
| 415 | Mutation uses the wrong JSON or multipart media type |
| 429 | Per-identity operation rate limit exceeded |
| 500 | Durable state or security configuration unavailable; internal detail is suppressed |

Errors use `{ "error": "safe message" }`. Internal stack traces, SQL details, binding identifiers, and secret values are never returned.

# API reference

All routes are same-origin application routes. They are not a public API and do not support bearer tokens, cross-origin browser clients, or arbitrary service integrations.

## Authentication and authorization

Hosted requests receive trusted Sites identity headers. CloudPen maps the normalized email to the first matching environment allowlist and enforces a capability in each route.

| Role | Read | Create plan | Request connector | Configure guardrails | Approve |
| --- | ---: | ---: | ---: | ---: | ---: |
| Admin | Yes | Yes | Yes | Yes | Reserved; no endpoint |
| Operator | Yes | Yes | Yes | No | No |
| Reviewer | Yes | No | No | No | Reserved; no endpoint |
| Viewer | Yes | No | No | No | No |

Local mode supplies a loopback-only development administrator. Do not use local mode in a shared or hosted environment.

## Mutation requirements

Every mutation requires:

- `Content-Type: application/json`;
- an `Origin` exactly equal to the request URL origin;
- `Sec-Fetch-Site: same-origin` when the browser sends it;
- a body no larger than 8,192 UTF-8 bytes;
- a top-level JSON object;
- a role with the required capability.

Mutation requests that do not meet these conditions are rejected before business logic. Responses under `/api/` are `Cache-Control: no-store, private` after Worker hardening.

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

Only a SHA-256 digest of the External ID is written to the audit event. The raw value is not persisted.

Response:

```json
{
  "status": "awaiting-runner-provisioning"
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

## Errors

| Status | Meaning |
| ---: | --- |
| 400 | Invalid JSON shape, field, path, mode, acknowledgement, or policy transition |
| 403 | Missing application membership, insufficient role, or cross-origin mutation |
| 413 | Body exceeds 8 KiB |
| 415 | Mutation is not JSON |
| 429 | Per-identity operation rate limit exceeded |
| 500 | Durable state or security configuration unavailable; internal detail is suppressed |

Errors use `{ "error": "safe message" }`. Internal stack traces, SQL details, binding identifiers, and secret values are never returned.

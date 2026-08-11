# API reference

All routes are same-origin application routes. They are not a public API and do not support bearer tokens, cross-origin browser clients, or arbitrary service integrations.

## Authentication and authorization

Hosted requests receive trusted Sites identity headers. CloudPen maps the normalized email to the first matching environment allowlist and enforces a capability in each route.

| Role | Read | Create plan/remediation | Request connector | Configure/enroll | Approve |
| --- | ---: | ---: | ---: | ---: | ---: |
| Admin | Yes | Yes | Yes | Yes | Yes, except own request |
| Operator | Yes | Yes | Yes | No | No |
| Reviewer | Yes | No | No | No | Yes, except own request |
| Viewer | Yes | No | No | No | No |

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
  "externalId": "cpv1_<43-character-base64url-value>"
}
```

Validation:

- name: 2–80 trimmed characters;
- account ID: exactly 12 digits;
- External ID: `cpv1_` followed by the 43-character unpadded base64url encoding of 256 random bits generated in the browser. Repeated/known-pattern values are rejected.

The External ID is validated and discarded. No raw value, hint, plain digest, or keyed verifier is retained or returned. The user must copy it into the customer-controlled AWS trust configuration before leaving the dialog.

Response:

```json
{
  "id": "CON-4D8A21BC",
  "status": "Runner required"
}
```

## `POST /api/evidence/{pathId}`

Generates a redacted signed evidence package for a known synthetic path.

- Capability: `read`
- Request: same-origin `application/json` with an empty `{}` body
- Rate limit: 20 exports per normalized user email per 60 seconds
- Success: `200 application/json`
- Disposition: attachment
- Caching: disabled

The response contains a `payload` and an `integrity` envelope with SHA-256 digest and HMAC-SHA-256 signature. Credentials, tokens, customer payloads, and raw cloud responses are not part of the package.

The export also creates a retained evidence-manifest row containing package ID, path, classification, digest, key ID, actor, and timestamp. The package body is not retained in D1.

## Additional control-plane routes

| Route | Capability | Behavior |
| --- | --- | --- |
| `GET /api/control-plane` | `read` | Returns workspace provenance, runs, connectors, evidence manifests, remediation, runners, audit events, and chain-verification status |
| `PATCH /api/validation-runs/{runId}` | `approve` or `plan` | Approves, rejects, or cancels an eligible plan with a required reason; never makes it executable |
| `POST /api/remediations` | `plan` | Creates an owned, due-dated remediation linked to a known path |
| `PATCH /api/remediations/{id}` | `plan` | Moves remediation through the supported workflow states |
| `POST /api/connectors/{id}/discovery` | `connect` | Records a bounded AWS metadata-read-only discovery plan with `executable: false` |
| `POST /api/connectors/{id}/external-id` | `connect` | Validates a newly generated one-time External ID, records rotation, returns the connector to `Runner required`, and retains no value or digest |
| `GET /api/guardrails/export` | `read` | Downloads a signed, non-executable policy envelope |
| `POST /api/reports/export` | `read` | Downloads a signed assessment derived from current exposure and workflow state; requires same-origin JSON `{}` |
| `POST /api/runners` | `enroll` (admin) | Pins a public-key fingerprint in `Pending` state with database-enforced `executable = 0` |

Remediation transitions are server-governed: `Open` may move to `In progress` or `Risk accepted`; `In progress` may move to `Risk accepted` or `Ready to revalidate`; `Risk accepted` may return to `In progress`; and `Ready to revalidate` may return to `In progress` or close. `Closed` is terminal. Every request supplies the current integer `version` and an 8–500 character `reason`; concurrent stale transitions return `409`.

- Operators and administrators may perform ordinary progress/revalidation transitions.
- Only administrators may accept risk. The request must include `riskAcceptanceExpiresAt` no more than 365 days in the future; actor, reason, and expiry are retained.
- Administrators and reviewers may close a remediation only from `Ready to revalidate` and only with a retained `revalidationEvidenceId` for the same attack path.
- Viewers cannot transition remediation records.

### Approval rules

- Only `Awaiting approval` plans may be approved or rejected.
- The requester cannot approve or reject their own active plan.
- The decision reason is required and audit logged.
- Approved intent remains non-executable and expires with the original plan.
- The requester or administrator may cancel an eligible plan.
- Approval, rejection, and cancellation use compare-and-set status and expiry predicates; only one concurrent decision can commit.

## Errors

| Status | Meaning |
| ---: | --- |
| 400 | Invalid JSON shape, field, path, mode, acknowledgement, or policy transition |
| 404 | Workspace-scoped record does not exist |
| 409 | Duplicate connector/remediation or an invalid state transition |
| 403 | Missing application membership, insufficient role, or cross-origin mutation |
| 413 | JSON exceeds 8 KiB |
| 415 | Mutation does not use `application/json` |
| 429 | Per-identity operation rate limit exceeded |
| 500 | Durable state or security configuration unavailable; internal detail is suppressed |

Errors use `{ "error": "safe message" }`. Internal stack traces, SQL details, binding identifiers, and secret values are never returned.

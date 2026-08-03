# Architecture and trust boundaries

## Current scope

CloudPen is a single-workspace, AWS-themed attack-path validation control plane. The current code renders synthetic topology, accepts constrained plan requests, stores control-plane records, and exports signed synthetic evidence. It performs no AWS API calls and has no runner communication channel.

## System context

```mermaid
flowchart LR
  U["Authorized user"] -->|HTTPS| S["Sites access policy and identity"]
  S -->|Trusted identity headers| W["Cloudflare Worker / Vinext"]
  W --> P["Next server routes"]
  P --> A["Application RBAC and request controls"]
  A --> C["Control-plane service"]
  C --> D[("Cloudflare D1")]
  W --> B["Browser dashboard"]
  C -. "No channel exists" .-> R["Future customer-hosted runner"]
  R -. "Disabled" .-> AWS["Customer AWS accounts"]
```

## Components

| Component | Responsibility | Security notes |
| --- | --- | --- |
| Sites dispatcher | External access restriction and user identity | Identity only; application role checks remain mandatory |
| Worker | Request entry point, runtime bindings, response hardening, image handling | Removes identifying headers; applies CSP, framing, MIME, privacy, and transport controls |
| Server page | Requires identity and application membership before rendering the dashboard | Per-request dynamic rendering prevents shared authenticated output |
| API routes | Parse request contracts and require capabilities | Mutation routes require same-origin JSON and bounded bodies |
| Control-plane service | Business rules, plan signing, evidence packaging, audit chaining, rate limits | Server-only module; browser cannot mark runs complete or executable |
| D1 | Durable workspace, membership, guardrail, validation, audit, and rate-limit state | Queries use prepared statements; current prototype uses one fixed workspace |
| Browser dashboard | Presentation and user interaction | Synthetic topology is client-visible; browser state is non-authoritative |

## Trust boundaries

### 1. Untrusted client to trusted dispatcher

Attackers can control request methods, headers, bodies, timing, and browser state. Hosted production must be reachable only through the Sites dispatcher. Direct exposure of the Worker behind an untrusted proxy would make identity-header provenance an open question and is not supported by this design.

### 2. Dispatcher identity to application authorization

An authenticated email is mapped server-side to one role through environment allowlists. A Sites visitor without an application role is denied. Role order is deterministic: admin, operator, reviewer, then viewer.

### 3. API route to durable state

Route handlers validate method-specific contracts before invoking the control-plane service. The service uses prepared D1 statements, fixed workspace scoping, and server-derived actor identity. Request-provided identities, workspace IDs, statuses, signatures, and timestamps are not accepted.

### 4. Control plane to future runner

No connection exists. Plans contain `executable: false`; active canary plans stop at `Awaiting approval`. Adding a runner changes the highest-risk trust boundary and requires the mandatory design in `runner-security-design.md`.

## Request flow: validation plan

```mermaid
sequenceDiagram
  participant User
  participant API as Validation API
  participant Auth as RBAC and request controls
  participant CP as Control-plane service
  participant DB as D1

  User->>API: POST same-origin JSON
  API->>Auth: Check content type, size, Origin, role
  Auth-->>API: Authorized operator/admin
  API->>CP: Path ID, mode, acknowledgement
  CP->>DB: Load enforced guardrails and rate bucket
  CP->>CP: Build canonical expiring non-executable plan
  CP->>CP: SHA-256 digest and HMAC-SHA-256 signature
  CP->>DB: Insert plan and chained audit event
  CP-->>User: Run projection and signed receipt
```

## Deployment modes

### Local evaluation

`npm start` runs the built Worker through Wrangler on `127.0.0.1:8787`. Local mode supplies a development-only administrator identity and signing key, and D1 persists under the ignored `.wrangler/state` directory. This is not an authentication model for shared environments.

### Hosted private deployment

Sites provides identity, private/custom access, D1 binding injection, and environment variables. Local mode must be absent. The hosted administrator/operator/reviewer/viewer lists and a unique production signing key are required.

## Security invariants

1. The browser is never authoritative for roles, approvals, execution, evidence, or audit history.
2. Cloud execution is impossible in this release.
3. Every issued plan is scoped, expiring, signed, stored, logged, and non-executable.
4. Core safety guardrails cannot be disabled through the API.
5. Unauthenticated, unauthorized, cross-origin, malformed, oversized, and over-limit requests fail closed.
6. Missing D1 or signing configuration fails the operation rather than falling back to browser storage.

## Known architectural limitations

- The workspace identifier is fixed to `northstar-labs`; this is not multi-tenant architecture.
- Synthetic account, asset, and path data is bundled into the client.
- HMAC signatures require shared-secret verification and are not suitable for independent third-party attestation.
- Runtime schema initialization duplicates the migration as a compatibility measure and must remain synchronized.
- The framework currently requires inline bootstrap code in the CSP.

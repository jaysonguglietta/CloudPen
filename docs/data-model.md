# Data model

CloudPen stores control-plane and exposure-snapshot metadata in D1. The authoritative schema is declared in `db/schema.ts`; migrations upgrade the baseline without discarding existing plans.

```mermaid
erDiagram
  WORKSPACES ||--o{ MEMBERSHIPS : contains
  WORKSPACES ||--|| GUARDRAIL_POLICIES : enforces
  WORKSPACES ||--o{ VALIDATION_RUNS : owns
  WORKSPACES ||--o{ CONNECTORS : owns
  WORKSPACES ||--o{ EVIDENCE_PACKAGES : retains
  WORKSPACES ||--o{ REMEDIATIONS : tracks
  WORKSPACES ||--o{ RUNNER_ENROLLMENTS : stages
  WORKSPACES ||--o{ EXPOSURE_SNAPSHOTS : collects
  EXPOSURE_SNAPSHOTS ||--o{ CLOUD_ACCOUNTS : contains
  EXPOSURE_SNAPSHOTS ||--o{ CLOUD_ASSETS : contains
  EXPOSURE_SNAPSHOTS ||--o{ EXPOSURE_PATHS : computes
  EXPOSURE_SNAPSHOTS ||--o{ GRAPH_EDGES : connects
  WORKSPACES ||--o{ AUDIT_EVENTS : records

  WORKSPACES {
    text id PK
    text name
    text data_mode
    text created_at
  }
  MEMBERSHIPS {
    text id PK
    text workspace_id
    text email
    text role
    text created_at
  }
  GUARDRAIL_POLICIES {
    text workspace_id PK
    boolean require_approval
    boolean canary_only
    boolean redact_evidence
    boolean cleanup_required
    integer max_concurrency
    integer max_session_minutes
    text updated_by
    text updated_at
  }
  VALIDATION_RUNS {
    text id PK
    text workspace_id
    text attack_path_id
    text mode
    text status
    text requested_by
    text approved_by
    text authorization_digest
    text plan_signature
    text expires_at
    text decision_reason
    integer findings
    text created_at
    text updated_at
  }
  AUDIT_EVENTS {
    text id PK
    text workspace_id
    text actor_email
    text action
    text target
    text details_json
    text previous_hash
    text event_hash
    text created_at
  }
  RATE_LIMITS {
    text key PK
    integer count
    integer expires_at
  }
```

## Table semantics

### `workspaces`

Contains the configured organization and an explicit `demo` or `live` provenance mode. Every product table and query is workspace scoped. Self-service workspace creation, deletion, switching, and cross-organization administration are intentionally not exposed yet.

### `memberships`

Records users observed after successful environment-allowlist authorization. The environment allowlist remains the authorization source in this release; a membership row alone does not grant access.

Roles:

- `admin`: read, create plans/remediation, configure, request connectors, approve another requester's plan, and stage runner enrollment.
- `operator`: read, create plans, and request connectors.
- `reviewer`: read and approve or reject another requester's active plan.
- `viewer`: read only.

### `guardrail_policies`

Stores mandatory execution-policy values. The current API rejects any attempt to disable approval, canary restriction, evidence redaction, or cleanup. Maximum concurrency and session duration are database constrained but not currently editable through the API.

### `validation_runs`

Stores server-issued plans and integrity data. Control-plane transitions include `Planned`, `Awaiting approval`, `Approved`, `Rejected`, `Expired`, and `Stopped`. Approval requires a distinct identity and still grants no execution capability.

### Connector and workflow tables

- `connectors` retains AWS account identity, owner, status, synchronization state, and the explicit marker `external_id_status = not-retained`. External IDs and reusable derivatives are absent from the current control-plane schema.
- `evidence_packages` retains signed-manifest metadata while the exported evidence body remains ephemeral.
- `remediations` tracks owner, due date, severity, guidance, optimistic-concurrency version, transition reason, accountable risk acceptance/expiry, revalidation evidence, and a server-governed workflow. A partial unique index permits at most one non-closed remediation per workspace/path.
- `discovery_jobs` stores read-only AWS metadata scope with a database check forcing `executable = 0`.
- `runner_enrollments` pins a reviewed public-key fingerprint in `Pending` or `Disabled` state, also with database-enforced `executable = 0`.

### Exposure graph tables

- `exposure_snapshots` identifies the collection source, status, and timestamp.
- `cloud_accounts`, `cloud_assets`, and `exposure_paths` contain normalized server-owned projections for a snapshot.
- `graph_edges` records directional relationships and bounded evidence metadata used to reconstruct attack reachability.

The current snapshot is a deterministic `demo-seed`. These tables are the ingestion boundary for a future customer-hosted read-only AWS collector; the browser no longer supplies authoritative topology.

### `audit_events`

Stores application-append-only events. Each event hashes its canonical content and the previous event hash. A unique `(workspace_id, previous_hash)` index prevents two successors from silently branching the same chain link. The chain is tamper-evident, not immutable against a database administrator; external anchoring is a future requirement.

### `rate_limits`

Stores per-identity counters and Unix expiry timestamps. Keys include the operation class and normalized email. Expired rows may be overwritten; scheduled garbage collection is not yet implemented.

## Mutation and audit atomicity

Security-relevant state changes and their hash-chained audit rows commit in one D1 batch. Conditional updates use compare-and-set predicates, and the audit insert is conditional on exactly one changed row. Audit-tip conflicts are retried with a newly derived chain link, so a failed audit write rolls back its paired mutation. Chain verification reads every row in bounded pages instead of treating histories over a fixed row count as invalid.

## Data classification

| Data | Classification | Current handling |
| --- | --- | --- |
| User email and display name | Internal personal data | Server-derived; email persisted for attribution |
| AWS account ID in connector audit | Confidential tenant metadata | Accepted only after validation; stored in audit details |
| External ID | Confidential confused-deputy context | Browser-generated from 256 random bits; validated then discarded with no raw value, hint, or digest logged |
| Signing key | Secret | Environment secret only; never stored in D1 or returned |
| Plan digest and HMAC | Integrity metadata | Stored and returned in plan receipt |
| Evidence observations | Synthetic confidential sample | Returned in a signed, non-cacheable download |
| Cloud topology | Synthetic sample | Seeded into D1 and server-delivered with explicit demo provenance |

## Retention

Automated retention is not implemented. Before accepting real personal or tenant data, define per-table retention, legal hold, deletion, export, backup, and restoration procedures. Rate-limit rows should have periodic expiry cleanup; audit and plan retention should be driven by security and compliance requirements rather than indefinite storage by default.

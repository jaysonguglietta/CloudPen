# Feature delivery status

This document tracks the implementation sequence without confusing administrative intent with cloud execution.

## Delivered control-plane capabilities

- Explicit demo/live provenance and authoritative empty workflow states.
- URL-addressable product views and a protected help center.
- Server-owned D1 exposure snapshots for accounts, assets, paths, and graph edges.
- Signed validation plans with expiry, detail receipts, cancel, approve, and reject transitions.
- Separation of duties: a requester cannot approve or reject their own active plan.
- Durable AWS connector records with browser-generated 256-bit External IDs that are validated, never retained, and explicitly rotatable.
- Non-executable metadata-read-only discovery plans.
- Evidence manifests, signed evidence downloads, audit-chain viewer, and chain verification.
- Owned, due-dated remediation records with risk acceptance and revalidation states.
- Signed assessment and guardrail exports.
- Pending runner-enrollment records pinned to a SHA-256 public-key fingerprint.
- Database constraints forcing discovery jobs and runner enrollments to remain non-executable.
- Versioned KMS-compatible PS256 signing, signed approvals/audit anchors/backup manifests, and an independent pinned-key verifier.
- Membership-derived workspace isolation with two-tenant adversarial tests.
- Direct SIEM delivery with durable failure outbox, legal holds, lifecycle maintenance, and signed logical backup.
- Tagged-release SBOM and build provenance attestation workflow.

## Partially delivered foundations

### AWS discovery

The schema, connector lifecycle, service allowlist, and discovery-plan envelope exist. The actual collector does not. Completing this phase requires a separately deployed customer-hosted component, account-ownership proof, short-lived workload identity, bounded egress, and normalized ingestion into a new `aws-read-only` exposure snapshot.

### Tenant isolation

All product records and queries carry membership-derived `workspace_id`; request bodies cannot choose a tenant, and automated tests exercise two workspaces. Self-service workspace creation/switching, invitations, SCIM, access certification, and tenant-specific signing keys remain launch gates for broad multi-customer service.

### Reporting and integrations

Signed JSON assessment export and direct SIEM delivery are available. PDF generation, Jira/GitHub routing, general webhooks, SLA notifications, and scheduled revalidation remain outside the current boundary.

### AI analyst

No model is connected. A future advisory assistant may explain paths, compare snapshots, and draft remediation only after tenant-scoped retrieval, prompt-injection controls, evidence citations, privacy configuration, and human review are implemented. It must never create runner commands.

## Execution launch gates

Active cloud validation remains disabled until every mandatory control in `runner-security-design.md` is implemented and independently tested. A pending enrollment fingerprint is not runner identity, and a correctly signed approved plan is still not execution authority without runner binding, atomic nonce consumption, module policy, workload identity, kill switch, and cleanup proof.

The next safe engineering milestone is the customer-hosted read-only AWS collector. Active-canary execution follows only after single-use delivery, runner/account binding, module allowlisting, independent policy verification, customer kill switch, cleanup proof, evidence attestation, and independent assessment are complete.

# Feature delivery status

This document tracks the implementation sequence without confusing administrative intent with cloud execution.

## Delivered control-plane capabilities

- Explicit demo/live provenance and authoritative empty workflow states.
- URL-addressable product views and a protected help center.
- Server-owned D1 exposure snapshots for accounts, assets, paths, and graph edges.
- Signed validation plans with expiry, detail receipts, cancel, approve, and reject transitions.
- Separation of duties: a requester cannot approve or reject their own active plan.
- Durable AWS connector records that retain only an External ID digest and hint.
- Non-executable metadata-read-only discovery plans.
- Evidence manifests, signed evidence downloads, audit-chain viewer, and chain verification.
- Authorized one-frame screenshot capture with control-dependent framework selectors, visible control banners, normalized names/folders, private R2 storage, D1 metadata, and searchable evidence cards.
- Owned, due-dated remediation records with risk acceptance and revalidation states.
- Signed assessment and guardrail exports.
- Pending runner-enrollment records pinned to a SHA-256 public-key fingerprint.
- Database constraints forcing discovery jobs and runner enrollments to remain non-executable.

## Partially delivered foundations

### AWS discovery

The schema, connector lifecycle, service allowlist, and discovery-plan envelope exist. The actual collector does not. Completing this phase requires a separately deployed customer-hosted component, account-ownership proof, short-lived workload identity, bounded egress, and normalized ingestion into a new `aws-read-only` exposure snapshot.

### Tenant isolation

All product records and queries carry the configured `workspace_id`; request bodies cannot choose a tenant. The current hosted/local deployment exposes one organization. Self-service workspace creation, switching, invitations, SCIM, tenant-specific keys, and automated cross-tenant negative testing remain launch gates before a multi-customer service.

### Reporting and integrations

Signed JSON assessment export is available. PDF generation, Jira/GitHub routing, SIEM delivery, webhooks, SLA notifications, and scheduled revalidation remain outside the current outbound-network boundary.

### Compliance evidence catalogs

Screenshot collection includes curated HIPAA, PCI DSS, FedRAMP/NIST, SOC 2, ISO 27001, and NIST CSF references. Full authoritative catalogs, OSCAL import, organization-defined controls, evidence approval, automated redaction, retention policies, and bulk audit packages remain future work.

### AI analyst

No model is connected. A future advisory assistant may explain paths, compare snapshots, and draft remediation only after tenant-scoped retrieval, prompt-injection controls, evidence citations, privacy configuration, and human review are implemented. It must never create runner commands.

## Execution launch gates

Active cloud validation remains disabled until every mandatory control in `runner-security-design.md` is implemented and independently tested. A pending enrollment fingerprint is not runner identity, an approved plan is not execution authority, and an HMAC envelope is not suitable for independent runner verification.

The next safe engineering milestone is the customer-hosted read-only AWS collector. Active-canary execution follows only after asymmetric signing, single-use delivery, module allowlisting, independent policy verification, customer kill switch, cleanup proof, and evidence attestation are complete.

# Data lifecycle, legal hold, backup, and recovery

CloudPen stores workspace memberships, cloud account identifiers, synthetic or future normalized topology, validation intent, approvals, evidence metadata, remediation workflow, public signing keys, audit history, audit anchors, and privacy-minimized security-event delivery state. External IDs, AWS credentials, signing private keys, signer/SIEM tokens, raw request bodies, and raw cloud response payloads are not retained.

Default policy:

| Data | Default | Destruction condition |
| --- | --- | --- |
| Expired rate counters | Remove on maintenance | Expired and workspace-scoped |
| Delivered SIEM outbox records | 7 days after confirmed delivery | No active legal hold |
| Undelivered SIEM records | Until delivered or incident disposition | Never age out silently |
| Plans, approvals, evidence metadata | 1 year | Verified backup, legal-hold check, approved customer/privacy workflow |
| Audit events and signed anchors | 7 years | Verified external archive/anchor and approved security/compliance procedure |
| Memberships/current configuration | Active lifecycle | Explicit authorized administration, never time-only deletion |

`GET /api/admin/lifecycle` reports holds, eligible operational records, SIEM backlog, policy, and the latest audit anchor. `POST` actions create/release a reasoned legal hold or run bounded maintenance. Every change is capability-checked, same-origin, rate-limited, and audited.

`POST /api/admin/backup` creates a bounded logical workspace export. It omits secrets and transient rate/SIEM records, includes required public verification keys, canonicalizes the archive, hashes it, and signs a manifest. It is a portability and investigation control, not a replacement for encrypted platform backup and point-in-time recovery.

Verify both the archive digest/row counts and the signed manifest with an independently distributed keyset:

```bash
npm run verify:backup -- cloudpen-workspace-backup.json --keyset trusted-keyset.json --workspace northstar-labs
```

Production restore drill:

1. Create a signed audit anchor and logical backup; store them in encrypted, access-controlled recovery storage.
2. Create a platform D1 backup/snapshot under the approved platform process.
3. Restore into an isolated non-production project with no signer or SIEM production credentials.
4. Apply only reviewed forward-compatible migrations.
5. Verify the logical archive digest and manifest using an independently pinned public key.
6. Verify every workspace audit chain and compare the restored chain head to the signed anchor.
7. Run the complete integration suite and synthetic RBAC/tenant-isolation checks.
8. Record restore duration, recovered timestamp, measured RPO/RTO, operator, approver, and discrepancies.
9. Destroy the isolated recovery copy under the approved process unless retained as incident evidence.

No restore operation is exposed through the web API; restoration is deliberately an operator-controlled platform procedure.

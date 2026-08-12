# Production hardening program

## Release posture

CloudPen is fail-closed for production configuration and remains non-executable for cloud actions. Source completion is not the same as operational evidence: `/api/admin/readiness` returns `503` until production mode, a durable database, HTTPS origin, external KMS signer, pinned public key, and independently administered SIEM delivery are all configured. Local and ephemeral signing modes cause the production gate to fail.

## Implemented in this repository

| Control | Implementation | Verification |
| --- | --- | --- |
| Artifact signing | Versioned `cloudpen.signed-artifact.v2` envelopes, RSA-PSS SHA-256, domain/workspace/audience/nonce/expiry binding, key registry, revocation status | Integration tests reject payload tampering, wrong tenant/audience, replay, expiry, revoked keys, and algorithm downgrade |
| Non-exportable production key | Deployable AWS SAM stack with RSA-3072 KMS key, sign-only Lambda role, strict protocol parser, generated bearer credential, API throttles, logs, tracing, and alarms | Four signer unit tests plus post-deployment synthetic known-answer check |
| Approval integrity | Stored plan payload/envelope/signature is reverified before any decision; signed approval binds the plan digest, requester, approver, decision, reason, workspace, and expiry | Separation-of-duties and concurrent-decision integration tests |
| Tenant isolation | Workspace comes from authenticated membership context, is included in every query/rate key/signature/audit event, and cannot be selected by request body | Two-workspace positive and negative integration tests |
| Mutation/audit atomicity | Database batch includes the mutation, linked audit insert, and a constraint sentinel that rolls back unaudited writes | Concurrent decision and workflow tests |
| Audit anchoring | Administrators can create long-lived signed chain-head anchors linked to the previous anchor | Chain validation and signed-anchor integration test |
| SIEM delivery | Privacy-minimized security events are sent to an exact HTTPS `/v1/events` endpoint; failures enter a D1 outbox with digest, bounded retries, and backoff. A separately deployable AWS receiver validates the contract and stores accepted events under S3 Object Lock `COMPLIANCE`. | Bundle checks, request telemetry tests, and isolated receiver unit tests; post-deployment delivery and alert receipt remain operational evidence |
| Retention/legal hold | Expired rate counters and delivered SIEM queue records are maintainable; active legal holds stop telemetry destruction; undelivered telemetry and audit evidence fail retained | Lifecycle integration tests |
| Backup/recovery | Admin-only logical workspace backup with strict size limits, public-key material only, archive digest, per-table counts, and signed manifest | Backup signature integration test; platform restore drill remains operational evidence |
| Supply chain | Pinned Actions, CodeQL, Dependabot, dependency audit, SBOM, deterministic release package, and GitHub build/SBOM attestation workflow | CI and `gh attestation verify` on a tagged release |
| Safe execution boundary | Plans, approvals, discovery jobs, and runner enrollments remain explicitly `executable: false`; no AWS credential or command channel exists in the web app | Database constraints and integration tests |

## Operational gates that cannot be self-attested by source changes

The following remain mandatory before labeling a deployment production-ready:

1. Deploy `infra/aws-kms-signer` in the explicitly approved AWS account and region; pin its public JWK/key ARN in Sites; prove key custody, rotation, revocation, and alarms.
2. Deploy `infra/aws-siem-collector` in the approved security-operations boundary or configure an equivalent independently administered `/v1/events` collector; prove delivery, outbox retry, alert routing, immutable retention, and credential rotation.
3. Execute and record a D1/platform backup and restore drill against an isolated recovery project, including audit-chain and signed-manifest verification and measured RPO/RTO.
4. Run a tagged release workflow and verify its artifact and SBOM attestations from a separate verifier context.
5. Obtain independent application/cloud/supply-chain review. The author of controls cannot provide independent assurance.
6. Complete the customer-hosted runner program in `runner-security-design.md` before any real AWS API execution. An approved control-plane record is not execution authority.

Until these gates have evidence, keep Sites access private, use synthetic data only, and keep production mode disabled.

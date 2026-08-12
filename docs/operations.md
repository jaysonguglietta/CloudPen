# Operations and incident response

## Operating objective

Keep CloudPen available for authorized control-plane evaluation without enabling cloud execution, leaking tenant metadata, accepting untrusted identity headers, or losing evidence and audit integrity.

## Routine checks

### Local

- Confirm the listener is `127.0.0.1:8787`, never `0.0.0.0`.
- Confirm `/` returns `200` in local mode.
- Confirm `/api/validation-runs` returns server-owned state.
- Stop the process when evaluation ends.

### Hosted

- Confirm the Sites project remains private/custom.
- Review role allowlists after personnel or responsibility changes.
- Review failed authorization, `429`, and `500` trends without logging sensitive bodies.
- Verify D1 availability and migration version.
- Periodically create and inspect a synthetic signed plan and evidence package.
- Verify that the runner remains disabled and no AWS credentials exist.

### Security telemetry and SIEM export

Each trusted entry-point request emits one JSON event with schema `cloudpen.security-event.v1`, a random request ID also returned as `X-Request-ID`, timestamp, normalized route template, method, category, outcome, status, duration, capability class, role, hashed actor ID, and local-mode flag. Query strings, bodies, evidence values, External IDs, credentials, tokens, signing material, and raw email addresses are excluded. JSON serialization prevents newline or field injection from changing the event structure.

Hosted production sends events directly under the contract in `siem-integration.md`; delivery failures are retained in the D1 outbox and retried. Platform log export remains a second independent channel. Alert on repeated `authorization_denied`, `cross_origin_denied`, `body_size_denied`, `rate_limit_denied`, `internal_failure`, and `identity_origin_denied`; any hosted event with `localMode: true`; audit-chain verification failure; signing failure; and a nonzero/aging outbox. Retain SIEM events for 90 days by default unless legal/privacy requirements specify otherwise. Never enable body capture.

## Security signals

Prioritize investigation of:

- repeated unauthorized identities or role-denied mutations;
- cross-origin mutation failures;
- bursts of body-size, malformed JSON, or rate-limit errors;
- unexpected `CLOUDPEN_LOCAL_MODE` in a hosted environment;
- missing or changed security headers;
- plan signature failures or an unavailable signing key;
- audit-chain uniqueness failures;
- unexplained D1 writes, deleted audit records, or role-list changes;
- a new outbound network destination, AWS SDK, command execution primitive, or credential variable.

## Incident severity

| Severity | Examples | Immediate action |
| --- | --- | --- |
| Critical | Signing key or cloud credentials exposed; unauthorized cloud execution; remote code execution | Disable access, revoke/rotate secrets, isolate the service, preserve evidence, invoke organizational incident response |
| High | Authentication bypass, unauthorized role, audit tampering, sensitive topology disclosure | Restrict access, preserve logs and D1 snapshot, rotate affected secrets, investigate scope |
| Medium | Repeated CSRF/DoS attempts, missing hardening header, dependency advisory with plausible reachability | Apply compensating controls, patch promptly, monitor exploitation indicators |
| Low | Non-sensitive diagnostic disclosure or localized security UX defect | Track, remediate, and verify in normal release process |

## Incident procedure

1. **Contain:** restrict or disable Sites access. Do not enable a runner as a diagnostic shortcut.
2. **Preserve:** record deployment version, configuration revision, relevant timestamps, sanitized request metadata, and an approved D1 backup or export.
3. **Revoke:** rotate the plan-signing key and any potentially exposed platform credentials. If a future runner exists, revoke its workload identity separately.
4. **Assess:** determine affected identities, plans, evidence exports, connector requests, and audit-chain links.
5. **Eradicate:** patch the root cause and add a regression test.
6. **Recover:** deploy the verified version behind private access, validate identity/RBAC and security headers, and monitor closely.
7. **Learn:** update the threat model, runbook, security review, and release checklist.

Never paste live secrets or customer evidence into GitHub issues, chat, email, or general-purpose logs.

## Signing-key rotation

1. Create a new RSA-3072 KMS signing key without deleting or disabling the old key.
2. Retrieve its public key independently, convert it to a PS256 JWK, and add it to the trusted verifier keyset.
3. Configure the new signer key ID/public JWK and deploy while issuance is paused.
4. Require readiness, issue a synthetic artifact, and verify it from a separate context with the pinned keyset.
5. Record a signed audit anchor and the exact issuance cutoff. Mark the old key `retired` for historical verification.
6. Revoke/disable the old key only for compromise or approved policy; retain public material and revocation evidence.
7. Rotate the signer bearer credential separately; warm Lambda instances refresh it within five minutes.

Private KMS material must never be exported or copied into Sites, D1, source, logs, or backup artifacts.

## Connector External ID rotation

External IDs are one-time customer-controlled values in this non-executable release. Creation and rotation generate 256 random bits in the browser; the API validates the `cpv1_` envelope and immediately discards it without storing a hint or digest. Operators must copy the value before committing the dialog, update the AWS role trust condition through the customer's approved change process, and then re-run ownership verification when a future runner supports it.

Rotation returns the connector to `Runner required` and records only actor, connector, time, and `externalIdStatus: not-retained`. The migration from earlier builds deliberately drops stored SHA-256 digests and hints. If a copied value is lost, generate another rotation value; it cannot be recovered from CloudPen. Disable the AWS trust relationship directly during revocation or suspected exposure because this control plane holds no credential and cannot revoke it remotely.

## Audit-chain verification

The application writes canonical event hashes linked by `previous_hash`. Operational verification should:

1. read events for one workspace in deterministic creation order;
2. start with `GENESIS`;
3. reconstruct each canonical event body exactly as the application does;
4. recompute SHA-256 and compare `event_hash`;
5. confirm each next `previous_hash` equals the prior event hash;
6. flag missing, duplicate, reordered, or branched links.

The control-plane snapshot endpoint and Evidence & Audit view run this verification automatically. Administrators can create signed linked chain-head anchors through `POST /api/admin/audit-anchor`; production operations must export those anchors to an independent append-only system. A database administrator can still rewrite records after the latest externally retained anchor, so do not call D1 itself immutable evidence.

## Backup, restore, and retention

The application implements lifecycle status, legal holds, bounded operational cleanup, and signed logical backups. Production still requires encrypted platform backup custody and the restore drill in `data-lifecycle.md`; record measured RPO/RTO, audit continuity, signed-manifest verification, and secure destruction of the isolated restore copy.

## Recovery validation

After any incident, outage, migration, or rollback, run the full automated suite plus manual synthetic checks for:

- unauthenticated and unauthorized denial;
- role enforcement;
- cross-origin rejection;
- non-disableable guardrails;
- plan `executable: false`;
- active-canary separation of duties and non-executable approved intent;
- connector External ID non-disclosure and non-executable discovery scope;
- pending runner enrollment with `executable: false`;
- evidence integrity envelope;
- D1 durability and audit chaining;
- response security headers;
- loopback-only local binding or private hosted access.

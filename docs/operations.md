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

Current packages identify key `cloudpen-plan-v1`, but the code supports one active HMAC secret. A safe rotation therefore requires a maintenance window and documented verification cutoff:

1. Stop issuing plans and exports.
2. Record the last package timestamp and digest under the old key.
3. Replace the Sites secret with a newly generated high-entropy value.
4. Deploy the new environment revision.
5. Issue and verify a synthetic package.
6. Treat old packages as historical artifacts requiring the retired key under controlled custody, or declare them unverifiable after the cutoff.

Do not keep retired keys in source or general environment files. Multi-key verification and asymmetric KMS signing are required before production evidence workflows.

## Audit-chain verification

The application writes canonical event hashes linked by `previous_hash`. Operational verification should:

1. read events for one workspace in deterministic creation order;
2. start with `GENESIS`;
3. reconstruct each canonical event body exactly as the application does;
4. recompute SHA-256 and compare `event_hash`;
5. confirm each next `previous_hash` equals the prior event hash;
6. flag missing, duplicate, reordered, or branched links.

An automated verifier and external chain anchor are not yet implemented. Database administrators can still rewrite a complete chain; do not call it immutable evidence.

## Backup, restore, and retention

Formal production procedures are not implemented because the app holds synthetic data. Before real use, define:

- encrypted D1 backup cadence and retention;
- restore objectives and rehearsals;
- per-table retention and deletion rules;
- legal hold and customer export processes;
- secure destruction for expired evidence and personal data;
- restoration validation for audit-chain continuity.

## Recovery validation

After any incident, outage, migration, or rollback, run the full automated suite plus manual synthetic checks for:

- unauthenticated and unauthorized denial;
- role enforcement;
- cross-origin rejection;
- non-disableable guardrails;
- plan `executable: false`;
- active-canary `Awaiting approval`;
- evidence integrity envelope;
- D1 durability and audit chaining;
- response security headers;
- loopback-only local binding or private hosted access.

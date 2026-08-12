# Adversarial security review

- **Review date:** 2026-08-12
- **Scope:** repository source, migrations, Worker/API behavior, CI/release configuration, KMS signer infrastructure-as-code, and intended private Sites topology
- **Classification:** production-hardening candidate; cloud execution remains deliberately disabled

## 1. Executive summary

CloudPen has a strong fail-closed control-plane implementation. Authentication is delegated to the private Sites dispatcher and followed by application membership/capability checks. Workspace scope is derived server-side, mutations use bounded same-origin JSON, state is D1-owned, security writes and linked audit records commit atomically, plans and decisions use versioned PS256 envelopes, and every runner/discovery artifact remains database-constrained to non-executable state. The suite covers adversarial signing, role separation, races, evidence redaction, and two-tenant isolation.

No confirmed remote code execution, SQL/command/template injection, SSRF through user input, stored/reflected XSS, authentication bypass in the supported Sites topology, cross-tenant access, secret retention, or cloud-credential exposure was found in this version. The web app contains no AWS execution credentials, arbitrary command channel, or runner.

Production approval cannot be established from source changes alone. The KMS signer and SIEM paths are fail-closed and deployable but are not operationally evidenced in the intended external accounts. Platform backup restoration, tagged attestation verification, and independent assessment are also outstanding. `/api/admin/readiness` deliberately reports failure until mandatory runtime controls are configured.

## 2. System overview and trust boundaries

### Assets

- Sites identity, application memberships, roles, and authorization decisions
- Workspace-scoped topology, connectors, plans, approvals, evidence metadata, remediation, and legal holds
- Canonical payloads, artifact signatures, public-key registry, nonces, and revocation state
- Hash-chained audit events, signed anchors, and security telemetry
- D1 state, migrations, source, lockfile, release artifact, SBOM, and provenance claims
- External KMS private key and signer/SIEM bearer credentials, which must remain outside this repository and D1

### Trust boundaries

1. Untrusted internet/browser to private Sites identity dispatcher.
2. Dispatcher-established identity to application membership and capability enforcement.
3. API parsing/business rules to workspace-scoped D1 state.
4. Worker to exact configured external KMS signer and SIEM endpoints.
5. Source/CI to tagged release artifacts and GitHub attestation trust root.
6. Control plane to a future customer-hosted runner. This boundary does not exist and remains blocked.

## 3. Threat model

| Attacker | Capabilities | Primary objectives |
| --- | --- | --- |
| Internet attacker | Arbitrary requests, headers, origins, timing, concurrency | Forge identity, exhaust service, reach internal state |
| Unauthorized Sites user | Valid platform identity without membership | Enter a workspace or enumerate topology |
| Malicious viewer/operator/reviewer | Valid lower privilege and browser control | Escalate, self-approve, cross tenants, forge evidence |
| Compromised browser | Modify requests/UI and steal displayed data | Treat client state as authority or trigger victim actions |
| Database administrator/attacker | Read/write D1 | Rewrite plans, keys, audit history, or lifecycle state |
| Control-plane compromise | Server execution and environment access | Abuse signer, exfiltrate state, suppress telemetry |
| Supply-chain attacker | Dependency/action/build/release influence | Run in CI/build or substitute deployed artifacts |
| Future compromised runner | Customer workload identity and cloud reach | Escape plan scope, replay, persist, or hide cleanup failure |

Likely attack chains include direct-origin identity-header spoofing if the dispatcher is bypassed; compromised operator plus missing separation of duties; database rewrite plus absent external anchor; signer-token theft plus signing-oracle abuse; SIEM outage plus outbox tampering; and future runner replay/scope confusion.

## 4. Attack surface inventory

| Surface | Controls | Residual concern |
| --- | --- | --- |
| Sites/Worker identity | Private access, canonical-origin identity check, app membership | Direct Worker origin must remain unreachable; headers are not independently signed |
| API mutations | Exact Origin/Fetch Metadata, JSON media type, streamed 8 KiB limit, strict fields, capabilities, rate limits | Edge/global anonymous volumetric protection is platform-owned |
| D1 | Prepared statements, workspace predicates, constraints, optimistic concurrency, atomic audit sentinel | DB administrator can rewrite state after latest external anchor |
| Signing | PS256, KMS adapter, strict domains/audience/workspace/nonce/expiry, key registry, independent verifier | KMS deployment, token custody, public-key pinning, and rotation need operational proof |
| SIEM egress | Exact HTTPS path, bearer auth, digest, timeout, no redirects, durable retry queue | Collector trust, alert routing, and immutable retention need operational proof |
| Backup/lifecycle | Signed logical manifest, legal holds, bounded cleanup | Platform backup encryption and full restore rehearsal remain external |
| Browser | Server-owned data, output-safe React, nonce CSP, frame/MIME/privacy headers | Inline styles allowed; authorized browser receives current page snapshot |
| Build/release | Lockfile, audits, CodeQL, pinned actions, SBOM, deterministic artifact, attestation workflow | Tagged workflow has not yet produced/verified this candidate's attestation |
| Runner/cloud | No channel, credential, SDK execution, or executable state | Any future enablement is a new critical boundary |

## 5. Prioritized findings

### SR-01 — Identity-header provenance depends on an unbypassable Sites dispatcher

- **Severity:** High if a direct origin is exposed; Informational in the supported private topology
- **Confidence:** High
- **Affected:** `app/chatgpt-auth.ts`, `worker/index.ts`, deployment routing
- **Type:** Conditional residual risk

The app consumes `oai-authenticated-user-*` headers established by Sites. It checks that identity is delivered on the configured origin and strips the local verification header, but it cannot cryptographically distinguish a forged identity header reaching a directly exposed Worker hostname.

An attacker who can bypass Sites and send requests to an alternate origin configured as canonical could claim an administrator email. Impact includes privileged plan/configuration/evidence actions, although cloud execution remains impossible. Keep Sites private/custom, remove direct-origin reachability, and test every hostname with forged headers. Any non-Sites deployment must replace header trust with verified OIDC/JWT issuer, audience, signature, expiry, nonce, and organization claims.

**CWE/OWASP:** CWE-345; OWASP A07.

### SR-02 — Full authorized snapshot delivery increases real-topology exposure

- **Severity:** High for real tenants; Informational for current demo data
- **Confidence:** High
- **Affected:** `app/page.tsx`, `lib/server/control-plane.ts`, dashboard snapshot flow
- **Type:** Design gap

The server correctly scopes the catalog by membership/workspace, but the main page receives the complete current workspace demo snapshot. A compromised authorized browser can read everything delivered for that view. Before real topology ingestion, add paginated/path-specific endpoints, purpose-minimized projections, field classification, and per-view authorization. Test built bundles and rendered responses for unrelated accounts, ARNs, evidence, and other tenants.

**CWE/OWASP:** CWE-200; OWASP A01.

### SR-03 — Tenant isolation is implemented; lifecycle governance is incomplete

- **Severity:** Medium
- **Confidence:** High
- **Affected:** `lib/security/authorization.ts`, membership administration and identity lifecycle
- **Type:** Defense-in-depth/operations

The previous hard-coded workspace defect is remediated: membership derives workspace and role, all records/queries/signatures/audit/rate keys are scoped, and tests prove a second tenant cannot select the first. However, invitations, SCIM deprovisioning, access certification, step-up authentication, emergency access, and tenant-specific signing keys are absent. A stale membership or standing administrator therefore remains plausible.

Implement enterprise IdP group mapping/SCIM, short session revocation, periodic access review, step-up for key/lifecycle operations, and tenant-specific key policy where required. Validate joiner/mover/leaver and stale-session behavior.

**CWE/OWASP:** CWE-266/CWE-639; OWASP A01/A07.

### SR-04 — KMS signing is source-complete but not operationally proven

- **Severity:** High production gate
- **Confidence:** High
- **Affected:** `lib/security/signing.ts`, `infra/aws-kms-signer/`, Sites bindings
- **Type:** Operational blocker, not a confirmed code vulnerability

The shared HMAC design is removed. Protocol v2 provides PS256 domains, scope, nonce, expiry, key registry, revocation, and an independent pinned-key verifier. The AWS stack constrains Lambda to one KMS key and secret. Without deployment evidence, however, key custody, alarms, token rotation, public-key pinning, and endpoint reachability are assumptions.

Deploy in the explicitly approved account, verify IAM/KMS policies, pin the public JWK through an independent path, run known-answer and abuse tests, rotate key/token, and record alerts. Keep production mode disabled until readiness and independent verification pass.

**CWE/OWASP:** CWE-320; OWASP A02/A05.

### SR-05 — Audit integrity still requires independent anchor custody

- **Severity:** Medium
- **Confidence:** High
- **Affected:** `audit_events`, `audit_anchors`, SIEM/archive operations
- **Type:** Residual risk

D1 mutation/audit commits are atomic, chain branches are constrained, full-history verification is paged, and signed linked anchors exist. A D1 administrator with access to the same public-key registry and unexported anchors can still rewrite everything after the last independently retained anchor or delete local anchors.

Create anchors on schedule and before/after releases/incidents, export them to an independently administered append-only system, alert on chain/head mismatch, and restrict D1 administration. Corruption tests must mutate, delete, reorder, duplicate, branch, and truncate events.

**CWE/OWASP:** CWE-778; OWASP A09.

### SR-06 — Inline styles remain permitted by CSP

- **Severity:** Low
- **Confidence:** High
- **Affected:** `worker/index.ts`
- **Type:** Defense-in-depth

Scripts receive fresh high-entropy nonces, `strict-dynamic`, and `script-src-attr 'none'`; framing and dangerous object sources are blocked. `style-src 'unsafe-inline'` remains for framework compatibility. A future HTML/CSS injection could manipulate display even without script execution. Evaluate style nonces/hashes and Trusted Types after full browser compatibility testing; retain current script nonce regression tests.

**CWE/OWASP:** CWE-79; OWASP A03.

### SR-07 — Backup and retention need platform restore evidence

- **Severity:** Medium production gate
- **Confidence:** High
- **Affected:** lifecycle/backup APIs, Sites/D1 operations
- **Type:** Operational blocker

Legal holds, bounded operational deletion, signed logical archive digests, and public-key-only backups are implemented. The logical export is capped at 4 MB and deliberately is not a platform backup. No production D1 restore has been rehearsed or measured.

Execute the isolated restore runbook, prove encryption/custody, record RPO/RTO, verify manifest and audit head, test legal hold/customer deletion, and destroy the recovery copy securely. Larger tenants require platform-native backup rather than increasing Worker memory limits.

**CWE/OWASP:** CWE-404; OWASP A05/A09.

### SR-08 — SIEM delivery needs independent collector evidence

- **Severity:** Medium production gate
- **Confidence:** High
- **Affected:** `lib/security/telemetry.ts`, collector configuration
- **Type:** Operational blocker

Events are minimized/canonical, exact-endpoint delivered, digested, and queued with bounded retry/backoff. Missing production SIEM configuration fails readiness and queues events. The repository cannot prove the external collector durably accepts, deduplicates, alerts, retains immutably, or rotates credentials.

Run the acceptance cases in `siem-integration.md`, monitor outbox age/depth, export platform logs as a second channel, and keep tokens in platform secrets. Never log bodies or raw identity.

**CWE/OWASP:** CWE-778; OWASP A09.

### SR-09 — Future runner remains the dominant critical-risk boundary

- **Severity:** Critical if enabled without all gates; Informational while absent
- **Confidence:** High
- **Affected:** future runner/delivery/workload-identity design
- **Type:** Deliberately disabled capability

An approved PS256 plan is still non-executable. There is no runner identity, account binding, atomic nonce consumption, module allowlist, workload credential flow, customer kill switch, bounded egress, cleanup proof, or evidence attestation. Treat any code that introduces cloud calls, credentials, command delivery, arbitrary modules, or executable state as a new security architecture requiring independent review.

Complete every gate in `runner-security-design.md`; do not let a browser, model, general script, or shared credential issue AWS calls.

**CWE/OWASP:** CWE-284/CWE-94; OWASP A01/A03.

### SR-10 — Release provenance exists but must be verified by consumers

- **Severity:** Low now; High for distributed runner artifacts
- **Confidence:** High
- **Affected:** `.github/workflows/`, release operations
- **Type:** Supply-chain residual risk

Actions are SHA-pinned, CodeQL/Dependabot/audits run, and tagged workflows generate deterministic artifacts, CycloneDX SBOMs, and GitHub attestations. Attestation generation alone does not prevent substitution if deployers never verify it. Require `gh attestation verify` against the expected repository/commit before deployment and retain the result. Keep build-only audit exceptions narrow, expiring, and bundle-reachability tested.

**CWE/OWASP:** CWE-494; OWASP A08.

## 6. Exploitation chains and combined-risk scenarios

- **Direct origin + static admin email:** dispatcher bypass could turn header forgery into privileged control-plane access. Private routing is mandatory.
- **D1 compromise + unexported anchors:** an attacker rewrites plans, public-key registry, and the entire local audit chain. Independently retained signed anchors bound the detectable cutoff.
- **Signer token theft + missing monitoring:** the attacker uses the constrained oracle to sign arbitrary envelopes. Domain/scope do not help if the control plane constructs them; rate limits, alarm delivery, token revocation, and KMS audit are required.
- **SIEM outage + D1 compromise:** queued events could be deleted before delivery. Platform logs and separately administered outbox monitoring provide a second channel.
- **Future runner + replay gap:** a valid approved plan could execute twice unless the runner atomically checks and consumes the nonce before any action.

## 7. Dependency and configuration risks

Production dependencies must remain free of High/Critical advisories. Build-only exceptions are documented, time-bounded, and guarded from entering the Worker bundle. GitHub Actions are commit-pinned. Production configuration must exclude local/ephemeral mode and include HTTPS origin, D1, external signer/token/key/JWK, SIEM/token, private Sites access, and production mode. The readiness endpoint checks runtime presence/shape but cannot prove external ownership or alert delivery.

## 8. Secure design gaps

- No self-service tenant lifecycle, SCIM, step-up, or periodic access certification.
- No paginated/purpose-minimized real-topology API.
- No platform restore evidence or automated customer-record deletion workflow.
- No independently retained production anchor or SIEM acceptance evidence yet.
- No customer-hosted collector/runner or safe execution protocol implementation.
- No independent application/cloud/supply-chain assessment.

## 9. Recommended remediation roadmap

1. Provision/evidence KMS and SIEM in approved external accounts; make readiness pass.
2. Run isolated backup/restore, anchor export, SIEM outage/retry, key/token rotation, and tagged-attestation verification exercises.
3. Obtain independent review and resolve its findings before real tenant data.
4. Add enterprise identity lifecycle and paginated topology minimization.
5. Build a customer-hosted read-only collector first; keep active execution disabled.
6. Only then implement the independently reviewed runner protocol and synthetic-canary exercises.

## 10. Security test plan

Automated gates cover authentication, role denial, tenant selection, CSRF, body limits, CSP, plan signing, tampering, downgrade, wrong scope/audience, expiry, replay, revoked keys, approval separation/races, atomic audit, connector secret non-retention, evidence redaction, remediation authority, non-executable runner/discovery, anchors, backup manifests, legal holds, readiness, and telemetry minimization.

Operational tests must cover forged headers on every hostname; KMS IAM/key policy and CloudTrail; signer auth/rate/rotation/alarms; SIEM outage/retry/dedup/alerts/retention; D1 corruption and external anchor comparison; backup/restore RPO/RTO; tagged attestation verification; load/volumetric abuse; browser injection; privacy review; and independent penetration testing.

## 11. Open questions and assumptions

- Which AWS account/region and security-operations SNS topic own the production KMS signer?
- Which independently administered SIEM implements `/v1/events`, and what are its retention/alert SLAs?
- What contractual RPO/RTO, evidence retention, data residency, legal hold, and deletion requirements apply?
- Which IdP groups, MFA/step-up policy, and SCIM source own membership lifecycle?
- Who retains trusted public keysets and signed audit anchors outside CloudPen?
- Which independent assessor will approve the app, external infrastructure, supply chain, and any future runner?
- Private Sites routing and identity-header stripping are assumed to operate as documented; alternate direct origins are unsupported.

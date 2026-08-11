# Adversarial security review

- **Review date:** 2026-07-31, updated for control-plane expansion 2026-08-03
- **Scope:** code in this repository, local Worker deployment, and intended private Sites deployment
- **Deployment classification:** pre-production control-plane prototype
- **Cloud execution:** absent and deliberately disabled

## 1. Executive summary

CloudPen now has a defensible fail-closed control-plane foundation for synthetic evaluation. Identity, roles, exposure snapshots, connectors, plan/approval decisions, evidence manifests, remediation, pending runner enrollment, guardrails, rate limits, and audit events are server-owned in D1. Mutations enforce same-origin bounded JSON input; plans, generated evidence, policies, and reports carry integrity envelopes; core guardrails cannot be disabled; and discovery/runner records are database-constrained to non-executable state.

No confirmed remote code execution, injection, SSRF, XSS, credential leakage, authentication bypass through the supported Sites path, or real cloud data exposure was found in the hardened version. The most important security property is absence: there is no AWS credential flow, runner protocol, or API execution capability.

The system is not production-ready for real tenants or penetration testing. Its residual risks are architectural: identity-header provenance depends on the Sites boundary, the configured organization has no self-service tenant lifecycle, HMAC does not provide independent attestation, audit history lacks an external anchor, retention and recovery are undefined, and the runner protocol is only a non-executable enrollment scaffold. These are release gates, not backlog polish.

## 2. System overview and trust boundaries

### Assets

- User identity, role assignment, and authorization decisions
- Validation plan scope, guardrails, signature, expiry, and status
- Evidence observations and integrity metadata
- Audit attribution and hash-chain continuity
- AWS account identifiers and non-secret connector lifecycle events; External IDs and their derivatives are not retained
- D1 data and the plan-signing secret
- Source, lockfile, CI workflow, migration, and deployment configuration

### Entry points

- `GET /` and `/access-denied`
- `GET/POST/PATCH /api/validation-runs`
- `GET/PATCH /api/guardrails`
- `POST /api/connectors`
- `POST /api/evidence/{pathId}`
- `GET /api/control-plane`, signed report/policy exports, remediation, discovery-plan, and runner-enrollment routes
- `/_vinext/image`
- Local Wrangler service on `127.0.0.1:8787`
- Hosted Sites dispatcher and environment bindings
- Dependency installation, build, CI, and release workflow

### Attacker-controlled inputs

- HTTP methods, paths, query strings, headers, Origin, content type, content length, and bodies
- Browser state, JavaScript execution, timing, retries, concurrency, and UI manipulation
- Path IDs, validation mode, acknowledgement, connector name/account/one-time External ID, and guardrail property
- Dependency and source contributions
- Local processes able to reach loopback

### Trust boundaries

See `architecture.md`. The highest current boundary is Sites identity to application authorization. The highest future boundary is control plane to customer-hosted runner; it does not exist today.

## 3. Threat model

### Attacker personas

| Persona | Capability | Objective |
| --- | --- | --- |
| Unauthenticated internet attacker | Arbitrary requests and browser automation | Reach private topology, exhaust service, bypass sign-in |
| Authenticated unauthorized workspace user | Valid Sites identity but no CloudPen role | Gain application access or create plans |
| Malicious viewer/operator | Valid lower-privilege role and browser control | Escalate role, disable safeguards, forge evidence or completion |
| Compromised browser/client | Modify UI state and requests | Treat client values as approvals or authoritative results |
| Compromised control plane | Server execution or signing-secret access | Issue fraudulent plans, exfiltrate state, rewrite records |
| Database administrator/compromise | Direct D1 read/write | Alter plans, identities, audit history, or rate limits |
| Supply-chain attacker | Dependency, action, build, or release compromise | Execute during install/build or alter deployed artifact |
| Future malicious/compromised runner | Workload identity and cloud API reach | Escape plan scope, access customer data, persist, hide activity |

### Primary attack paths

1. Forge identity headers by bypassing the trusted dispatcher.
2. Use a valid low-privilege identity to call an unprotected mutation.
3. Submit cross-origin or oversized requests to abuse state or resources.
4. Modify browser state to mark a run completed or fabricate evidence.
5. Disable approval/canary/redaction/cleanup controls before creating a plan.
6. Steal the shared signing key and forge plan or evidence envelopes.
7. Alter D1 records and recompute the entire local audit chain.
8. Expose real topology by replacing synthetic client data without changing architecture.
9. Compromise dependencies, CI actions, or stale build output.
10. Introduce a future runner that accepts arbitrary actions, replayed plans, broad credentials, or unsafe egress.

## 4. Attack-surface inventory

| Surface | Current controls | Remaining concern |
| --- | --- | --- |
| Page authentication | Sites identity, server redirect, application allowlist | Header provenance requires dispatcher isolation |
| RBAC | Server capability matrix in every API | Static environment lists lack lifecycle automation |
| Mutations | Exact Origin, Fetch Metadata, bounded JSON media type, field validation | No general API client authentication model by design |
| D1 | Prepared statements, workspace predicates, constraints, indexes | One configured organization and admin-level tampering remain |
| Plan creation | Server timestamps/status, enforced policy, expiry, digest/HMAC, non-executable | HMAC shared secret and no verifier/runner protocol |
| Evidence | Server-generated, redacted fields, signed, non-cacheable, manifest-retained, audited | Synthetic only; retention and asymmetric verification absent |
| Approval | Distinct reviewer/admin, required reason, expiry, compare-and-set audited transition | Approved intent remains non-executable; no step-up or nonce protocol |
| Discovery/runner staging | Service allowlist, pinned fingerprint, database `executable = 0` | No ownership proof, workload identity, delivery, or collector exists |
| Audit | Application append-only hash chain, branch-prevention index | No external anchor; DB admin can rewrite full chain |
| Rate limiting | D1 per-email counters on primary operations | No edge/global anonymous limiter documented |
| Worker response | CSP, frame denial, nosniff, referrer, permissions, COOP/CORP, HSTS on HTTPS | CSP still permits inline framework code |
| Local runtime | Explicit loopback, project-local D1, security artifact test | Any local process can reach it; Local Explorer is development-only |
| Build/CI | Clean `dist`, lockfile, zero audit at validation, pinned actions, read-only CI | Registry/package compromise and future advisories remain possible |

## 5. Prioritized findings

### SR-01 — Identity headers require an unbypassable trusted dispatcher

- **Severity:** High if the Worker is directly exposed; Informational in the supported private Sites topology
- **Confidence:** High
- **Affected:** `app/chatgpt-auth.ts`, `lib/security/authorization.ts`, deployment architecture
- **Status:** Conditional residual risk

**Description:** CloudPen accepts `oai-authenticated-user-*` headers as authenticated identity. The application does not validate a dispatcher signature because Sites is expected to inject and protect these headers.

**Evidence:** `getChatGPTUser()` reads the email header directly; role lookup then trusts that email. Local mode is independently restricted to loopback.

**Exploitation scenario:** If an operator exposes the Worker directly or places an untrusted proxy in front of it without stripping and re-establishing identity headers, an attacker supplies an administrator email and reaches privileged routes.

**Impact:** Authentication bypass, guardrail administration, signed plan creation, connector requests, and evidence access.

**Recommended fix:** Treat private Sites dispatch as mandatory. Do not expose an alternate Worker URL. If other hosting is required, replace header trust with verified OIDC/JWT middleware using issuer, audience, signature, expiry, nonce, and organization claims, and strip external identity headers at the first trusted hop.

**Patch guidance:** Add a platform-authentication adapter with explicit deployment modes; fail startup when hosted mode lacks a supported verifier. Do not add a shared header secret as the long-term identity solution.

**Validation:** Send forged identity headers to every reachable hostname. Only the trusted dispatcher route may accept dispatcher-established identity. Verify direct origin hostnames are unavailable.

**CWE/OWASP:** CWE-345; OWASP A07 Identification and Authentication Failures.

### SR-02 — Minimize real topology delivered to each authorized browser

- **Severity:** High for real tenant data; Informational for current synthetic data
- **Confidence:** High
- **Affected:** `lib/cloudpen-data.ts`, `app/cloudpen-dashboard.tsx`
- **Status:** Partially remediated; pagination/field minimization remains a production gate

**Description:** The static catalog is now seeded into a server-owned D1 snapshot and passed by the authenticated server page. This removes hidden catalog data from the client bundle, but the current page still receives the complete authorized demo snapshot instead of paginated, purpose-minimized records.

**Evidence:** `getExposureCatalog()` reads workspace-scoped snapshot tables; `app/page.tsx` supplies that authorized projection to the client dashboard.

**Exploitation scenario:** A future implementation replaces samples with real topology while retaining the client bundle. Any viewer or compromised browser downloads the full catalog, including paths not required for the active view.

**Impact:** Sensitive topology disclosure, cross-workspace leakage if tenancy is added incorrectly, and valuable reconnaissance.

**Recommended fix:** Preserve the server-owned model and add paginated/path-specific APIs before real ingestion. Minimize fields, classify and redact evidence, and avoid preloading paths unrelated to the current view.

**Validation:** Search built client chunks for tenant account IDs, resource ARNs, evidence, and hidden records. Add tests that one workspace cannot enumerate another.

**CWE/OWASP:** CWE-200; OWASP A01 Broken Access Control.

### SR-03 — Fixed single-workspace scoping is not multi-tenant isolation

- **Severity:** Medium now; Critical if multiple real tenants are introduced without redesign
- **Confidence:** High
- **Affected:** `lib/server/control-plane.ts`, D1 schema
- **Status:** Production blocker for multi-tenancy

**Description:** Every new product table and query is scoped to the configured workspace, and request bodies cannot select a workspace. The current deployment nevertheless supports one organization only and lacks server-derived multi-workspace selection, tenant-specific keys, lifecycle administration, and two-workspace negative tests.

**Exploitation scenario:** Developers add workspace switching in the UI or ingest multiple tenants into shared tables without introducing server-derived tenant context and row-level authorization.

**Impact:** Cross-tenant plan, evidence, identity, and audit access.

**Recommended fix:** Design tenant identity and membership centrally. Derive workspace from authenticated server context, never request body. Include workspace in every primary/unique/index relationship, query predicate, cache key, rate key, signature, evidence envelope, audit event, and storage object path. Add isolation tests before a second tenant.

**Validation:** Property and integration tests attempt every CRUD/read operation across two workspaces using every role.

**CWE/OWASP:** CWE-639; OWASP A01 Broken Access Control.

### SR-04 — HMAC integrity cannot provide independent attestation or graceful rotation

- **Severity:** Medium
- **Confidence:** High
- **Affected:** `lib/security/runtime.ts`, `lib/server/control-plane.ts`
- **Status:** Accepted prototype limitation; production evidence blocker

**Description:** Plans and evidence use one environment HMAC secret and fixed key ID. Anyone who can verify with the key can also forge. The application has no multi-key verification, revocation history, or external signing service.

**Exploitation scenario:** A control-plane compromise obtains the environment secret and creates fraudulent historical-looking packages. Rotation makes old packages unverifiable unless the retired secret is retained.

**Impact:** Loss of evidence provenance and plan trust.

**Recommended fix:** Use KMS/HSM-backed asymmetric signing. Publish versioned public verification keys, include algorithm/key/protocol versions, support rotation and revocation, and keep the private key non-exportable. The future runner must verify independently.

**Validation:** Known-answer vectors, malformed canonicalization tests, key rotation, revoked key, wrong audience/runner, expiry, and replay tests.

**CWE/OWASP:** CWE-320; OWASP A02 Cryptographic Failures.

### SR-05 — Audit chain is tamper-evident only within the same database

- **Severity:** Medium
- **Confidence:** High
- **Affected:** `audit_events`, `appendAuditEvent()`
- **Status:** Defense-in-depth gap

**Description:** Events link hashes and prevent silent branch insertion through a unique prior-hash index. A database administrator can still delete or rewrite the entire chain and recompute hashes because no external anchor or asymmetric signature exists.

**Exploitation scenario:** An attacker with D1 administrative access rewrites both malicious plan records and corresponding audit events.

**Impact:** Reduced forensic confidence and repudiation resistance.

**Recommended fix:** Automate chain verification; periodically anchor signed chain heads in an independent append-only system; export security events to a separate SIEM/account; restrict database administration; alert on gaps and verification failure.

**Validation:** Mutate, delete, reorder, duplicate, and branch events and ensure verification/monitoring detects each case.

**CWE/OWASP:** CWE-778; OWASP A09 Security Logging and Monitoring Failures.

### SR-06 — CSP permits inline script and style execution

- **Severity:** Medium
- **Confidence:** High
- **Affected:** `worker/index.ts`
- **Status:** Framework-hardening gap

**Description:** The CSP restricts origins but includes `'unsafe-inline'` for scripts and styles to support current framework bootstrap behavior.

**Exploitation scenario:** A future HTML injection bug has a larger path to script execution because inline scripts are permitted.

**Impact:** Increased XSS impact, session actions under the victim identity, topology exposure, and plan abuse within the victim role.

**Recommended fix:** Implement per-response nonces or hashes integrated with server rendering, remove `'unsafe-inline'`, add Trusted Types where supported, and retain output encoding. Do not weaken `connect-src`, `object-src`, or `frame-ancestors`.

**Validation:** Browser CSP tests must prove hydration works and injected inline/event-handler/script payloads are blocked.

**CWE/OWASP:** CWE-79; OWASP A03 Injection.

### SR-07 — Retention, backup, recovery, and security-event export are undefined

- **Severity:** Medium before real data; Informational now
- **Confidence:** High
- **Affected:** D1 operational lifecycle
- **Status:** Production blocker for real data

**Description:** The schema stores emails, account IDs, plans, audit details, and evidence-export attribution without automated retention, deletion, export, backup, restore testing, or external SIEM integration.

**Exploitation scenario:** Data accumulates indefinitely, cannot be deleted or restored reliably, or disappears during an incident without independent security telemetry.

**Impact:** Privacy, compliance, investigation, and availability failures.

**Recommended fix:** Define data inventory and lawful purpose, table-specific retention, expiry jobs, subject/customer export and deletion, encrypted backups, restore objectives, legal hold, secure destruction, and SIEM export with field minimization.

**Validation:** Automated expiry, deletion, backup, point-in-time restore, audit continuity, and access-control tests.

**CWE/OWASP:** CWE-404/CWE-778; OWASP A09.

### SR-08 — Runtime schema initialization duplicates migrations

- **Severity:** Low
- **Confidence:** High
- **Affected:** `db/schema.ts`, `drizzle/*.sql`, deployment and local startup
- **Status:** Remediated; migrations are the only schema and seed authority

**Description:** Previously, table definitions existed in Drizzle schema, SQL migration, and runtime `CREATE TABLE IF NOT EXISTS` statements. Request-time DDL and seeding have been removed; local startup and integration tests now apply reviewed migrations before traffic is served.

**Exploitation scenario:** A future constraint is added only to migration while local/runtime initialization silently creates a weaker table.

**Impact:** Environment-specific security behavior and missing database enforcement.

**Recommended fix:** Keep migrations as the only production and local schema authority. Fail deployment or startup when migrations cannot be applied.

**Validation:** Compare `sqlite_master` output for a migrated database and a fresh local database in CI.

**CWE/OWASP:** CWE-16; OWASP A05 Security Misconfiguration.

### SR-09 — Identity lifecycle is static allowlist management

- **Severity:** Informational now; Medium at organizational scale
- **Confidence:** High
- **Affected:** environment role lists and operations
- **Status:** Scale/readiness gap

**Description:** Roles are comma-separated environment values. There is no group mapping, SCIM lifecycle, access review workflow, step-up authentication, or delegated workspace administration.

**Exploitation scenario:** Departed or transferred personnel remain on an allowlist, or an administrator receives excessive standing privilege.

**Impact:** Stale access and weak governance.

**Recommended fix:** Use enterprise IdP groups, MFA/step-up requirements, SCIM deprovisioning, least-privilege roles, periodic access certification, and emergency access controls. Preserve server-side capability enforcement.

**Validation:** Joiner/mover/leaver and group-change tests, stale-session revocation, MFA policy, and access-review evidence.

**CWE/OWASP:** CWE-266; OWASP A01/A07.

## 6. Exploitation chains and combined risk

### Direct-origin exposure to administrator impersonation

Direct Worker exposure + trusted raw identity header + known administrator email -> application administrator -> signed plan and connector requests. No cloud execution follows today, but future runner connectivity would turn this into a critical chain. The deployment boundary must be enforced before runner work.

### Over-broad topology projection plus compromised browser

Real data ingested without pagination/field minimization + viewer access or browser compromise -> download the full authorized workspace snapshot -> targeted cloud attack reconnaissance. Purpose-specific authorized queries are required before real ingestion.

### Control-plane secret plus database compromise

Signing-secret theft + D1 write access -> forged packages + rewritten local audit chain -> plausible false history. Asymmetric KMS signing, external audit anchoring, and independent monitoring break this chain.

### Unsafe runner addition

Existing plan UI + new AWS SDK/control-plane credentials without runner protocol -> compromised operator/control plane -> arbitrary AWS actions. ADR 0001 and the runner gates explicitly prohibit this path.

## 7. Dependency and configuration risks

- The production dependency audit reports zero known vulnerabilities at the current validation. The full development audit reports two high-severity infinite-loop advisories in `image-size@2.0.2`, introduced only through the Vinext build tool. Upstream lists no patched `image-size` release as of August 11, 2026. The package is not imported by application code or included in `dist/server`. A tested Vinext 0.0.45 downgrade removed the dependency but crashed the built Worker during stateful API traffic, so it was rejected. Treat repository image inputs as untrusted, keep the package out of the deployed artifact, monitor upstream, and upgrade as soon as Vinext can remove or patch it.
- The lockfile is required. Do not publish installs produced without it.
- CI actions are pinned to full SHAs and use read-only repository permissions.
- Package install scripts remain a supply-chain execution surface; use trusted registries, review lockfile diffs, preserve provenance/SBOMs, and consider a package-install allowlist.
- `PUBLIC_APP_ORIGIN` is validated as an absolute HTTP(S) origin, eliminating Host-derived metadata.
- Hosted configuration must omit local mode and protect the signing secret.
- Local Wrangler includes development tooling and is not a public server.

## 8. Secure design gaps

- Real AWS discovery, dynamic path calculation, and cloud execution do not exist.
- Workspace scoping exists, but multi-organization identity, keys, lifecycle, and isolation tests do not.
- Two-person control-plane approval exists; step-up authentication, nonces, and runner-bound asymmetric authorization do not.
- No asymmetric signing, replay nonce store, verifier protocol, or key revocation exists.
- D1 snapshot ingestion exists for the demo seed; real collector ingestion and server-side pagination do not.
- No retention, customer deletion/export, backup/restore, SIEM, or external audit anchor exists.
- No SSO group/SCIM/step-up administration exists beyond Sites identity and environment lists.
- No independent security assessment or production compliance evidence exists.

## 9. Remediation roadmap

### Phase 0 — Maintain current safety floor

- Keep the repository private or appropriately licensed and reviewed before public distribution.
- Keep live AWS execution absent.
- Enforce private Sites access and role allowlists.
- Run all release gates and remediate future advisories.

### Phase 1 — Real control-plane readiness

- Complete server-derived tenant/workspace identity and multi-tenant negative tests; the demo catalog is already server-owned.
- Add paginated authorized APIs and isolation tests.
- Implement automated audit verification, external anchoring, SIEM export, retention, backups, and restore exercises.
- Replace static role lists with governed IdP groups and lifecycle controls.
- Deploy nonce/hash-based CSP hardening.

### Phase 2 — Cryptographic and approval protocol

- Adopt KMS-backed asymmetric signing and versioned canonical protocol.
- Implement two-person approval, step-up authentication, expiry, one-time nonces, revocation, and state-machine concurrency.
- Build independent verifiers and protocol fuzz/property tests.

### Phase 3 — Customer-hosted runner

- Implement every mandatory control in `runner-security-design.md`.
- Validate in isolated synthetic AWS organizations with budget, SCP, permission-boundary, tag, egress, and kill-switch controls.
- Complete independent application, protocol, runner, AWS, and supply-chain penetration tests.

### Phase 4 — Limited production pilot

- Explicit customer authorization and account ownership proof.
- Restricted modules/canary accounts only.
- Continuous monitoring, incident exercises, evidence verification, support and vulnerability processes.
- Formal go/no-go review for every expansion of AWS permissions or target classes.

## 10. Security test plan

### Automated now

Current tests cover identity redirect, authorized rendering, response headers, direct-origin rejection, CSRF, body-stream limits, plan signing/non-execution, approval separation and concurrent decisions, governed remediation transitions, guardrail protection, RBAC, connector secret handling, non-executable discovery, evidence manifests, pending runner enrollment, signed reports, and audit verification. Artifact and dependency gates cover stale files, listener binding, hardening presence, and advisories.

### Add before real data

- Two-workspace authorization matrix and identifier tampering.
- Query pagination/limits and response field minimization.
- Audit-chain verifier and corruption cases.
- Retention, deletion, backup, restore, and personal-data export.
- Load, concurrency, race, and rate-limit boundary tests.
- CSP browser tests without unsafe inline execution.
- Secret-scanning and build-provenance verification.

### Add before runner

- Signature/canonicalization known-answer and fuzz tests.
- Nonce replay, expiry, wrong audience/account/runner, revoked key, and downgrade tests.
- Module allowlist and IAM policy negative testing.
- SSRF/egress, metadata, DNS rebinding, redirect, and certificate tests.
- Container/process sandbox escape and resource exhaustion tests.
- Cleanup failure, kill switch, control-plane outage, and evidence upload failure.
- Malicious update, rollback, dependency, and signing compromise simulations.
- Independent manual adversarial assessment.

## 11. Open questions and assumptions

- Will the long-term hosting path always guarantee an unbypassable trusted identity dispatcher?
- Is the product single-tenant per deployment or multi-tenant SaaS?
- Which IdP, MFA, SCIM, and access-review requirements apply?
- What data classes, jurisdictions, retention periods, and evidence obligations apply?
- Who owns the signing keys, runner workload identity, and emergency kill switch?
- Which AWS accounts, partitions, regions, services, modules, resources, tags, and operations may ever be validated?
- What explicit customer authorization artifact is required before each plan?
- What are the recovery objectives, backup custody, SIEM, and incident-notification requirements?
- Which independent assessor and launch criteria will approve the first runner pilot?

Assumptions for this review: the exposure snapshot and generated attack-path evidence remain synthetic; access remains local or private Sites; the Sites dispatcher is trusted; pending runner enrollment has no communication channel or cloud credentials; and no other services write the D1 records.

## Remediated findings from the prototype baseline

The following previously confirmed issues are fixed in the current working tree:

- missing application authentication/RBAC;
- client-only validation approval and execution simulation;
- forgeable localStorage run history and browser-authoritative validation evidence;
- known dependency advisories present in the earlier lockfile;
- missing primary response security headers;
- local service bound to all interfaces;
- stale files surviving into deployment artifacts;
- Host-derived social metadata;
- absence of application rate limits on primary stateful operations;
- unsafe dormant example API code.

Regression tests and artifact checks must remain in place so these controls do not silently regress.

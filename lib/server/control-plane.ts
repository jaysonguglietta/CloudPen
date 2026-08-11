import "server-only";
import {
  type AuditRecord,
  type ConnectorRecord,
  type ControlPlaneSnapshot,
  type EvidenceRecord,
  type ExposureCatalog,
  type AttackPath,
  type RemediationRecord,
  type RunnerRecord,
  type ValidationRun,
} from "../cloudpen-data";
import type { AuthorizedUser } from "../security/authorization";
import { runtimeBindings, signingKey } from "../security/runtime";

const WORKSPACE_ID = "northstar-labs";
const encoder = new TextEncoder();

export type GuardrailPolicy = {
  requireApproval: boolean;
  canaryOnly: boolean;
  redactEvidence: boolean;
  cleanupRequired: boolean;
  maxConcurrency: number;
  maxSessionMinutes: number;
};

export async function listValidationRuns(user: AuthorizedUser): Promise<ValidationRun[]> {
  const db = database();
  await enforceRateLimit(db, `read:${user.email.toLowerCase()}`, 120, 60);
  await expireStalePlans(db);
  const result = await db
    .prepare(`SELECT id, attack_path_id, name, mode, status, findings, requested_by, approved_by,
      authorization_digest, plan_signature, expires_at, decision_reason, created_at
      FROM validation_runs WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100`)
    .bind(WORKSPACE_ID)
    .all<Record<string, unknown>>();

  return result.results.map((row: Record<string, unknown>) => ({
    id: String(row.id),
    name: String(row.name),
    mode: row.mode as ValidationRun["mode"],
    status: row.status as ValidationRun["status"],
    pathCount: 1,
    findings: Number(row.findings),
    requestedBy: String(row.requested_by),
    started: new Date(String(row.created_at)).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }),
    duration: row.status === "Planned" || row.status === "Awaiting approval" ? "Not executed" : "Recorded",
    attackPathId: String(row.attack_path_id),
    authorizationDigest: String(row.authorization_digest),
    signature: String(row.plan_signature),
    expiresAt: String(row.expires_at),
    approvedBy: row.approved_by ? String(row.approved_by) : null,
    decisionReason: row.decision_reason ? String(row.decision_reason) : null,
  }));
}

export async function createValidationPlan(
  user: AuthorizedUser,
  input: { attackPathId: string; mode: "Read-only" | "Active canary"; acknowledged: boolean },
): Promise<{ run: ValidationRun; receipt: { algorithm: string; keyId: string; authorizationDigest: string; signature: string; executable: false } }> {
  const db = database();
  await enforceRateLimit(db, `plan:${user.email.toLowerCase()}`, 10, 60);

  const path = await findAttackPath(db, input.attackPathId);
  if (!path) throw new ValidationError("Unknown attack path.");
  if (input.mode !== "Read-only" && input.mode !== "Active canary") throw new ValidationError("Unsupported validation mode.");
  if (input.mode === "Active canary" && !input.acknowledged) {
    throw new ValidationError("Active canary plans require an explicit authorization acknowledgement.");
  }

  const policy = await getGuardrailPolicy(user);
  if (input.mode === "Active canary" && (!policy.requireApproval || !policy.canaryOnly || !policy.cleanupRequired)) {
    throw new ValidationError("The active-canary policy is not fail-safe and cannot issue a plan.");
  }

  const id = `RUN-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const status = input.mode === "Active canary" ? "Awaiting approval" : "Planned";
  const plan = {
    id,
    workspaceId: WORKSPACE_ID,
    attackPathId: path.id,
    mode: input.mode,
    status,
    requester: user.email.toLowerCase(),
    createdAt,
    expiresAt: new Date(Date.now() + policy.maxSessionMinutes * 60_000).toISOString(),
    constraints: policy,
    executable: false,
  } as const;
  const canonicalPlan = canonicalJson(plan);
  const authorizationDigest = await sha256(canonicalPlan);
  const planSignature = await hmac(canonicalPlan);

  await db.prepare(`INSERT INTO validation_runs
    (id, workspace_id, attack_path_id, name, mode, status, requested_by, authorization_digest, plan_signature, expires_at, findings, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`)
    .bind(id, WORKSPACE_ID, path.id, `${path.id} · ${path.title}`, input.mode, status, user.email, authorizationDigest, planSignature, plan.expiresAt, createdAt, createdAt)
    .run();
  await appendAuditEvent(db, user.email, "validation.plan.created", id, {
    attackPathId: path.id,
    mode: input.mode,
    status,
    authorizationDigest,
  });

  return {
    run: {
      id,
      name: `${path.id} · ${path.title}`,
      mode: input.mode,
      status,
      pathCount: 1,
      findings: 0,
      requestedBy: user.displayName,
      started: new Date(createdAt).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }),
      duration: "Not executed",
      attackPathId: path.id,
      authorizationDigest,
      signature: planSignature,
      expiresAt: plan.expiresAt,
      approvedBy: null,
      decisionReason: null,
    },
    receipt: {
      algorithm: "HMAC-SHA-256",
      keyId: "cloudpen-plan-v1",
      authorizationDigest,
      signature: planSignature,
      executable: false,
    },
  };
}

export async function getGuardrailPolicy(user: AuthorizedUser): Promise<GuardrailPolicy> {
  const db = database();
  await enforceRateLimit(db, `policy-read:${user.email.toLowerCase()}`, 120, 60);
  const row = await db.prepare(`SELECT require_approval, canary_only, redact_evidence, cleanup_required,
      max_concurrency, max_session_minutes FROM guardrail_policies WHERE workspace_id = ?`)
    .bind(WORKSPACE_ID)
    .first<Record<string, unknown>>();
  if (!row) throw new Error("Guardrail policy is unavailable.");
  return {
    requireApproval: Boolean(row.require_approval),
    canaryOnly: Boolean(row.canary_only),
    redactEvidence: Boolean(row.redact_evidence),
    cleanupRequired: Boolean(row.cleanup_required),
    maxConcurrency: Number(row.max_concurrency),
    maxSessionMinutes: Number(row.max_session_minutes),
  };
}

export async function updateGuardrailPolicy(
  user: AuthorizedUser,
  patch: Partial<Pick<GuardrailPolicy, "requireApproval" | "canaryOnly" | "redactEvidence" | "cleanupRequired">>,
): Promise<GuardrailPolicy> {
  const db = database();
  await enforceRateLimit(db, `configure:${user.email.toLowerCase()}`, 20, 60);
  const current = await getGuardrailPolicy(user);
  const next = { ...current, ...patch };
  if (!next.requireApproval || !next.canaryOnly || !next.redactEvidence || !next.cleanupRequired) {
    throw new ValidationError("Core production safety controls cannot be disabled in this release.");
  }
  await db.prepare(`UPDATE guardrail_policies SET require_approval = ?, canary_only = ?, redact_evidence = ?,
      cleanup_required = ?, updated_by = ?, updated_at = ? WHERE workspace_id = ?`)
    .bind(next.requireApproval ? 1 : 0, next.canaryOnly ? 1 : 0, next.redactEvidence ? 1 : 0,
      next.cleanupRequired ? 1 : 0, user.email, new Date().toISOString(), WORKSPACE_ID)
    .run();
  await appendAuditEvent(db, user.email, "guardrail.policy.updated", WORKSPACE_ID, next);
  return next;
}

export async function createEvidencePackage(user: AuthorizedUser, attackPathId: string) {
  const db = database();
  await enforceRateLimit(db, `evidence:${user.email.toLowerCase()}`, 20, 60);
  const path = await findAttackPath(db, attackPathId);
  if (!path) throw new ValidationError("Unknown attack path.");
  const issuedAt = new Date().toISOString();
  const payload = {
    schema: "cloudpen.evidence.v1",
    classification: "CONFIDENTIAL — AUTHORIZED SECURITY VALIDATION",
    workspaceId: WORKSPACE_ID,
    issuedAt,
    issuedTo: user.email,
    evidence: {
      pathId: path.id,
      status: path.status,
      techniques: path.techniques,
      observations: path.evidence,
      rootCause: path.rootCause,
      remediation: path.remediation,
    },
    redaction: { customerPayloads: "removed", credentials: "removed", tokens: "removed" },
  };
  const canonical = canonicalJson(payload);
  const digest = await sha256(canonical);
  const signature = await hmac(canonical);
  const packageId = `EV-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  await db.prepare(`INSERT INTO evidence_packages
    (id, workspace_id, path_id, classification, digest, signature, key_id, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(packageId, WORKSPACE_ID, path.id, payload.classification, digest, signature, "cloudpen-plan-v1", user.email, issuedAt)
    .run();
  await appendAuditEvent(db, user.email, "evidence.exported", path.id, { digest });
  return { packageId, payload, integrity: { algorithm: "HMAC-SHA-256", keyId: "cloudpen-plan-v1", digest, signature } };
}

export async function recordConnectorRequest(
  user: AuthorizedUser,
  input: { name: string; accountId: string; externalId: string },
) {
  const db = database();
  await enforceRateLimit(db, `connect:${user.email.toLowerCase()}`, 5, 300);
  const existing = await db.prepare("SELECT id FROM connectors WHERE workspace_id = ? AND account_id = ?")
    .bind(WORKSPACE_ID, input.accountId).first<{ id: string }>();
  if (existing) throw new ConflictError("This AWS account already has a connector in the workspace.");
  const id = `CON-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const externalIdDigest = await sha256(input.externalId);
  await db.prepare(`INSERT INTO connectors
    (id, workspace_id, provider, name, account_id, status, external_id_digest, external_id_hint, created_by, created_at, updated_at)
    VALUES (?, ?, 'AWS', ?, ?, 'Runner required', ?, ?, ?, ?, ?)`)
    .bind(id, WORKSPACE_ID, input.name, input.accountId, externalIdDigest, `••••${input.externalId.slice(-4)}`, user.email, createdAt, createdAt)
    .run();
  await appendAuditEvent(db, user.email, "connector.requested", id, {
    name: input.name,
    accountId: input.accountId,
    externalIdDigest,
    status: "awaiting-runner-provisioning",
  });
  return { id, status: "Runner required" as const };
}

export async function getExposureCatalog(user: AuthorizedUser): Promise<ExposureCatalog> {
  const db = database();
  await enforceRateLimit(db, `catalog-read:${user.email.toLowerCase()}`, 120, 60);
  const snapshot = await db.prepare(`SELECT id, source, status, collected_at FROM exposure_snapshots
    WHERE workspace_id = ? ORDER BY collected_at DESC LIMIT 1`).bind(WORKSPACE_ID)
    .first<{ id: string; source: ExposureCatalog["snapshot"]["source"]; status: ExposureCatalog["snapshot"]["status"]; collected_at: string }>();
  if (!snapshot) throw new Error("Exposure snapshot is unavailable.");
  const [accountRows, assetRows, pathRows] = await Promise.all([
    db.prepare("SELECT data_json FROM cloud_accounts WHERE workspace_id = ? AND snapshot_id = ? ORDER BY id")
      .bind(WORKSPACE_ID, snapshot.id).all<{ data_json: string }>(),
    db.prepare("SELECT data_json FROM cloud_assets WHERE workspace_id = ? AND snapshot_id = ? ORDER BY id")
      .bind(WORKSPACE_ID, snapshot.id).all<{ data_json: string }>(),
    db.prepare("SELECT data_json FROM exposure_paths WHERE workspace_id = ? AND snapshot_id = ? ORDER BY id DESC")
      .bind(WORKSPACE_ID, snapshot.id).all<{ data_json: string }>(),
  ]);
  return {
    accounts: accountRows.results.map((row) => JSON.parse(row.data_json)),
    assets: assetRows.results.map((row) => JSON.parse(row.data_json)),
    attackPaths: pathRows.results.map((row) => JSON.parse(row.data_json)),
    snapshot: { id: snapshot.id, source: snapshot.source, status: snapshot.status, collectedAt: snapshot.collected_at },
  };
}

export async function getControlPlaneSnapshot(user: AuthorizedUser): Promise<ControlPlaneSnapshot> {
  const db = database();
  await enforceRateLimit(db, `snapshot-read:${user.email.toLowerCase()}`, 60, 60);
  const [workspace, runs, connectorRows, evidenceRows, remediationRows, auditRows, runnerRows] = await Promise.all([
    db.prepare("SELECT name, data_mode FROM workspaces WHERE id = ?")
      .bind(WORKSPACE_ID).first<{ name: string; data_mode: "demo" | "live" }>(),
    listValidationRuns(user),
    db.prepare(`SELECT id, name, account_id, provider, status, external_id_hint, created_by,
      created_at, last_sync_at, error_message FROM connectors WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100`)
      .bind(WORKSPACE_ID).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, path_id, classification, digest, key_id, created_by, created_at
      FROM evidence_packages WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100`)
      .bind(WORKSPACE_ID).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, path_id, title, status, priority, owner, due_at, guidance, created_at, updated_at
      FROM remediations WHERE workspace_id = ? ORDER BY updated_at DESC LIMIT 100`)
      .bind(WORKSPACE_ID).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, actor_email, action, target, previous_hash, event_hash, created_at
      FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT 200`)
      .bind(WORKSPACE_ID).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, name, status, public_key_fingerprint, executable, created_by, created_at
      FROM runner_enrollments WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 20`)
      .bind(WORKSPACE_ID).all<Record<string, unknown>>(),
  ]);
  const connectors: ConnectorRecord[] = connectorRows.results.map((row) => ({
    id: String(row.id), name: String(row.name), accountId: String(row.account_id), provider: "AWS",
    status: row.status as ConnectorRecord["status"], externalIdHint: String(row.external_id_hint),
    createdBy: String(row.created_by), createdAt: String(row.created_at),
    lastSyncAt: row.last_sync_at ? String(row.last_sync_at) : null,
    errorMessage: row.error_message ? String(row.error_message) : null,
  }));
  const evidence: EvidenceRecord[] = evidenceRows.results.map((row) => ({
    id: String(row.id), pathId: String(row.path_id), classification: String(row.classification),
    digest: String(row.digest), keyId: String(row.key_id), createdBy: String(row.created_by), createdAt: String(row.created_at),
  }));
  const remediations: RemediationRecord[] = remediationRows.results.map((row) => ({
    id: String(row.id), pathId: String(row.path_id), title: String(row.title),
    status: row.status as RemediationRecord["status"], priority: row.priority as RemediationRecord["priority"],
    owner: String(row.owner), dueAt: String(row.due_at), guidance: String(row.guidance),
    createdAt: String(row.created_at), updatedAt: String(row.updated_at),
  }));
  const audit: AuditRecord[] = auditRows.results.map((row) => ({
    id: String(row.id), actorEmail: String(row.actor_email), action: String(row.action), target: String(row.target),
    previousHash: String(row.previous_hash), eventHash: String(row.event_hash), createdAt: String(row.created_at),
  }));
  const runners: RunnerRecord[] = runnerRows.results.map((row) => ({
    id: String(row.id), name: String(row.name), status: row.status as RunnerRecord["status"],
    publicKeyFingerprint: String(row.public_key_fingerprint), executable: false,
    createdBy: String(row.created_by), createdAt: String(row.created_at),
  }));
  if (!workspace) throw new Error("Workspace configuration is unavailable.");
  return {
    workspace: { id: WORKSPACE_ID, name: workspace.name, dataMode: workspace.data_mode, role: user.role },
    runs, connectors, evidence, remediations, audit, runners, auditChainValid: await verifyAuditChain(db),
  };
}

export async function createRunnerEnrollment(
  user: AuthorizedUser,
  input: { name: string; publicKeyFingerprint: string },
): Promise<RunnerRecord> {
  const db = database();
  await enforceRateLimit(db, `runner-enroll:${user.email.toLowerCase()}`, 3, 300);
  const now = new Date().toISOString();
  const record: RunnerRecord = {
    id: `RNR-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    name: input.name, status: "Pending", publicKeyFingerprint: input.publicKeyFingerprint,
    executable: false, createdBy: user.email, createdAt: now,
  };
  await db.prepare(`INSERT INTO runner_enrollments
    (id, workspace_id, name, status, public_key_fingerprint, executable, created_by, created_at)
    VALUES (?, ?, ?, 'Pending', ?, 0, ?, ?)`)
    .bind(record.id, WORKSPACE_ID, record.name, record.publicKeyFingerprint, user.email, now).run();
  await appendAuditEvent(db, user.email, "runner.enrollment.requested", record.id, {
    publicKeyFingerprint: record.publicKeyFingerprint, status: record.status, executable: false,
  });
  return record;
}

export async function createAssessmentReport(user: AuthorizedUser) {
  const db = database();
  await enforceRateLimit(db, `report:${user.email.toLowerCase()}`, 10, 60);
  const catalog = await getExposureCatalog(user);
  const snapshot = await getControlPlaneSnapshot(user);
  const issuedAt = new Date().toISOString();
  const payload = {
    schema: "cloudpen.assessment.v1",
    classification: "CONFIDENTIAL — AUTHORIZED SECURITY VALIDATION",
    workspace: snapshot.workspace,
    issuedAt,
    summary: {
      attackPaths: catalog.attackPaths.length,
      validatedPaths: catalog.attackPaths.filter((path) => path.status === "Validated").length,
      criticalPaths: catalog.attackPaths.filter((path) => path.severity === "Critical" && path.status !== "Mitigated").length,
      openRemediations: snapshot.remediations.filter((item) => item.status !== "Closed").length,
      connectedAccounts: snapshot.connectors.length,
      retainedEvidencePackages: snapshot.evidence.length,
    },
    paths: catalog.attackPaths.map((path) => ({
      id: path.id, title: path.title, severity: path.severity, status: path.status,
      score: path.score, account: path.account, target: path.target, techniques: path.techniques,
      rootCause: path.rootCause, remediation: path.remediation,
    })),
    remediations: snapshot.remediations,
    assurance: { auditChainValid: snapshot.auditChainValid, executable: false, dataMode: snapshot.workspace.dataMode },
  };
  const canonical = canonicalJson(payload);
  const integrity = { algorithm: "HMAC-SHA-256", keyId: "cloudpen-plan-v1", digest: await sha256(canonical), signature: await hmac(canonical) };
  await appendAuditEvent(db, user.email, "assessment.report.exported", WORKSPACE_ID, { digest: integrity.digest });
  return { payload, integrity };
}

export async function decideValidationRun(
  user: AuthorizedUser,
  runId: string,
  decision: "approve" | "reject" | "cancel",
  reason: string,
): Promise<void> {
  const db = database();
  await enforceRateLimit(db, `decision:${user.email.toLowerCase()}`, 30, 60);
  await expireStalePlans(db);
  const row = await db.prepare(`SELECT status, requested_by, expires_at FROM validation_runs
    WHERE id = ? AND workspace_id = ?`).bind(runId, WORKSPACE_ID)
    .first<{ status: string; requested_by: string; expires_at: string }>();
  if (!row) throw new NotFoundError("Validation run not found.");
  if (decision === "cancel") {
    if (row.requested_by.toLowerCase() !== user.email.toLowerCase() && user.role !== "admin") {
      throw new ValidationError("Only the requester or an administrator may cancel this plan.");
    }
    if (!new Set(["Planned", "Awaiting approval", "Approved"]).has(row.status)) throw new ConflictError("This plan can no longer be cancelled.");
  } else {
    if (row.status !== "Awaiting approval") throw new ConflictError("Only awaiting-approval plans can be reviewed.");
    if (row.requested_by.toLowerCase() === user.email.toLowerCase()) throw new ValidationError("Requesters cannot approve or reject their own active plan.");
  }
  const status = decision === "approve" ? "Approved" : decision === "reject" ? "Rejected" : "Stopped";
  const now = new Date().toISOString();
  await db.prepare(`UPDATE validation_runs SET status = ?, approved_by = ?, decision_reason = ?, updated_at = ?
    WHERE id = ? AND workspace_id = ?`)
    .bind(status, decision === "cancel" ? null : user.email, reason, now, runId, WORKSPACE_ID).run();
  await appendAuditEvent(db, user.email, `validation.plan.${decision}d`, runId, { status, reason, executable: false });
}

export async function createRemediation(
  user: AuthorizedUser,
  input: { pathId: string; owner: string; dueAt: string },
): Promise<RemediationRecord> {
  const db = database();
  await enforceRateLimit(db, `remediation-create:${user.email.toLowerCase()}`, 20, 60);
  const path = await findAttackPath(db, input.pathId);
  if (!path) throw new ValidationError("Unknown attack path.");
  const existing = await db.prepare("SELECT id FROM remediations WHERE workspace_id = ? AND path_id = ? AND status != 'Closed'")
    .bind(WORKSPACE_ID, path.id).first<{ id: string }>();
  if (existing) throw new ConflictError("An open remediation already exists for this path.");
  const now = new Date().toISOString();
  const record: RemediationRecord = {
    id: `REM-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    pathId: path.id, title: `Restrict access for ${path.title}`, status: "Open", priority: path.severity,
    owner: input.owner, dueAt: input.dueAt, guidance: path.remediation, createdAt: now, updatedAt: now,
  };
  await db.prepare(`INSERT INTO remediations
    (id, workspace_id, path_id, title, status, priority, owner, due_at, guidance, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(record.id, WORKSPACE_ID, record.pathId, record.title, record.status, record.priority, record.owner,
      record.dueAt, record.guidance, user.email, now, now).run();
  await appendAuditEvent(db, user.email, "remediation.created", record.id, { pathId: path.id, owner: input.owner, dueAt: input.dueAt });
  return record;
}

export async function updateRemediation(
  user: AuthorizedUser,
  id: string,
  input: { status: RemediationRecord["status"] },
): Promise<void> {
  const db = database();
  await enforceRateLimit(db, `remediation-update:${user.email.toLowerCase()}`, 60, 60);
  const result = await db.prepare("UPDATE remediations SET status = ?, updated_at = ? WHERE id = ? AND workspace_id = ?")
    .bind(input.status, new Date().toISOString(), id, WORKSPACE_ID).run();
  if (!result.meta.changes) throw new NotFoundError("Remediation not found.");
  await appendAuditEvent(db, user.email, "remediation.status.updated", id, input);
}

export async function createDiscoveryPlan(user: AuthorizedUser, connectorId: string) {
  const db = database();
  await enforceRateLimit(db, `discovery:${user.email.toLowerCase()}`, 10, 60);
  const connector = await db.prepare("SELECT id, account_id, status FROM connectors WHERE id = ? AND workspace_id = ?")
    .bind(connectorId, WORKSPACE_ID).first<{ id: string; account_id: string; status: string }>();
  if (!connector || connector.status === "Disabled") throw new NotFoundError("Active connector not found.");
  const id = `DISC-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const scope = { provider: "AWS", accountId: connector.account_id, mode: "metadata-read-only", services: ["iam", "organizations", "s3", "lambda", "kms", "ec2", "ecr", "ecs"], executable: false };
  await db.prepare(`INSERT INTO discovery_jobs (id, workspace_id, connector_id, status, scope_json, executable, created_by, created_at)
    VALUES (?, ?, ?, 'Runner required', ?, 0, ?, ?)`)
    .bind(id, WORKSPACE_ID, connectorId, canonicalJson(scope), user.email, new Date().toISOString()).run();
  await appendAuditEvent(db, user.email, "discovery.plan.created", id, scope);
  return { id, status: "Runner required", scope };
}

export async function exportGuardrailPolicy(user: AuthorizedUser) {
  const policy = await getGuardrailPolicy(user);
  const payload = { schema: "cloudpen.guardrails.v1", workspaceId: WORKSPACE_ID, policy, issuedAt: new Date().toISOString(), executable: false };
  const canonical = canonicalJson(payload);
  return { payload, integrity: { algorithm: "HMAC-SHA-256", keyId: "cloudpen-plan-v1", digest: await sha256(canonical), signature: await hmac(canonical) } };
}

async function findAttackPath(db: D1Database, pathId: string): Promise<AttackPath | null> {
  const row = await db.prepare("SELECT data_json FROM exposure_paths WHERE workspace_id = ? AND id = ?")
    .bind(WORKSPACE_ID, `${WORKSPACE_ID}:${pathId}`).first<{ data_json: string }>();
  return row ? JSON.parse(row.data_json) as AttackPath : null;
}

async function expireStalePlans(db: D1Database): Promise<void> {
  const now = new Date().toISOString();
  await db.prepare(`UPDATE validation_runs SET status = 'Expired', updated_at = ?
    WHERE workspace_id = ? AND status IN ('Planned', 'Awaiting approval', 'Approved') AND expires_at <= ?`)
    .bind(now, WORKSPACE_ID, now).run();
}

async function verifyAuditChain(db: D1Database): Promise<boolean> {
  const rows = await db.prepare(`SELECT id, actor_email, action, target, details_json, previous_hash, event_hash, created_at
    FROM audit_events WHERE workspace_id = ? LIMIT 1000`)
    .bind(WORKSPACE_ID).all<Record<string, unknown>>();
  const byPrevious = new Map(rows.results.map((row) => [String(row.previous_hash), row]));
  let previousHash = "GENESIS";
  let visited = 0;
  while (byPrevious.has(previousHash)) {
    const row = byPrevious.get(previousHash)!;
    let details: unknown;
    try { details = JSON.parse(String(row.details_json)); } catch { return false; }
    const event = {
      id: String(row.id), workspaceId: WORKSPACE_ID, actorEmail: String(row.actor_email),
      action: String(row.action), target: String(row.target), details,
      previousHash: String(row.previous_hash), createdAt: String(row.created_at),
    };
    const expected = await sha256(canonicalJson(event));
    if (expected !== String(row.event_hash)) return false;
    previousHash = String(row.event_hash);
    visited += 1;
  }
  return visited === rows.results.length;
}

async function enforceRateLimit(db: D1Database, key: string, limit: number, windowSeconds: number): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + windowSeconds;
  await db.prepare(`INSERT INTO rate_limits (key, count, expires_at) VALUES (?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN rate_limits.expires_at <= ? THEN 1 ELSE rate_limits.count + 1 END,
      expires_at = CASE WHEN rate_limits.expires_at <= ? THEN excluded.expires_at ELSE rate_limits.expires_at END`)
    .bind(key, expiresAt, now, now)
    .run();
  const row = await db.prepare("SELECT count, expires_at FROM rate_limits WHERE key = ?").bind(key).first<{ count: number; expires_at: number }>();
  if (row && row.expires_at > now && row.count > limit) throw new RateLimitError();
}

async function appendAuditEvent(
  db: D1Database,
  actorEmail: string,
  action: string,
  target: string,
  details: unknown,
): Promise<void> {
  const previous = await db.prepare(`SELECT parent.event_hash FROM audit_events parent
      WHERE parent.workspace_id = ? AND NOT EXISTS (
        SELECT 1 FROM audit_events child WHERE child.workspace_id = parent.workspace_id AND child.previous_hash = parent.event_hash
      ) LIMIT 1`)
    .bind(WORKSPACE_ID)
    .first<{ event_hash: string }>();
  const event = {
    id: crypto.randomUUID(),
    workspaceId: WORKSPACE_ID,
    actorEmail: actorEmail.toLowerCase(),
    action,
    target,
    details,
    previousHash: previous?.event_hash ?? "GENESIS",
    createdAt: new Date().toISOString(),
  };
  const eventHash = await sha256(canonicalJson(event));
  await db.prepare(`INSERT INTO audit_events
    (id, workspace_id, actor_email, action, target, details_json, previous_hash, event_hash, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(event.id, WORKSPACE_ID, event.actorEmail, action, target, canonicalJson(details), event.previousHash, eventHash, event.createdAt)
    .run();
}

function database(): D1Database {
  const db = runtimeBindings().DB;
  if (!db) throw new Error("The durable control-plane database is unavailable.");
  return db;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toBase64Url(digest);
}

async function hmac(value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(signingKey()), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toBase64Url(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

function toBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export class ValidationError extends Error {
  readonly status = 400;
}

export class NotFoundError extends Error {
  readonly status = 404;
}

export class ConflictError extends Error {
  readonly status = 409;
}

export class RateLimitError extends Error {
  readonly status = 429;
  constructor() {
    super("Too many requests. Try again after the rate-limit window resets.");
  }
}

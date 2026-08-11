import "server-only";
import {
  accounts as demoAccounts,
  assets as demoAssets,
  attackPaths as demoAttackPaths,
  type AuditRecord,
  type ConnectorRecord,
  type ControlPlaneSnapshot,
  type EvidenceRecord,
  type ExposureCatalog,
  type AttackPath,
  type RemediationRecord,
  type RunnerRecord,
  type ScreenshotEvidenceRecord,
  type ValidationRun,
} from "../cloudpen-data";
import { controlById, controlFolderSegment, frameworkById, screenshotFilename } from "../compliance-controls";
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
  const [runs, connectorRows, evidenceRows, remediationRows, auditRows, runnerRows] = await Promise.all([
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
  return {
    workspace: { id: WORKSPACE_ID, name: "Northstar Labs", dataMode: "demo", role: user.role },
    runs, connectors, evidence, remediations, audit, runners, auditChainValid: await verifyAuditChain(db),
  };
}

export async function createRunnerEnrollment(
  user: AuthorizedUser,
  input: { name: string; publicKeyFingerprint: string },
): Promise<RunnerRecord> {
  const db = database();
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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

export async function listScreenshotEvidence(
  user: AuthorizedUser,
  filters: { frameworkId?: string; controlId?: string; query?: string },
): Promise<ScreenshotEvidenceRecord[]> {
  const db = database();
  await initializeControlPlane(db, user);
  await enforceRateLimit(db, `screenshot-read:${user.email.toLowerCase()}`, 120, 60);
  const frameworkId = filters.frameworkId?.trim() ?? "";
  const controlId = filters.controlId?.trim() ?? "";
  const query = filters.query?.trim().toLowerCase() ?? "";
  if (frameworkId && !frameworkById(frameworkId)) throw new ValidationError("Unknown compliance framework.");
  if (controlId && (!frameworkId || !controlById(frameworkId, controlId))) throw new ValidationError("Unknown compliance control.");
  if (query.length > 100) throw new ValidationError("Screenshot search is limited to 100 characters.");
  const escapedQuery = `%${query.replaceAll("\\", "\\\\").replaceAll("%", "\\%").replaceAll("_", "\\_")}%`;
  const rows = await db.prepare(`SELECT id, framework_id, framework_label, control_id, control_label, title, notes,
      stored_filename, folder_path, banner_position, include_timestamp, include_actor, captured_at,
      width, height, size_bytes, sha256_digest, created_by, created_at
    FROM screenshot_evidence
    WHERE workspace_id = ?
      AND (? = '' OR framework_id = ?)
      AND (? = '' OR control_id = ?)
      AND (? = '' OR lower(title) LIKE ? ESCAPE '\\' OR lower(stored_filename) LIKE ? ESCAPE '\\'
        OR lower(notes) LIKE ? ESCAPE '\\' OR lower(control_label) LIKE ? ESCAPE '\\')
    ORDER BY created_at DESC LIMIT 100`)
    .bind(WORKSPACE_ID, frameworkId, frameworkId, controlId, controlId, query, escapedQuery, escapedQuery, escapedQuery, escapedQuery)
    .all<Record<string, unknown>>();
  return rows.results.map(screenshotRecordFromRow);
}

export async function createScreenshotEvidence(
  user: AuthorizedUser,
  input: {
    frameworkId: string;
    controlId: string;
    title: string;
    notes: string;
    customName: string;
    bannerPosition: "top" | "bottom";
    includeTimestamp: boolean;
    includeActor: boolean;
    capturedAt: string;
  },
  bytes: Uint8Array,
): Promise<ScreenshotEvidenceRecord> {
  const db = database();
  await initializeControlPlane(db, user);
  await enforceRateLimit(db, `screenshot-create:${user.email.toLowerCase()}`, 20, 600);
  const bucket = evidenceBucket();
  const framework = frameworkById(input.frameworkId);
  const control = controlById(input.frameworkId, input.controlId);
  if (!framework || !control) throw new ValidationError("A supported compliance framework and control are required.");
  if (input.title.trim().length < 2 || input.title.trim().length > 120) throw new ValidationError("Evidence title must be 2–120 characters.");
  if (input.notes.trim().length > 500) throw new ValidationError("Evidence notes are limited to 500 characters.");
  if (input.customName.trim().length < 1 || input.customName.trim().length > 80) throw new ValidationError("Custom filename must be 1–80 characters.");
  if (input.bannerPosition !== "top" && input.bannerPosition !== "bottom") throw new ValidationError("Unsupported banner position.");
  if (bytes.byteLength < 32 || bytes.byteLength > 12 * 1024 * 1024) throw new ValidationError("Screenshot must be a PNG no larger than 12 MiB.");
  const dimensions = pngDimensions(bytes);
  if (!dimensions || dimensions.width > 12000 || dimensions.height > 12000 || dimensions.width * dimensions.height > 60_000_000) {
    throw new ValidationError("Screenshot PNG dimensions are invalid or exceed the 60-megapixel limit.");
  }
  const capturedAt = new Date(input.capturedAt);
  if (Number.isNaN(capturedAt.valueOf()) || Math.abs(Date.now() - capturedAt.valueOf()) > 10 * 60_000) {
    throw new ValidationError("Capture timestamp is invalid or outside the allowed clock window.");
  }
  const createdAt = new Date().toISOString();
  const storedFilename = screenshotFilename({
    frameworkId: framework.id,
    controlId: control.id,
    customName: input.customName,
    capturedAt: capturedAt.toISOString(),
  });
  const date = new Date(createdAt);
  const folderPath = `${framework.id}/${controlFolderSegment(control.id)}/${date.getUTCFullYear()}/${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
  const id = `SCR-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const objectKey = `${WORKSPACE_ID}/screenshots/${folderPath}/${id.toLowerCase()}--${storedFilename}`;
  const sha256Digest = await sha256Bytes(bytes);
  await bucket.put(objectKey, bytes, {
    httpMetadata: {
      contentType: "image/png",
      cacheControl: "private, no-store",
      contentDisposition: `attachment; filename="${storedFilename}"`,
    },
    customMetadata: {
      framework: framework.id,
      control: control.id,
      digest: sha256Digest,
      capturedBy: user.email.toLowerCase(),
    },
  });
  try {
    await db.prepare(`INSERT INTO screenshot_evidence
      (id, workspace_id, framework_id, framework_label, control_id, control_label, title, notes, stored_filename,
        object_key, folder_path, banner_position, include_timestamp, include_actor, captured_at,
        width, height, size_bytes, sha256_digest, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, WORKSPACE_ID, framework.id, `${framework.label} ${framework.version}`, control.id, control.title,
        input.title.trim(), input.notes.trim(), storedFilename, objectKey, folderPath, input.bannerPosition,
        input.includeTimestamp ? 1 : 0, input.includeActor ? 1 : 0, capturedAt.toISOString(), dimensions.width,
        dimensions.height, bytes.byteLength, sha256Digest, user.email.toLowerCase(), createdAt)
      .run();
    await appendAuditEvent(db, user.email, "screenshot.evidence.created", id, {
      frameworkId: framework.id,
      controlId: control.id,
      folderPath,
      storedFilename,
      sha256Digest,
      sizeBytes: bytes.byteLength,
    });
  } catch (error) {
    await Promise.allSettled([
      bucket.delete(objectKey),
      db.prepare("DELETE FROM screenshot_evidence WHERE id = ? AND workspace_id = ?").bind(id, WORKSPACE_ID).run(),
    ]);
    throw error;
  }
  return {
    id,
    frameworkId: framework.id,
    frameworkLabel: `${framework.label} ${framework.version}`,
    controlId: control.id,
    controlLabel: control.title,
    title: input.title.trim(),
    notes: input.notes.trim(),
    storedFilename,
    folderPath,
    bannerPosition: input.bannerPosition,
    includeTimestamp: input.includeTimestamp,
    includeActor: input.includeActor,
    capturedAt: capturedAt.toISOString(),
    width: dimensions.width,
    height: dimensions.height,
    sizeBytes: bytes.byteLength,
    sha256Digest,
    createdBy: user.email.toLowerCase(),
    createdAt,
    contentUrl: `/api/screenshots/${id}/content`,
    downloadUrl: `/api/screenshots/${id}/content?download=1`,
  };
}

export async function getScreenshotEvidenceContent(user: AuthorizedUser, id: string) {
  const db = database();
  await initializeControlPlane(db, user);
  await enforceRateLimit(db, `screenshot-content:${user.email.toLowerCase()}`, 180, 60);
  const row = await db.prepare(`SELECT object_key, stored_filename, sha256_digest FROM screenshot_evidence
    WHERE id = ? AND workspace_id = ?`).bind(id, WORKSPACE_ID)
    .first<{ object_key: string; stored_filename: string; sha256_digest: string }>();
  if (!row) throw new NotFoundError("Screenshot evidence was not found.");
  const object = await evidenceBucket().get(row.object_key);
  if (!object) throw new NotFoundError("Screenshot image is unavailable.");
  return { object, storedFilename: row.stored_filename, sha256Digest: row.sha256_digest };
}

export async function decideValidationRun(
  user: AuthorizedUser,
  runId: string,
  decision: "approve" | "reject" | "cancel",
  reason: string,
): Promise<void> {
  const db = database();
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
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
  await initializeControlPlane(db, user);
  const result = await db.prepare("UPDATE remediations SET status = ?, updated_at = ? WHERE id = ? AND workspace_id = ?")
    .bind(input.status, new Date().toISOString(), id, WORKSPACE_ID).run();
  if (!result.meta.changes) throw new NotFoundError("Remediation not found.");
  await appendAuditEvent(db, user.email, "remediation.status.updated", id, input);
}

export async function createDiscoveryPlan(user: AuthorizedUser, connectorId: string) {
  const db = database();
  await initializeControlPlane(db, user);
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

async function initializeControlPlane(db: D1Database, user: AuthorizedUser): Promise<void> {
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL, data_mode TEXT NOT NULL DEFAULT 'demo' CHECK (data_mode IN ('demo', 'live')), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS memberships (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'reviewer', 'viewer')), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(workspace_id, email))"),
    db.prepare("CREATE TABLE IF NOT EXISTS guardrail_policies (workspace_id TEXT PRIMARY KEY, require_approval INTEGER NOT NULL DEFAULT 1 CHECK (require_approval IN (0, 1)), canary_only INTEGER NOT NULL DEFAULT 1 CHECK (canary_only IN (0, 1)), redact_evidence INTEGER NOT NULL DEFAULT 1 CHECK (redact_evidence IN (0, 1)), cleanup_required INTEGER NOT NULL DEFAULT 1 CHECK (cleanup_required IN (0, 1)), max_concurrency INTEGER NOT NULL DEFAULT 2 CHECK (max_concurrency BETWEEN 1 AND 4), max_session_minutes INTEGER NOT NULL DEFAULT 15 CHECK (max_session_minutes BETWEEN 1 AND 30), updated_by TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS validation_runs (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, attack_path_id TEXT NOT NULL, name TEXT NOT NULL, mode TEXT NOT NULL CHECK (mode IN ('Read-only', 'Active canary')), status TEXT NOT NULL CHECK (status IN ('Planned', 'Awaiting approval', 'Approved', 'Rejected', 'Expired', 'Stopped', 'Completed')), requested_by TEXT NOT NULL, approved_by TEXT, authorization_digest TEXT NOT NULL, plan_signature TEXT NOT NULL, expires_at TEXT NOT NULL, decision_reason TEXT, findings INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS connectors (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'AWS' CHECK (provider = 'AWS'), name TEXT NOT NULL, account_id TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('Draft', 'Awaiting verification', 'Verified', 'Runner required', 'Disabled', 'Error')), external_id_digest TEXT NOT NULL, external_id_hint TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_sync_at TEXT, error_message TEXT, UNIQUE(workspace_id, account_id))"),
    db.prepare("CREATE TABLE IF NOT EXISTS evidence_packages (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, path_id TEXT NOT NULL, classification TEXT NOT NULL, digest TEXT NOT NULL, signature TEXT NOT NULL, key_id TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS remediations (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, path_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('Open', 'In progress', 'Risk accepted', 'Ready to revalidate', 'Closed')), priority TEXT NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')), owner TEXT NOT NULL, due_at TEXT NOT NULL, guidance TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS discovery_jobs (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, connector_id TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('Planned', 'Runner required', 'Completed', 'Failed')), scope_json TEXT NOT NULL, executable INTEGER NOT NULL DEFAULT 0 CHECK (executable = 0), created_by TEXT NOT NULL, created_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS runner_enrollments (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('Pending', 'Disabled')), public_key_fingerprint TEXT NOT NULL, executable INTEGER NOT NULL DEFAULT 0 CHECK (executable = 0), created_by TEXT NOT NULL, created_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS exposure_snapshots (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, source TEXT NOT NULL CHECK (source IN ('demo-seed', 'aws-read-only')), status TEXT NOT NULL CHECK (status IN ('Complete', 'Partial')), collected_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS cloud_accounts (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, provider_account_id TEXT NOT NULL, data_json TEXT NOT NULL, UNIQUE(workspace_id, provider_account_id))"),
    db.prepare("CREATE TABLE IF NOT EXISTS cloud_assets (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, data_json TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS exposure_paths (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, data_json TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS graph_edges (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, source_node TEXT NOT NULL, target_node TEXT NOT NULL, relationship TEXT NOT NULL, evidence_json TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS screenshot_evidence (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, framework_id TEXT NOT NULL, framework_label TEXT NOT NULL, control_id TEXT NOT NULL, control_label TEXT NOT NULL, title TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '', stored_filename TEXT NOT NULL, object_key TEXT NOT NULL UNIQUE, folder_path TEXT NOT NULL, banner_position TEXT NOT NULL CHECK (banner_position IN ('top', 'bottom')), include_timestamp INTEGER NOT NULL DEFAULT 1 CHECK (include_timestamp IN (0, 1)), include_actor INTEGER NOT NULL DEFAULT 1 CHECK (include_actor IN (0, 1)), captured_at TEXT NOT NULL, width INTEGER NOT NULL CHECK (width BETWEEN 1 AND 12000), height INTEGER NOT NULL CHECK (height BETWEEN 1 AND 12000), size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 12582912), sha256_digest TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, actor_email TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, details_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, created_at TEXT NOT NULL)"),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS audit_events_chain_link ON audit_events (workspace_id, previous_hash)"),
    db.prepare("CREATE INDEX IF NOT EXISTS validation_runs_workspace_created ON validation_runs (workspace_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS audit_events_workspace_created ON audit_events (workspace_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS connectors_workspace_created ON connectors (workspace_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS evidence_workspace_created ON evidence_packages (workspace_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS remediations_workspace_updated ON remediations (workspace_id, updated_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS exposure_paths_workspace_snapshot ON exposure_paths (workspace_id, snapshot_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS cloud_assets_workspace_snapshot ON cloud_assets (workspace_id, snapshot_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS graph_edges_workspace_snapshot ON graph_edges (workspace_id, snapshot_id)"),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS screenshot_evidence_object_key ON screenshot_evidence (object_key)"),
    db.prepare("CREATE INDEX IF NOT EXISTS screenshot_evidence_workspace_control_created ON screenshot_evidence (workspace_id, framework_id, control_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS screenshot_evidence_workspace_created ON screenshot_evidence (workspace_id, created_at)"),
    db.prepare("CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL)"),
  ]);
  await ensureRuntimeSchemaCompatibility(db);
  await db.prepare("INSERT OR IGNORE INTO workspaces (id, name) VALUES (?, ?)").bind(WORKSPACE_ID, "Northstar Labs").run();
  await db.prepare(`INSERT OR IGNORE INTO memberships (id, workspace_id, email, role) VALUES (?, ?, ?, ?)`)
    .bind(`${WORKSPACE_ID}:${user.email.toLowerCase()}`, WORKSPACE_ID, user.email.toLowerCase(), user.role)
    .run();
  await db.prepare(`INSERT OR IGNORE INTO guardrail_policies
      (workspace_id, require_approval, canary_only, redact_evidence, cleanup_required, max_concurrency, max_session_minutes, updated_by)
      VALUES (?, 1, 1, 1, 1, 2, 15, ?)`)
    .bind(WORKSPACE_ID, user.email)
    .run();
  const demoSnapshotId = `${WORKSPACE_ID}:demo-v1`;
  const seeded = await db.prepare("SELECT id FROM exposure_snapshots WHERE id = ? AND workspace_id = ?")
    .bind(demoSnapshotId, WORKSPACE_ID).first<{ id: string }>();
  if (!seeded) {
    await db.prepare(`INSERT INTO exposure_snapshots (id, workspace_id, source, status, collected_at)
      VALUES (?, ?, 'demo-seed', 'Complete', ?)`)
      .bind(demoSnapshotId, WORKSPACE_ID, "2026-08-03T00:00:00.000Z").run();
    await db.batch([
    ...demoAccounts.map((account) => db.prepare(`INSERT OR IGNORE INTO cloud_accounts
      (id, workspace_id, snapshot_id, provider_account_id, data_json) VALUES (?, ?, ?, ?, ?)`)
      .bind(`${WORKSPACE_ID}:${account.id}`, WORKSPACE_ID, demoSnapshotId, account.id.replaceAll("-", ""), canonicalJson(account))),
    ...demoAssets.map((asset) => db.prepare(`INSERT OR IGNORE INTO cloud_assets
      (id, workspace_id, snapshot_id, data_json) VALUES (?, ?, ?, ?)`)
      .bind(`${WORKSPACE_ID}:${asset.id}`, WORKSPACE_ID, demoSnapshotId, canonicalJson(asset))),
    ...demoAttackPaths.map((path) => db.prepare(`INSERT OR IGNORE INTO exposure_paths
      (id, workspace_id, snapshot_id, data_json) VALUES (?, ?, ?, ?)`)
      .bind(`${WORKSPACE_ID}:${path.id}`, WORKSPACE_ID, demoSnapshotId, canonicalJson(path))),
    ...demoAttackPaths.flatMap((path) => path.steps.slice(0, -1).map((step, index) => db.prepare(`INSERT OR IGNORE INTO graph_edges
      (id, workspace_id, snapshot_id, source_node, target_node, relationship, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(`${WORKSPACE_ID}:${path.id}:${index}`, WORKSPACE_ID, demoSnapshotId, step.label, path.steps[index + 1].label,
        step.type === "permission" ? "permits" : "reaches", canonicalJson({ pathId: path.id, evidence: path.evidence })))),
    ]);
  }
}

async function ensureRuntimeSchemaCompatibility(db: D1Database): Promise<void> {
  const workspaceColumns = await db.prepare("PRAGMA table_info(workspaces)").all<{ name: string }>();
  if (!workspaceColumns.results.some((column) => column.name === "data_mode")) {
    await db.prepare("ALTER TABLE workspaces ADD data_mode TEXT NOT NULL DEFAULT 'demo' CHECK (data_mode IN ('demo', 'live'))").run();
  }

  const runColumns = await db.prepare("PRAGMA table_info(validation_runs)").all<{ name: string }>();
  if (!runColumns.results.some((column) => column.name === "expires_at")) {
    await db.batch([
      db.prepare("ALTER TABLE validation_runs RENAME TO validation_runs_legacy"),
      db.prepare("DROP INDEX IF EXISTS validation_runs_workspace_created"),
      db.prepare("CREATE TABLE validation_runs (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, attack_path_id TEXT NOT NULL, name TEXT NOT NULL, mode TEXT NOT NULL CHECK (mode IN ('Read-only', 'Active canary')), status TEXT NOT NULL CHECK (status IN ('Planned', 'Awaiting approval', 'Approved', 'Rejected', 'Expired', 'Stopped', 'Completed')), requested_by TEXT NOT NULL, approved_by TEXT, authorization_digest TEXT NOT NULL, plan_signature TEXT NOT NULL, expires_at TEXT NOT NULL, decision_reason TEXT, findings INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"),
      db.prepare(`INSERT INTO validation_runs
        (id, workspace_id, attack_path_id, name, mode, status, requested_by, approved_by, authorization_digest, plan_signature, expires_at, decision_reason, findings, created_at, updated_at)
        SELECT id, workspace_id, attack_path_id, name, mode, status, requested_by, approved_by, authorization_digest, plan_signature,
          datetime(created_at, '+15 minutes'), NULL, findings, created_at, updated_at FROM validation_runs_legacy`),
      db.prepare("DROP TABLE validation_runs_legacy"),
      db.prepare("CREATE INDEX validation_runs_workspace_created ON validation_runs (workspace_id, created_at)"),
    ]);
  }
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

function evidenceBucket(): R2Bucket {
  const bucket = runtimeBindings().EVIDENCE;
  if (!bucket) throw new Error("The private evidence object store is unavailable.");
  return bucket;
}

function screenshotRecordFromRow(row: Record<string, unknown>): ScreenshotEvidenceRecord {
  const id = String(row.id);
  return {
    id,
    frameworkId: String(row.framework_id),
    frameworkLabel: String(row.framework_label),
    controlId: String(row.control_id),
    controlLabel: String(row.control_label),
    title: String(row.title),
    notes: String(row.notes),
    storedFilename: String(row.stored_filename),
    folderPath: String(row.folder_path),
    bannerPosition: row.banner_position as "top" | "bottom",
    includeTimestamp: Number(row.include_timestamp) === 1,
    includeActor: Number(row.include_actor) === 1,
    capturedAt: String(row.captured_at),
    width: Number(row.width),
    height: Number(row.height),
    sizeBytes: Number(row.size_bytes),
    sha256Digest: String(row.sha256_digest),
    createdBy: String(row.created_by),
    createdAt: String(row.created_at),
    contentUrl: `/api/screenshots/${id}/content`,
    downloadUrl: `/api/screenshots/${id}/content?download=1`,
  };
}

function pngDimensions(bytes: Uint8Array): { width: number; height: number } | null {
  if (bytes.byteLength < 24) return null;
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  if (!signature.every((value, index) => bytes[index] === value)) return null;
  if (String.fromCharCode(...bytes.slice(12, 16)) !== "IHDR") return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const width = view.getUint32(16, false);
  const height = view.getUint32(20, false);
  return width > 0 && height > 0 ? { width, height } : null;
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

async function sha256Bytes(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value as BufferSource);
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

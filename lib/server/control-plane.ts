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
import { AuthorizationError, type AuthorizedUser } from "../security/authorization";
import { canonicalJson, sha256Base64Url } from "../security/canonical";
import { sanitizeAttackPathEvidence } from "../security/evidence";
import { runtimeBindings } from "../security/runtime";
import { signArtifact, verifySignedArtifact, type SignedArtifact, type SignedArtifactEnvelope } from "../security/signing";

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
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:read:${user.email.toLowerCase()}`, 120, 60);
  await expireStalePlans(db, workspaceId);
  const result = await db
    .prepare(`SELECT id, attack_path_id, name, mode, status, findings, requested_by, approved_by,
      authorization_digest, plan_signature, expires_at, decision_reason, created_at
      FROM validation_runs WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100`)
    .bind(workspaceId)
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
): Promise<{ run: ValidationRun; receipt: SignedArtifact & { payload: unknown; algorithm: "PS256"; keyId: string; authorizationDigest: string; executable: false } }> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:plan:${user.email.toLowerCase()}`, 10, 60);

  const path = await findAttackPath(db, workspaceId, input.attackPathId);
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
    workspaceId: workspaceId,
    attackPathId: path.id,
    mode: input.mode,
    status,
    requester: user.email.toLowerCase(),
    createdAt,
    expiresAt: new Date(Date.now() + policy.maxSessionMinutes * 60_000).toISOString(),
    constraints: policy,
    executable: false,
  } as const;
  const signedPlan = await signArtifact(plan, {
    domain: "cloudpen.plan.v2",
    workspaceId,
    audience: "cloudpen-runner.v1",
    expiresAt: plan.expiresAt,
  });
  await ensureSigningKey(db, signedPlan, workspaceId, user.email);
  const authorizationDigest = signedPlan.envelope.payloadDigest;
  const planSignature = signedPlan.signature;

  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO validation_runs
      (id, workspace_id, attack_path_id, name, mode, status, requested_by, authorization_digest, plan_signature,
       plan_payload_json, plan_envelope_json, plan_key_id, plan_algorithm, expires_at, findings, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`)
    .bind(id, workspaceId, path.id, `${path.id} · ${path.title}`, input.mode, status, user.email, authorizationDigest,
      planSignature, canonicalJson(plan), canonicalJson(signedPlan.envelope), signedPlan.envelope.keyId, signedPlan.envelope.algorithm,
      plan.expiresAt, createdAt, createdAt),
  user.email, "validation.plan.created", id, {
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
      ...signedPlan,
      payload: plan,
      algorithm: signedPlan.envelope.algorithm,
      keyId: signedPlan.envelope.keyId,
      authorizationDigest,
      executable: false,
    },
  };
}

export async function getGuardrailPolicy(user: AuthorizedUser): Promise<GuardrailPolicy> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:policy-read:${user.email.toLowerCase()}`, 120, 60);
  const row = await db.prepare(`SELECT require_approval, canary_only, redact_evidence, cleanup_required,
      max_concurrency, max_session_minutes FROM guardrail_policies WHERE workspace_id = ?`)
    .bind(workspaceId)
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
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:configure:${user.email.toLowerCase()}`, 20, 60);
  const current = await getGuardrailPolicy(user);
  const next = { ...current, ...patch };
  if (!next.requireApproval || !next.canaryOnly || !next.redactEvidence || !next.cleanupRequired) {
    throw new ValidationError("Core production safety controls cannot be disabled in this release.");
  }
  await runAuditedMutation(db, workspaceId, () => db.prepare(`UPDATE guardrail_policies SET require_approval = ?, canary_only = ?, redact_evidence = ?,
      cleanup_required = ?, updated_by = ?, updated_at = ? WHERE workspace_id = ?`)
    .bind(next.requireApproval ? 1 : 0, next.canaryOnly ? 1 : 0, next.redactEvidence ? 1 : 0,
      next.cleanupRequired ? 1 : 0, user.email, new Date().toISOString(), workspaceId),
  user.email, "guardrail.policy.updated", workspaceId, next);
  return next;
}

export async function createEvidencePackage(user: AuthorizedUser, attackPathId: string) {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:evidence:${user.email.toLowerCase()}`, 20, 60);
  const path = await findAttackPath(db, workspaceId, attackPathId);
  if (!path) throw new ValidationError("Unknown attack path.");
  const issuedAt = new Date().toISOString();
  const sanitized = sanitizeAttackPathEvidence(path);
  const payload = {
    schema: "cloudpen.evidence.v1",
    classification: "CONFIDENTIAL — AUTHORIZED SECURITY VALIDATION",
    workspaceId: workspaceId,
    issuedAt,
    issuedTo: user.email,
    evidence: sanitized.evidence,
    redaction: sanitized.redaction,
  };
  const signed = await signArtifact(payload, {
    domain: "cloudpen.evidence.v2",
    workspaceId,
    audience: "cloudpen-evidence-verifier.v1",
    expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
  });
  await ensureSigningKey(db, signed, workspaceId, user.email);
  const digest = signed.envelope.payloadDigest;
  const signature = signed.signature;
  const packageId = `EV-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO evidence_packages
      (id, workspace_id, path_id, classification, digest, signature, key_id, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(packageId, workspaceId, path.id, payload.classification, digest, signature, signed.envelope.keyId, user.email, issuedAt),
  user.email, "evidence.exported", path.id, { digest });
  return { packageId, payload, integrity: {
    ...signed,
    algorithm: signed.envelope.algorithm,
    keyId: signed.envelope.keyId,
    digest,
  } };
}

export async function recordConnectorRequest(
  user: AuthorizedUser,
  input: { name: string; accountId: string; externalId: string },
) {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:connect:${user.email.toLowerCase()}`, 5, 300);
  const existing = await db.prepare("SELECT id FROM connectors WHERE workspace_id = ? AND account_id = ?")
    .bind(workspaceId, input.accountId).first<{ id: string }>();
  if (existing) throw new ConflictError("This AWS account already has a connector in the workspace.");
  const id = `CON-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const externalIdPayload = input.externalId.startsWith("cpv1_") ? input.externalId.slice(5) : "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(externalIdPayload) || new Set(externalIdPayload).size < 12) {
    throw new ValidationError("Use a CloudPen-generated 256-bit External ID.");
  }
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO connectors
      (id, workspace_id, provider, name, account_id, status, external_id_status, created_by, created_at, updated_at)
      VALUES (?, ?, 'AWS', ?, ?, 'Runner required', 'not-retained', ?, ?, ?)`)
    .bind(id, workspaceId, input.name, input.accountId, user.email, createdAt, createdAt),
  user.email, "connector.requested", id, {
    name: input.name,
    accountId: input.accountId,
    externalIdStatus: "not-retained",
    status: "awaiting-runner-provisioning",
  });
  return { id, status: "Runner required" as const };
}

export async function getExposureCatalog(user: AuthorizedUser): Promise<ExposureCatalog> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:catalog-read:${user.email.toLowerCase()}`, 120, 60);
  const snapshot = await db.prepare(`SELECT id, source, status, collected_at FROM exposure_snapshots
    WHERE workspace_id = ? ORDER BY collected_at DESC LIMIT 1`).bind(workspaceId)
    .first<{ id: string; source: ExposureCatalog["snapshot"]["source"]; status: ExposureCatalog["snapshot"]["status"]; collected_at: string }>();
  if (!snapshot) throw new Error("Exposure snapshot is unavailable.");
  const [accountRows, assetRows, pathRows] = await Promise.all([
    db.prepare("SELECT data_json FROM cloud_accounts WHERE workspace_id = ? AND snapshot_id = ? ORDER BY id")
      .bind(workspaceId, snapshot.id).all<{ data_json: string }>(),
    db.prepare("SELECT data_json FROM cloud_assets WHERE workspace_id = ? AND snapshot_id = ? ORDER BY id")
      .bind(workspaceId, snapshot.id).all<{ data_json: string }>(),
    db.prepare("SELECT data_json FROM exposure_paths WHERE workspace_id = ? AND snapshot_id = ? ORDER BY id DESC")
      .bind(workspaceId, snapshot.id).all<{ data_json: string }>(),
  ]);
  return {
    accounts: accountRows.results.map((row) => JSON.parse(row.data_json)),
    assets: assetRows.results.map((row) => JSON.parse(row.data_json)),
    attackPaths: pathRows.results.map((row) => JSON.parse(row.data_json)),
    snapshot: { id: snapshot.id, source: snapshot.source, status: snapshot.status, collectedAt: snapshot.collected_at },
  };
}

export async function rotateConnectorExternalId(user: AuthorizedUser, connectorId: string, externalId: string): Promise<void> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:connector-rotate:${user.email.toLowerCase()}`, 5, 300);
  const payload = externalId.startsWith("cpv1_") ? externalId.slice(5) : "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(payload) || new Set(payload).size < 12) {
    throw new ValidationError("Use a CloudPen-generated 256-bit External ID.");
  }
  const result = await runAuditedMutation(db, workspaceId, () => db.prepare(`UPDATE connectors
      SET status = 'Runner required', external_id_status = 'not-retained', updated_at = ?
      WHERE id = ? AND workspace_id = ? AND status != 'Disabled'`)
    .bind(new Date().toISOString(), connectorId, workspaceId),
  user.email, "connector.external-id.rotated", connectorId, {
    externalIdStatus: "not-retained",
    customerTrustUpdateRequired: true,
  });
  if (!result.meta.changes) throw new NotFoundError("Active connector not found.");
}

export async function getControlPlaneSnapshot(user: AuthorizedUser): Promise<ControlPlaneSnapshot> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:snapshot-read:${user.email.toLowerCase()}`, 60, 60);
  const [workspace, runs, connectorRows, evidenceRows, remediationRows, auditRows, runnerRows] = await Promise.all([
    db.prepare("SELECT name, data_mode FROM workspaces WHERE id = ?")
      .bind(workspaceId).first<{ name: string; data_mode: "demo" | "live" }>(),
    listValidationRuns(user),
    db.prepare(`SELECT id, name, account_id, provider, status, external_id_status, created_by,
      created_at, last_sync_at, error_message FROM connectors WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100`)
      .bind(workspaceId).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, path_id, classification, digest, key_id, created_by, created_at
      FROM evidence_packages WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100`)
      .bind(workspaceId).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, path_id, title, status, priority, owner, due_at, guidance, created_at, updated_at,
      version, transition_reason, risk_accepted_by, risk_acceptance_reason, risk_acceptance_expires_at, revalidation_evidence_id
      FROM remediations WHERE workspace_id = ? ORDER BY updated_at DESC LIMIT 100`)
      .bind(workspaceId).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, actor_email, action, target, previous_hash, event_hash, created_at
      FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT 200`)
      .bind(workspaceId).all<Record<string, unknown>>(),
    db.prepare(`SELECT id, name, status, public_key_fingerprint, executable, created_by, created_at
      FROM runner_enrollments WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 20`)
      .bind(workspaceId).all<Record<string, unknown>>(),
  ]);
  const connectors: ConnectorRecord[] = connectorRows.results.map((row) => ({
    id: String(row.id), name: String(row.name), accountId: String(row.account_id), provider: "AWS",
    status: row.status as ConnectorRecord["status"], externalIdStatus: "not-retained",
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
    version: Number(row.version), transitionReason: row.transition_reason ? String(row.transition_reason) : null,
    riskAcceptedBy: row.risk_accepted_by ? String(row.risk_accepted_by) : null,
    riskAcceptanceReason: row.risk_acceptance_reason ? String(row.risk_acceptance_reason) : null,
    riskAcceptanceExpiresAt: row.risk_acceptance_expires_at ? String(row.risk_acceptance_expires_at) : null,
    revalidationEvidenceId: row.revalidation_evidence_id ? String(row.revalidation_evidence_id) : null,
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
    workspace: { id: workspaceId, name: workspace.name, dataMode: workspace.data_mode, role: user.role },
    runs, connectors, evidence, remediations, audit, runners, auditChainValid: await verifyAuditChain(db, workspaceId),
  };
}

export async function createRunnerEnrollment(
  user: AuthorizedUser,
  input: { name: string; publicKeyFingerprint: string },
): Promise<RunnerRecord> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:runner-enroll:${user.email.toLowerCase()}`, 3, 300);
  const now = new Date().toISOString();
  const record: RunnerRecord = {
    id: `RNR-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    name: input.name, status: "Pending", publicKeyFingerprint: input.publicKeyFingerprint,
    executable: false, createdBy: user.email, createdAt: now,
  };
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO runner_enrollments
      (id, workspace_id, name, status, public_key_fingerprint, executable, created_by, created_at)
      VALUES (?, ?, ?, 'Pending', ?, 0, ?, ?)`)
    .bind(record.id, workspaceId, record.name, record.publicKeyFingerprint, user.email, now),
  user.email, "runner.enrollment.requested", record.id, {
    publicKeyFingerprint: record.publicKeyFingerprint, status: record.status, executable: false,
  });
  return record;
}

export async function createAssessmentReport(user: AuthorizedUser) {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:report:${user.email.toLowerCase()}`, 10, 60);
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
  const signed = await signArtifact(payload, {
    domain: "cloudpen.assessment.v2",
    workspaceId,
    audience: "cloudpen-assessment-verifier.v1",
    expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
  });
  await ensureSigningKey(db, signed, workspaceId, user.email);
  const integrity = {
    ...signed,
    algorithm: signed.envelope.algorithm,
    keyId: signed.envelope.keyId,
    digest: signed.envelope.payloadDigest,
  };
  await appendAuditEvent(db, workspaceId, user.email, "assessment.report.exported", workspaceId, { digest: integrity.digest });
  return { payload, integrity };
}

export async function decideValidationRun(
  user: AuthorizedUser,
  runId: string,
  decision: "approve" | "reject" | "cancel",
  reason: string,
): Promise<{ approvalId: string; decision: "approve" | "reject" | "cancel"; payload: unknown; integrity: SignedArtifact; executable: false }> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:decision:${user.email.toLowerCase()}`, 30, 60);
  await expireStalePlans(db, workspaceId);
  const row = await db.prepare(`SELECT status, requested_by, expires_at, version, authorization_digest,
      plan_payload_json, plan_envelope_json, plan_signature, plan_key_id FROM validation_runs
    WHERE id = ? AND workspace_id = ?`).bind(runId, workspaceId)
    .first<{ status: string; requested_by: string; expires_at: string; version: number; authorization_digest: string;
      plan_payload_json: string | null; plan_envelope_json: string | null; plan_signature: string; plan_key_id: string | null }>();
  if (!row) throw new NotFoundError("Validation run not found.");
  if (!row.plan_payload_json || !row.plan_envelope_json || !row.plan_key_id) {
    throw new ConflictError("Legacy plans without a complete signed envelope cannot receive production decisions.");
  }
  await verifyStoredPlan(db, workspaceId, row);
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
  const approvalId = `APV-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const approvalPayload = {
    schema: "cloudpen.approval-decision.v2",
    approvalId,
    planId: runId,
    planDigest: row.authorization_digest,
    decision,
    finalStatus: status,
    workspaceId,
    requester: row.requested_by.toLowerCase(),
    approver: user.email.toLowerCase(),
    reason,
    runnerId: null,
    executable: false,
  } as const;
  const signedApproval = await signArtifact(approvalPayload, {
    domain: "cloudpen.approval.v2",
    workspaceId,
    audience: "cloudpen-runner.v1",
    issuedAt: now,
    expiresAt: row.expires_at,
  });
  await ensureSigningKey(db, signedApproval, workspaceId, user.email);
  const allowedStatuses = decision === "cancel" ? ["Planned", "Awaiting approval", "Approved"] : ["Awaiting approval"];
  const placeholders = allowedStatuses.map(() => "?").join(", ");
  const result = await runAuditedMutation(db, workspaceId, () => [
    db.prepare(`UPDATE validation_runs
      SET status = ?, approved_by = ?, decision_reason = ?, approval_id = ?, version = version + 1, updated_at = ?
      WHERE id = ? AND workspace_id = ? AND status IN (${placeholders}) AND version = ? AND expires_at > ?`)
      .bind(status, decision === "cancel" ? null : user.email, reason, approvalId, now, runId, workspaceId, ...allowedStatuses, row.version, now),
    db.prepare(`INSERT INTO approval_envelopes
      (id, workspace_id, run_id, plan_digest, decision, payload_json, envelope_json, signature, key_id, nonce, created_by, created_at)
      SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1`)
      .bind(approvalId, workspaceId, runId, row.authorization_digest, decision, canonicalJson(approvalPayload),
        canonicalJson(signedApproval.envelope), signedApproval.signature, signedApproval.envelope.keyId,
        signedApproval.envelope.nonce, user.email, now),
  ], user.email, `validation.plan.${decision}d`, runId, {
    approvalId,
    planDigest: row.authorization_digest,
    status,
    reason,
    decisionNonce: signedApproval.envelope.nonce,
    executable: false,
  });
  if (!result.meta.changes) throw new ConflictError("The plan changed or expired before this decision was committed.");
  return { approvalId, decision, payload: approvalPayload, integrity: signedApproval, executable: false };
}

export async function createRemediation(
  user: AuthorizedUser,
  input: { pathId: string; owner: string; dueAt: string },
): Promise<RemediationRecord> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:remediation-create:${user.email.toLowerCase()}`, 20, 60);
  const path = await findAttackPath(db, workspaceId, input.pathId);
  if (!path) throw new ValidationError("Unknown attack path.");
  const existing = await db.prepare("SELECT id FROM remediations WHERE workspace_id = ? AND path_id = ? AND status != 'Closed'")
    .bind(workspaceId, path.id).first<{ id: string }>();
  if (existing) throw new ConflictError("An open remediation already exists for this path.");
  const now = new Date().toISOString();
  const record: RemediationRecord = {
    id: `REM-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    pathId: path.id, title: `Restrict access for ${path.title}`, status: "Open", priority: path.severity,
    owner: input.owner, dueAt: input.dueAt, guidance: path.remediation, createdAt: now, updatedAt: now,
    version: 1, transitionReason: null, riskAcceptedBy: null, riskAcceptanceReason: null,
    riskAcceptanceExpiresAt: null, revalidationEvidenceId: null,
  };
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO remediations
      (id, workspace_id, path_id, title, status, priority, owner, due_at, guidance, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(record.id, workspaceId, record.pathId, record.title, record.status, record.priority, record.owner,
      record.dueAt, record.guidance, user.email, now, now),
  user.email, "remediation.created", record.id, { pathId: path.id, owner: input.owner, dueAt: input.dueAt });
  return record;
}

export async function updateRemediation(
  user: AuthorizedUser,
  id: string,
  input: {
    status: RemediationRecord["status"];
    version: number;
    reason: string;
    riskAcceptanceExpiresAt: string | null;
    revalidationEvidenceId: string | null;
  },
): Promise<void> {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:remediation-update:${user.email.toLowerCase()}`, 60, 60);
  if (input.reason.trim().length < 8 || input.reason.trim().length > 500) {
    throw new ValidationError("A decision reason between 8 and 500 characters is required.");
  }
  if (input.status === "Risk accepted" && user.role !== "admin") {
    throw new AuthorizationError(403, "Only administrators may accept remediation risk.");
  }
  if (input.status === "Closed" && user.role !== "admin" && user.role !== "reviewer") {
    throw new AuthorizationError(403, "Only administrators or reviewers may close a remediation.");
  }
  if (input.status !== "Risk accepted" && input.status !== "Closed" && user.role !== "admin" && user.role !== "operator") {
    throw new AuthorizationError(403, "Only administrators or operators may update remediation progress.");
  }
  const current = await db.prepare("SELECT status, version, path_id FROM remediations WHERE id = ? AND workspace_id = ?")
    .bind(id, workspaceId).first<{ status: RemediationRecord["status"]; version: number; path_id: string }>();
  if (!current) throw new NotFoundError("Remediation not found.");
  if (current.version !== input.version) throw new ConflictError("The remediation has changed. Refresh it before retrying.");
  const transitions: Record<RemediationRecord["status"], ReadonlySet<RemediationRecord["status"]>> = {
    Open: new Set(["In progress", "Risk accepted"]),
    "In progress": new Set(["Risk accepted", "Ready to revalidate"]),
    "Risk accepted": new Set(["In progress"]),
    "Ready to revalidate": new Set(["In progress", "Closed"]),
    Closed: new Set(),
  };
  if (!transitions[current.status].has(input.status)) {
    throw new ConflictError(`A remediation cannot move from ${current.status} to ${input.status}.`);
  }
  const now = new Date().toISOString();
  let riskExpiry: string | null = null;
  let evidenceId: string | null = null;
  if (input.status === "Risk accepted") {
    const expiry = input.riskAcceptanceExpiresAt ? new Date(input.riskAcceptanceExpiresAt) : null;
    if (!expiry || Number.isNaN(expiry.valueOf()) || expiry <= new Date() || expiry.valueOf() > Date.now() + 365 * 86_400_000) {
      throw new ValidationError("Risk acceptance requires an expiry within the next 365 days.");
    }
    riskExpiry = expiry.toISOString();
  }
  if (input.status === "Closed") {
    evidenceId = input.revalidationEvidenceId;
    const evidence = evidenceId ? await db.prepare(`SELECT id FROM evidence_packages
      WHERE id = ? AND workspace_id = ? AND path_id = ?`).bind(evidenceId, workspaceId, current.path_id).first<{ id: string }>() : null;
    if (!evidence) throw new ConflictError("Closure requires retained revalidation evidence for this attack path.");
  }
  const details = {
    from: current.status,
    to: input.status,
    reason: input.reason,
    previousVersion: current.version,
    nextVersion: current.version + 1,
    riskAcceptedBy: input.status === "Risk accepted" ? user.email : null,
    riskAcceptanceExpiresAt: riskExpiry,
    revalidationEvidenceId: evidenceId,
  };
  let result: D1Result;
  try {
    result = await runAuditedMutation(db, workspaceId, () => db.prepare(`UPDATE remediations SET
        status = ?, updated_at = ?, version = version + 1, transition_reason = ?,
        risk_accepted_by = ?, risk_acceptance_reason = ?, risk_acceptance_expires_at = ?, revalidation_evidence_id = ?
        WHERE id = ? AND workspace_id = ? AND status = ? AND version = ?`)
      .bind(input.status, now, input.reason,
        input.status === "Risk accepted" ? user.email : null,
        input.status === "Risk accepted" ? input.reason : null,
        riskExpiry, evidenceId, id, workspaceId, current.status, current.version),
    user.email, "remediation.status.updated", id, details);
  } catch (error) {
    // The batch sentinel deliberately rejects a no-op optimistic update so the
    // audit insert is rolled back with it. Surface that expected race as a
    // client conflict instead of leaking the database constraint as a 500.
    if (isAtomicMutationRejected(error)) {
      throw new ConflictError("The remediation changed before this transition was committed.");
    }
    throw error;
  }
  if (!result.meta.changes) throw new ConflictError("The remediation changed before this transition was committed.");
}

export async function createDiscoveryPlan(user: AuthorizedUser, connectorId: string) {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:discovery:${user.email.toLowerCase()}`, 10, 60);
  const connector = await db.prepare("SELECT id, account_id, status FROM connectors WHERE id = ? AND workspace_id = ?")
    .bind(connectorId, workspaceId).first<{ id: string; account_id: string; status: string }>();
  if (!connector || connector.status === "Disabled") throw new NotFoundError("Active connector not found.");
  const id = `DISC-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const scope = { provider: "AWS", accountId: connector.account_id, mode: "metadata-read-only", services: ["iam", "organizations", "s3", "lambda", "kms", "ec2", "ecr", "ecs"], executable: false };
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO discovery_jobs
      (id, workspace_id, connector_id, status, scope_json, executable, created_by, created_at)
      VALUES (?, ?, ?, 'Runner required', ?, 0, ?, ?)`)
    .bind(id, workspaceId, connectorId, canonicalJson(scope), user.email, new Date().toISOString()),
  user.email, "discovery.plan.created", id, scope);
  return { id, status: "Runner required", scope };
}

export async function exportGuardrailPolicy(user: AuthorizedUser) {
  const { workspaceId } = user;
  const policy = await getGuardrailPolicy(user);
  const payload = { schema: "cloudpen.guardrails.v1", workspaceId: workspaceId, policy, issuedAt: new Date().toISOString(), executable: false };
  const signed = await signArtifact(payload, {
    domain: "cloudpen.guardrails.v2",
    workspaceId,
    audience: "cloudpen-runner.v1",
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  });
  await ensureSigningKey(database(), signed, workspaceId, user.email);
  await appendAuditEvent(database(), workspaceId, user.email, "guardrail.policy.exported", workspaceId, {
    digest: signed.envelope.payloadDigest,
  });
  return { payload, integrity: {
    ...signed,
    algorithm: signed.envelope.algorithm,
    keyId: signed.envelope.keyId,
    digest: signed.envelope.payloadDigest,
  } };
}

export async function createAuditAnchor(user: AuthorizedUser) {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:audit-anchor:${user.email.toLowerCase()}`, 3, 300);
  if (!(await verifyAuditChain(db, workspaceId))) throw new ConflictError("The audit chain is invalid and cannot be anchored.");
  const head = await auditChainHead(db, workspaceId);
  const previous = await db.prepare(`SELECT envelope_json FROM audit_anchors
      WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 1`)
    .bind(workspaceId).first<{ envelope_json: string }>();
  let previousAnchorDigest: string | null = null;
  if (previous) {
    try { previousAnchorDigest = (JSON.parse(previous.envelope_json) as SignedArtifactEnvelope).payloadDigest; } catch {
      throw new ConflictError("The previous audit anchor is malformed.");
    }
  }
  const now = new Date().toISOString();
  const payload = {
    schema: "cloudpen.audit-anchor.v2",
    workspaceId,
    chainHead: head.chainHead,
    eventCount: head.eventCount,
    previousAnchorDigest,
    anchoredAt: now,
  } as const;
  const signed = await signArtifact(payload, {
    domain: "cloudpen.audit-anchor.v2",
    workspaceId,
    audience: "cloudpen-audit-verifier.v1",
    issuedAt: now,
    expiresAt: new Date(Date.now() + 3_650 * 86_400_000).toISOString(),
  });
  await ensureSigningKey(db, signed, workspaceId, user.email);
  const id = `ANC-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO audit_anchors
      (id, workspace_id, chain_head, event_count, payload_json, envelope_json, signature, key_id, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, workspaceId, head.chainHead, head.eventCount, canonicalJson(payload), canonicalJson(signed.envelope),
      signed.signature, signed.envelope.keyId, user.email, now),
  user.email, "audit.anchor.created", id, {
    chainHead: head.chainHead,
    eventCount: head.eventCount,
    anchorDigest: signed.envelope.payloadDigest,
  });
  return { id, payload, integrity: signed };
}

export async function createWorkspaceBackup(user: AuthorizedUser) {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:backup:${user.email.toLowerCase()}`, 2, 600);
  if (!(await verifyAuditChain(db, workspaceId))) throw new ConflictError("The audit chain is invalid; backup export is blocked.");
  const workspaceTables = [
    "memberships", "guardrail_policies", "validation_runs", "approval_envelopes", "consumed_artifact_nonces",
    "connectors", "evidence_packages", "remediations", "discovery_jobs", "runner_enrollments", "exposure_snapshots",
    "cloud_accounts", "cloud_assets", "exposure_paths", "graph_edges", "audit_events", "audit_anchors", "legal_holds",
  ] as const;
  const tables: Record<string, Record<string, unknown>[]> = {};
  tables.workspaces = await backupRows(db, "workspaces", "id", workspaceId);
  for (const table of workspaceTables) tables[table] = await backupRows(db, table, "workspace_id", workspaceId);
  const referencedKeyIds = new Set<string>();
  for (const table of ["validation_runs", "approval_envelopes", "evidence_packages", "audit_anchors"]) {
    for (const row of tables[table]) {
      const keyId = row.plan_key_id ?? row.key_id;
      if (typeof keyId === "string") referencedKeyIds.add(keyId);
    }
  }
  tables.signing_keys = [];
  for (const keyId of [...referencedKeyIds].sort()) {
    const key = await db.prepare(`SELECT key_id, algorithm, public_jwk, status, not_before, not_after, created_at
        FROM signing_keys WHERE key_id = ?`).bind(keyId).first<Record<string, unknown>>();
    if (key) tables.signing_keys.push(key);
  }
  const createdAt = new Date().toISOString();
  const archive = { format: "cloudpen.workspace-backup.v1", workspaceId, createdAt, tables };
  const archiveJson = canonicalJson(archive);
  if (new TextEncoder().encode(archiveJson).byteLength > 4_000_000) {
    throw new ConflictError("The logical backup exceeds the 4 MB application export limit; use a platform D1 backup.");
  }
  const manifest = {
    schema: "cloudpen.backup-manifest.v2",
    workspaceId,
    createdAt,
    archiveDigest: await sha256Base64Url(archiveJson),
    rowCounts: Object.fromEntries(Object.entries(tables).map(([name, rows]) => [name, rows.length])),
    containsSecrets: false,
    encryptedByApplication: false,
  };
  const signed = await signArtifact(manifest, {
    domain: "cloudpen.backup-manifest.v2",
    workspaceId,
    audience: "cloudpen-backup-verifier.v1",
    issuedAt: createdAt,
    expiresAt: new Date(Date.now() + 3_650 * 86_400_000).toISOString(),
  });
  await ensureSigningKey(db, signed, workspaceId, user.email);
  await appendAuditEvent(db, workspaceId, user.email, "workspace.backup.exported", workspaceId, {
    archiveDigest: manifest.archiveDigest,
    rowCounts: manifest.rowCounts,
  });
  return { archive, manifest, integrity: signed };
}

export async function getLifecycleStatus(user: AuthorizedUser) {
  const db = database();
  const { workspaceId } = user;
  const now = Math.floor(Date.now() / 1000);
  const [holds, expiredRateLimits, pendingTelemetry, deliveredTelemetry, latestAnchor] = await Promise.all([
    db.prepare("SELECT COUNT(*) AS count FROM legal_holds WHERE workspace_id = ? AND active = 1").bind(workspaceId).first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) AS count FROM rate_limits WHERE key LIKE ? AND expires_at <= ?").bind(`${workspaceId}:%`, now).first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) AS count FROM security_event_outbox WHERE delivered_at IS NULL").first<{ count: number }>(),
    db.prepare("SELECT COUNT(*) AS count FROM security_event_outbox WHERE delivered_at IS NOT NULL").first<{ count: number }>(),
    db.prepare("SELECT id, chain_head, event_count, created_at FROM audit_anchors WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 1")
      .bind(workspaceId).first<Record<string, unknown>>(),
  ]);
  return {
    workspaceId,
    legalHoldActive: Number(holds?.count ?? 0) > 0,
    retention: {
      rateLimits: "expired operational counters are purged",
      deliveredTelemetry: "7 days after confirmed SIEM delivery",
      undeliveredTelemetry: "retained until delivery or incident disposition",
      auditEvents: "7 years; deletion requires a verified external anchor and approved archive procedure",
      plansApprovalsEvidence: "1 year by default; customer deletion requires a verified backup and legal-hold check",
    },
    eligible: { expiredRateLimits: Number(expiredRateLimits?.count ?? 0), deliveredTelemetry: Number(deliveredTelemetry?.count ?? 0) },
    pendingTelemetry: Number(pendingTelemetry?.count ?? 0),
    latestAnchor: latestAnchor ?? null,
  };
}

export async function runLifecycleMaintenance(user: AuthorizedUser) {
  const db = database();
  const { workspaceId } = user;
  await enforceRateLimit(db, `${workspaceId}:lifecycle:${user.email.toLowerCase()}`, 3, 600);
  const hold = await db.prepare("SELECT id FROM legal_holds WHERE workspace_id = ? AND active = 1 LIMIT 1")
    .bind(workspaceId).first<{ id: string }>();
  const now = Math.floor(Date.now() / 1000);
  const expired = await db.prepare("SELECT COUNT(*) AS count FROM rate_limits WHERE key LIKE ? AND expires_at <= ?")
    .bind(`${workspaceId}:%`, now).first<{ count: number }>();
  let expiredRateLimits = 0;
  if (Number(expired?.count ?? 0) > 0) {
    const result = await runAuditedMutation(db, workspaceId, () => db.prepare("DELETE FROM rate_limits WHERE key LIKE ? AND expires_at <= ?")
      .bind(`${workspaceId}:%`, now), user.email, "retention.rate_limits.purged", workspaceId, {
        cutoffEpoch: now,
        eligibleRows: Number(expired?.count ?? 0),
      }, "one-or-more");
    expiredRateLimits = Number(result.meta.changes ?? 0);
  }
  let deliveredTelemetry = 0;
  if (!hold) {
    const cutoff = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const eligible = await db.prepare("SELECT COUNT(*) AS count FROM security_event_outbox WHERE delivered_at IS NOT NULL AND delivered_at < ?")
      .bind(cutoff).first<{ count: number }>();
    if (Number(eligible?.count ?? 0) > 0) {
      const result = await runAuditedMutation(db, workspaceId, () => db.prepare(`DELETE FROM security_event_outbox
          WHERE delivered_at IS NOT NULL AND delivered_at < ?`).bind(cutoff),
      user.email, "retention.telemetry.purged", workspaceId, {
        cutoff,
        eligibleRows: Number(eligible?.count ?? 0),
      }, "one-or-more");
      deliveredTelemetry = Number(result.meta.changes ?? 0);
    }
  }
  return { expiredRateLimits, deliveredTelemetry, legalHoldBlockedTelemetryPurge: Boolean(hold) };
}

export async function createLegalHold(user: AuthorizedUser, reason: string) {
  if (reason.trim().length < 10 || reason.trim().length > 500) throw new ValidationError("A legal-hold reason between 10 and 500 characters is required.");
  const db = database();
  const { workspaceId } = user;
  const id = `HLD-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const now = new Date().toISOString();
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO legal_holds
      (id, workspace_id, reason, active, created_by, created_at) VALUES (?, ?, ?, 1, ?, ?)`)
    .bind(id, workspaceId, reason.trim(), user.email, now), user.email, "legal_hold.created", id, { reason: reason.trim() });
  return { id, active: true, reason: reason.trim(), createdAt: now };
}

export async function releaseLegalHold(user: AuthorizedUser, id: string, reason: string) {
  if (!/^HLD-[A-Z0-9]{8}$/.test(id) || reason.trim().length < 10 || reason.trim().length > 500) {
    throw new ValidationError("A valid hold ID and release reason between 10 and 500 characters are required.");
  }
  const db = database();
  const { workspaceId } = user;
  const now = new Date().toISOString();
  const result = await runAuditedMutation(db, workspaceId, () => db.prepare(`UPDATE legal_holds
      SET active = 0, released_by = ?, released_at = ? WHERE id = ? AND workspace_id = ? AND active = 1`)
    .bind(user.email, now, id, workspaceId), user.email, "legal_hold.released", id, { reason: reason.trim() });
  if (!result.meta.changes) throw new NotFoundError("Active legal hold not found.");
  return { id, active: false, releasedAt: now };
}

async function auditChainHead(db: D1Database, workspaceId: string): Promise<{ chainHead: string; eventCount: number }> {
  const [leaf, count] = await Promise.all([
    db.prepare(`SELECT parent.event_hash FROM audit_events parent WHERE parent.workspace_id = ? AND NOT EXISTS (
        SELECT 1 FROM audit_events child WHERE child.workspace_id = parent.workspace_id AND child.previous_hash = parent.event_hash
      ) LIMIT 1`).bind(workspaceId).first<{ event_hash: string }>(),
    db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE workspace_id = ?").bind(workspaceId).first<{ count: number }>(),
  ]);
  return { chainHead: leaf?.event_hash ?? "GENESIS", eventCount: Number(count?.count ?? 0) };
}

async function backupRows(db: D1Database, table: string, workspaceColumn: string, workspaceId: string): Promise<Record<string, unknown>[]> {
  const result = await db.prepare(`SELECT * FROM ${table} WHERE ${workspaceColumn} = ? ORDER BY rowid LIMIT 5001`)
    .bind(workspaceId).all<Record<string, unknown>>();
  if (result.results.length > 5_000) throw new ConflictError(`The ${table} table exceeds the application backup row limit.`);
  return result.results;
}

async function ensureSigningKey(
  db: D1Database,
  artifact: SignedArtifact,
  workspaceId: string,
  actorEmail: string,
): Promise<void> {
  const publicJwk = canonicalJson(artifact.publicKeyJwk);
  const existing = await db.prepare("SELECT public_jwk, algorithm, status FROM signing_keys WHERE key_id = ?")
    .bind(artifact.envelope.keyId)
    .first<{ public_jwk: string; algorithm: string; status: "active" | "retired" | "revoked" }>();
  if (existing) {
    if (existing.public_jwk !== publicJwk || existing.algorithm !== artifact.envelope.algorithm) {
      throw new Error("The signing key ID is already bound to different public key material.");
    }
    if (existing.status !== "active") throw new Error(`Signing key ${artifact.envelope.keyId} is ${existing.status}.`);
    return;
  }
  await runAuditedMutation(db, workspaceId, () => db.prepare(`INSERT INTO signing_keys
        (key_id, algorithm, public_jwk, status, not_before, not_after, created_at)
        VALUES (?, 'PS256', ?, 'active', ?, NULL, ?)`)
      .bind(artifact.envelope.keyId, publicJwk, artifact.envelope.issuedAt, new Date().toISOString()),
  actorEmail, "signing_key.observed", artifact.envelope.keyId, {
    algorithm: artifact.envelope.algorithm,
    notBefore: artifact.envelope.issuedAt,
  });
}

async function verifyStoredPlan(
  db: D1Database,
  workspaceId: string,
  row: {
    authorization_digest: string;
    plan_payload_json: string | null;
    plan_envelope_json: string | null;
    plan_signature: string;
    plan_key_id: string | null;
  },
): Promise<void> {
  let payload: unknown;
  let envelope: SignedArtifactEnvelope;
  try {
    payload = JSON.parse(row.plan_payload_json!);
    envelope = JSON.parse(row.plan_envelope_json!) as SignedArtifactEnvelope;
  } catch {
    throw new ConflictError("The stored plan integrity data is malformed.");
  }
  if (envelope.payloadDigest !== row.authorization_digest || envelope.keyId !== row.plan_key_id) {
    throw new ConflictError("The stored plan integrity metadata is inconsistent.");
  }
  const key = await db.prepare(`SELECT public_jwk, status, not_before, not_after FROM signing_keys WHERE key_id = ?`)
    .bind(envelope.keyId)
    .first<{ public_jwk: string; status: "active" | "retired" | "revoked"; not_before: string; not_after: string | null }>();
  if (!key || key.status === "revoked") throw new ConflictError("The plan signing key is unavailable or revoked.");
  if (key.not_after && new Date(key.not_after).valueOf() <= Date.now()) throw new ConflictError("The plan signing key is no longer valid.");
  let publicKeyJwk: JsonWebKey;
  try { publicKeyJwk = JSON.parse(key.public_jwk) as JsonWebKey; } catch { throw new ConflictError("The plan verification key is malformed."); }
  const consumed = await db.prepare("SELECT nonce FROM consumed_artifact_nonces WHERE nonce = ? AND workspace_id = ?")
    .bind(envelope.nonce, workspaceId).first<{ nonce: string }>();
  const valid = await verifySignedArtifact(payload, { envelope, signature: row.plan_signature, publicKeyJwk }, {
    domain: "cloudpen.plan.v2",
    workspaceId,
    audience: "cloudpen-runner.v1",
    consumedNonces: consumed ? new Set([consumed.nonce]) : undefined,
  });
  if (!valid) throw new ConflictError("The stored plan signature or scope is invalid.");
}

async function findAttackPath(db: D1Database, workspaceId: string, pathId: string): Promise<AttackPath | null> {
  const row = await db.prepare("SELECT data_json FROM exposure_paths WHERE workspace_id = ? AND id = ?")
    .bind(workspaceId, `${workspaceId}:${pathId}`).first<{ data_json: string }>();
  return row ? JSON.parse(row.data_json) as AttackPath : null;
}

async function expireStalePlans(db: D1Database, workspaceId: string): Promise<void> {
  const now = new Date().toISOString();
  const stale = await db.prepare(`SELECT id, version FROM validation_runs
      WHERE workspace_id = ? AND status IN ('Planned', 'Awaiting approval', 'Approved') AND expires_at <= ?
      ORDER BY expires_at LIMIT 100`)
    .bind(workspaceId, now).all<{ id: string; version: number }>();
  let expired = 0;
  for (const row of stale.results) {
    try {
      const result = await runAuditedMutation(db, workspaceId, () => db.prepare(`UPDATE validation_runs
          SET status = 'Expired', version = version + 1, updated_at = ?
          WHERE id = ? AND workspace_id = ? AND version = ?
            AND status IN ('Planned', 'Awaiting approval', 'Approved') AND expires_at <= ?`)
        .bind(now, row.id, workspaceId, row.version, now), "system@cloudpen.invalid", "validation.plan.expired", row.id, {
        reason: "authorization_window_elapsed",
        previousVersion: row.version,
      });
      expired += Number(result.meta.changes ?? 0);
    } catch (error) {
      if (!/CHECK constraint failed: id/i.test(String(error))) throw error;
    }
  }
  if (expired) emitServiceSecurityEvent("automatic_plan_expiration", { count: expired });
}

async function verifyAuditChain(db: D1Database, workspaceId: string): Promise<boolean> {
  const rows: Record<string, unknown>[] = [];
  const pageSize = 500;
  for (let offset = 0; ; offset += pageSize) {
    const page = await db.prepare(`SELECT id, actor_email, action, target, details_json, previous_hash, event_hash, created_at
      FROM audit_events WHERE workspace_id = ? ORDER BY created_at, id LIMIT ? OFFSET ?`)
      .bind(workspaceId, pageSize, offset).all<Record<string, unknown>>();
    rows.push(...page.results);
    if (page.results.length < pageSize) break;
  }
  const byPrevious = new Map(rows.map((row) => [String(row.previous_hash), row]));
  let previousHash = "GENESIS";
  let visited = 0;
  while (byPrevious.has(previousHash)) {
    const row = byPrevious.get(previousHash)!;
    let details: unknown;
    try { details = JSON.parse(String(row.details_json)); } catch { return auditVerificationFailure("invalid_details_json"); }
    const event = {
      id: String(row.id), workspaceId: workspaceId, actorEmail: String(row.actor_email),
      action: String(row.action), target: String(row.target), details,
      previousHash: String(row.previous_hash), createdAt: String(row.created_at),
    };
    const expected = await sha256Base64Url(canonicalJson(event));
    if (expected !== String(row.event_hash)) return auditVerificationFailure("event_hash_mismatch");
    previousHash = String(row.event_hash);
    visited += 1;
  }
  return visited === rows.length || auditVerificationFailure("chain_length_mismatch");
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
  workspaceId: string,
  actorEmail: string,
  action: string,
  target: string,
  details: unknown,
): Promise<void> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const statement = await prepareAuditInsert(db, workspaceId, actorEmail, action, target, details, false);
    try {
      await statement.run();
      return;
    } catch (error) {
      if (!isAuditChainRace(error) || attempt === 3) throw error;
    }
  }
}

async function runAuditedMutation(
  db: D1Database,
  workspaceId: string,
  mutation: () => D1PreparedStatement | D1PreparedStatement[],
  actorEmail: string,
  action: string,
  target: string,
  details: unknown,
  changeRequirement: "exactly-one" | "one-or-more" = "exactly-one",
): Promise<D1Result> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const audit = await prepareAuditInsert(db, workspaceId, actorEmail, action, target, details, changeRequirement);
    const mutations = mutation();
    const statements = Array.isArray(mutations) ? mutations : [mutations];
    const atomicGuard = db.prepare("INSERT INTO atomic_guards (id) SELECT 2 WHERE changes() != 1");
    try {
      const [result] = await db.batch([...statements, audit, atomicGuard]);
      return result;
    } catch (error) {
      if (!isAuditChainRace(error) || attempt === 3) throw error;
    }
  }
  throw new Error("The audited mutation could not be committed.");
}

async function prepareAuditInsert(
  db: D1Database,
  workspaceId: string,
  actorEmail: string,
  action: string,
  target: string,
  details: unknown,
  changeRequirement: false | "exactly-one" | "one-or-more",
): Promise<D1PreparedStatement> {
  const previous = await db.prepare(`SELECT parent.event_hash FROM audit_events parent
      WHERE parent.workspace_id = ? AND NOT EXISTS (
        SELECT 1 FROM audit_events child WHERE child.workspace_id = parent.workspace_id AND child.previous_hash = parent.event_hash
      ) LIMIT 1`)
    .bind(workspaceId)
    .first<{ event_hash: string }>();
  const event = {
    id: crypto.randomUUID(),
    workspaceId: workspaceId,
    actorEmail: actorEmail.toLowerCase(),
    action,
    target,
    details,
    previousHash: previous?.event_hash ?? "GENESIS",
    createdAt: new Date().toISOString(),
  };
  const eventHash = await sha256Base64Url(canonicalJson(event));
  const predicate = changeRequirement === "exactly-one" ? " WHERE changes() = 1"
    : changeRequirement === "one-or-more" ? " WHERE changes() >= 1"
    : "";
  return db.prepare(`INSERT INTO audit_events
      (id, workspace_id, actor_email, action, target, details_json, previous_hash, event_hash, created_at)
      SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?${predicate}`)
    .bind(event.id, workspaceId, event.actorEmail, action, target, canonicalJson(details), event.previousHash, eventHash, event.createdAt);
}

function isAuditChainRace(error: unknown): boolean {
  return /UNIQUE constraint failed: audit_events\.workspace_id, audit_events\.previous_hash/i.test(String(error));
}

function isAtomicMutationRejected(error: unknown): boolean {
  return /CHECK constraint failed: id/i.test(String(error));
}

function database(): D1Database {
  const db = runtimeBindings().DB;
  if (!db) throw new Error("The durable control-plane database is unavailable.");
  return db;
}

function auditVerificationFailure(reason: string): false {
  emitServiceSecurityEvent("audit_verification_failed", { reason });
  return false;
}

function emitServiceSecurityEvent(category: string, fields: Record<string, string | number>): void {
  console.warn(JSON.stringify({
    schema: "cloudpen.security-event.v1",
    timestamp: new Date().toISOString(),
    requestId: null,
    category,
    outcome: "alert",
    ...fields,
  }));
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

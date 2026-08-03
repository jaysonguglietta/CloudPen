import "server-only";
import { attackPaths, type ValidationRun } from "../cloudpen-data";
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
  const result = await db
    .prepare(`SELECT id, name, mode, status, findings, requested_by, created_at
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
  }));
}

export async function createValidationPlan(
  user: AuthorizedUser,
  input: { attackPathId: string; mode: "Read-only" | "Active canary"; acknowledged: boolean },
): Promise<{ run: ValidationRun; receipt: { algorithm: string; keyId: string; authorizationDigest: string; signature: string; executable: false } }> {
  const db = database();
  await initializeControlPlane(db, user);
  await enforceRateLimit(db, `plan:${user.email.toLowerCase()}`, 10, 60);

  const path = attackPaths.find((candidate) => candidate.id === input.attackPathId);
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
    (id, workspace_id, attack_path_id, name, mode, status, requested_by, authorization_digest, plan_signature, findings, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`)
    .bind(id, WORKSPACE_ID, path.id, `${path.id} · ${path.title}`, input.mode, status, user.email, authorizationDigest, planSignature, createdAt, createdAt)
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
  const path = attackPaths.find((candidate) => candidate.id === attackPathId);
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
  await appendAuditEvent(db, user.email, "evidence.exported", path.id, { digest });
  return { payload, integrity: { algorithm: "HMAC-SHA-256", keyId: "cloudpen-plan-v1", digest, signature } };
}

export async function recordConnectorRequest(
  user: AuthorizedUser,
  input: { name: string; accountId: string; externalId: string },
) {
  const db = database();
  await initializeControlPlane(db, user);
  await enforceRateLimit(db, `connect:${user.email.toLowerCase()}`, 5, 300);
  await appendAuditEvent(db, user.email, "connector.requested", input.accountId, {
    name: input.name,
    accountId: input.accountId,
    externalIdDigest: await sha256(input.externalId),
    status: "awaiting-runner-provisioning",
  });
  return { status: "awaiting-runner-provisioning" as const };
}

async function initializeControlPlane(db: D1Database, user: AuthorizedUser): Promise<void> {
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS memberships (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'reviewer', 'viewer')), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(workspace_id, email))"),
    db.prepare("CREATE TABLE IF NOT EXISTS guardrail_policies (workspace_id TEXT PRIMARY KEY, require_approval INTEGER NOT NULL DEFAULT 1 CHECK (require_approval IN (0, 1)), canary_only INTEGER NOT NULL DEFAULT 1 CHECK (canary_only IN (0, 1)), redact_evidence INTEGER NOT NULL DEFAULT 1 CHECK (redact_evidence IN (0, 1)), cleanup_required INTEGER NOT NULL DEFAULT 1 CHECK (cleanup_required IN (0, 1)), max_concurrency INTEGER NOT NULL DEFAULT 2 CHECK (max_concurrency BETWEEN 1 AND 4), max_session_minutes INTEGER NOT NULL DEFAULT 15 CHECK (max_session_minutes BETWEEN 1 AND 30), updated_by TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    db.prepare("CREATE TABLE IF NOT EXISTS validation_runs (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, attack_path_id TEXT NOT NULL, name TEXT NOT NULL, mode TEXT NOT NULL CHECK (mode IN ('Read-only', 'Active canary')), status TEXT NOT NULL CHECK (status IN ('Planned', 'Awaiting approval', 'Stopped', 'Completed')), requested_by TEXT NOT NULL, approved_by TEXT, authorization_digest TEXT NOT NULL, plan_signature TEXT NOT NULL, findings INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, actor_email TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, details_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL, created_at TEXT NOT NULL)"),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS audit_events_chain_link ON audit_events (workspace_id, previous_hash)"),
    db.prepare("CREATE INDEX IF NOT EXISTS validation_runs_workspace_created ON validation_runs (workspace_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS audit_events_workspace_created ON audit_events (workspace_id, created_at)"),
    db.prepare("CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL)"),
  ]);
  await db.prepare("INSERT OR IGNORE INTO workspaces (id, name) VALUES (?, ?)").bind(WORKSPACE_ID, "Northstar Labs").run();
  await db.prepare(`INSERT OR IGNORE INTO memberships (id, workspace_id, email, role) VALUES (?, ?, ?, ?)`)
    .bind(`${WORKSPACE_ID}:${user.email.toLowerCase()}`, WORKSPACE_ID, user.email.toLowerCase(), user.role)
    .run();
  await db.prepare(`INSERT OR IGNORE INTO guardrail_policies
      (workspace_id, require_approval, canary_only, redact_evidence, cleanup_required, max_concurrency, max_session_minutes, updated_by)
      VALUES (?, 1, 1, 1, 1, 2, 15, ?)`)
    .bind(WORKSPACE_ID, user.email)
    .run();
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
  const previous = await db.prepare("SELECT event_hash FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT 1")
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

export class RateLimitError extends Error {
  readonly status = 429;
  constructor() {
    super("Too many requests. Try again after the rate-limit window resets.");
  }
}

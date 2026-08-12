import { sql } from "drizzle-orm";
import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const workspaces = sqliteTable("workspaces", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  dataMode: text("data_mode", { enum: ["demo", "live"] }).notNull().default("demo"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const memberships = sqliteTable(
  "memberships",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull(),
    email: text("email").notNull(),
    role: text("role", { enum: ["admin", "operator", "reviewer", "viewer"] }).notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [uniqueIndex("membership_workspace_email").on(table.workspaceId, table.email)],
);

export const guardrailPolicies = sqliteTable("guardrail_policies", {
  workspaceId: text("workspace_id").primaryKey(),
  requireApproval: integer("require_approval", { mode: "boolean" }).notNull().default(true),
  canaryOnly: integer("canary_only", { mode: "boolean" }).notNull().default(true),
  redactEvidence: integer("redact_evidence", { mode: "boolean" }).notNull().default(true),
  cleanupRequired: integer("cleanup_required", { mode: "boolean" }).notNull().default(true),
  maxConcurrency: integer("max_concurrency").notNull().default(2),
  maxSessionMinutes: integer("max_session_minutes").notNull().default(15),
  updatedBy: text("updated_by").notNull(),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const validationRuns = sqliteTable("validation_runs", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  attackPathId: text("attack_path_id").notNull(),
  name: text("name").notNull(),
  mode: text("mode", { enum: ["Read-only", "Active canary"] }).notNull(),
  status: text("status", { enum: ["Planned", "Awaiting approval", "Approved", "Rejected", "Expired", "Stopped", "Completed"] }).notNull(),
  requestedBy: text("requested_by").notNull(),
  approvedBy: text("approved_by"),
  authorizationDigest: text("authorization_digest").notNull(),
  planSignature: text("plan_signature").notNull(),
  planPayloadJson: text("plan_payload_json"),
  planEnvelopeJson: text("plan_envelope_json"),
  planKeyId: text("plan_key_id"),
  planAlgorithm: text("plan_algorithm"),
  approvalId: text("approval_id"),
  version: integer("version").notNull().default(1),
  expiresAt: text("expires_at").notNull(),
  decisionReason: text("decision_reason"),
  findings: integer("findings").notNull().default(0),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const signingKeys = sqliteTable("signing_keys", {
  keyId: text("key_id").primaryKey(),
  algorithm: text("algorithm", { enum: ["PS256"] }).notNull(),
  publicJwk: text("public_jwk").notNull(),
  status: text("status", { enum: ["active", "retired", "revoked"] }).notNull(),
  notBefore: text("not_before").notNull(),
  notAfter: text("not_after"),
  createdAt: text("created_at").notNull(),
});

export const approvalEnvelopes = sqliteTable("approval_envelopes", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  runId: text("run_id").notNull(),
  planDigest: text("plan_digest").notNull(),
  decision: text("decision", { enum: ["approve", "reject", "cancel"] }).notNull(),
  payloadJson: text("payload_json").notNull(),
  envelopeJson: text("envelope_json").notNull(),
  signature: text("signature").notNull(),
  keyId: text("key_id").notNull(),
  nonce: text("nonce").notNull(),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull(),
});

export const consumedArtifactNonces = sqliteTable("consumed_artifact_nonces", {
  nonce: text("nonce").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  artifactDomain: text("artifact_domain").notNull(),
  consumedBy: text("consumed_by").notNull(),
  consumedAt: text("consumed_at").notNull(),
});

export const connectors = sqliteTable(
  "connectors",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull(),
    provider: text("provider", { enum: ["AWS"] }).notNull().default("AWS"),
    name: text("name").notNull(),
    accountId: text("account_id").notNull(),
    status: text("status", { enum: ["Draft", "Awaiting verification", "Verified", "Runner required", "Disabled", "Error"] }).notNull(),
    externalIdStatus: text("external_id_status", { enum: ["not-retained"] }).notNull().default("not-retained"),
    createdBy: text("created_by").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
    lastSyncAt: text("last_sync_at"),
    errorMessage: text("error_message"),
  },
  (table) => [uniqueIndex("connector_workspace_account").on(table.workspaceId, table.accountId)],
);

export const evidencePackages = sqliteTable("evidence_packages", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  pathId: text("path_id").notNull(),
  classification: text("classification").notNull(),
  digest: text("digest").notNull(),
  signature: text("signature").notNull(),
  keyId: text("key_id").notNull(),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull(),
});

export const remediations = sqliteTable(
  "remediations",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull(),
    pathId: text("path_id").notNull(),
    title: text("title").notNull(),
    status: text("status", { enum: ["Open", "In progress", "Risk accepted", "Ready to revalidate", "Closed"] }).notNull(),
    priority: text("priority", { enum: ["Critical", "High", "Medium", "Low"] }).notNull(),
    owner: text("owner").notNull(),
    dueAt: text("due_at").notNull(),
    guidance: text("guidance").notNull(),
    createdBy: text("created_by").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
    version: integer("version").notNull().default(1),
    transitionReason: text("transition_reason"),
    riskAcceptedBy: text("risk_accepted_by"),
    riskAcceptanceReason: text("risk_acceptance_reason"),
    riskAcceptanceExpiresAt: text("risk_acceptance_expires_at"),
    revalidationEvidenceId: text("revalidation_evidence_id"),
  },
  (table) => [
    uniqueIndex("remediation_workspace_open_path")
      .on(table.workspaceId, table.pathId)
      .where(sql`${table.status} != 'Closed'`),
  ],
);

export const discoveryJobs = sqliteTable("discovery_jobs", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  connectorId: text("connector_id").notNull(),
  status: text("status", { enum: ["Planned", "Runner required", "Completed", "Failed"] }).notNull(),
  scopeJson: text("scope_json").notNull(),
  executable: integer("executable", { mode: "boolean" }).notNull().default(false),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull(),
});

export const runnerEnrollments = sqliteTable("runner_enrollments", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  name: text("name").notNull(),
  status: text("status", { enum: ["Pending", "Disabled"] }).notNull(),
  publicKeyFingerprint: text("public_key_fingerprint").notNull(),
  executable: integer("executable", { mode: "boolean" }).notNull().default(false),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull(),
});

export const exposureSnapshots = sqliteTable("exposure_snapshots", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  source: text("source", { enum: ["demo-seed", "aws-read-only"] }).notNull(),
  status: text("status", { enum: ["Complete", "Partial"] }).notNull(),
  collectedAt: text("collected_at").notNull(),
});

export const cloudAccounts = sqliteTable(
  "cloud_accounts",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id").notNull(),
    snapshotId: text("snapshot_id").notNull(),
    providerAccountId: text("provider_account_id").notNull(),
    dataJson: text("data_json").notNull(),
  },
  (table) => [uniqueIndex("cloud_account_workspace_provider_id").on(table.workspaceId, table.providerAccountId)],
);

export const cloudAssets = sqliteTable("cloud_assets", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  snapshotId: text("snapshot_id").notNull(),
  dataJson: text("data_json").notNull(),
});

export const exposurePaths = sqliteTable("exposure_paths", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  snapshotId: text("snapshot_id").notNull(),
  dataJson: text("data_json").notNull(),
});

export const graphEdges = sqliteTable("graph_edges", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  snapshotId: text("snapshot_id").notNull(),
  sourceNode: text("source_node").notNull(),
  targetNode: text("target_node").notNull(),
  relationship: text("relationship").notNull(),
  evidenceJson: text("evidence_json").notNull(),
});

export const auditEvents = sqliteTable("audit_events", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  actorEmail: text("actor_email").notNull(),
  action: text("action").notNull(),
  target: text("target").notNull(),
  detailsJson: text("details_json").notNull(),
  previousHash: text("previous_hash").notNull(),
  eventHash: text("event_hash").notNull(),
  createdAt: text("created_at").notNull(),
});

export const rateLimits = sqliteTable("rate_limits", {
  key: text("key").primaryKey(),
  count: integer("count").notNull(),
  expiresAt: integer("expires_at").notNull(),
});

export const securityEventOutbox = sqliteTable("security_event_outbox", {
  id: text("id").primaryKey(),
  eventJson: text("event_json").notNull(),
  eventDigest: text("event_digest").notNull(),
  attempts: integer("attempts").notNull().default(0),
  nextAttemptAt: integer("next_attempt_at").notNull(),
  lastError: text("last_error"),
  deliveredAt: text("delivered_at"),
  createdAt: text("created_at").notNull(),
});

export const auditAnchors = sqliteTable("audit_anchors", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  chainHead: text("chain_head").notNull(),
  eventCount: integer("event_count").notNull(),
  payloadJson: text("payload_json").notNull(),
  envelopeJson: text("envelope_json").notNull(),
  signature: text("signature").notNull(),
  keyId: text("key_id").notNull(),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull(),
});

export const legalHolds = sqliteTable("legal_holds", {
  id: text("id").primaryKey(),
  workspaceId: text("workspace_id").notNull(),
  reason: text("reason").notNull(),
  active: integer("active", { mode: "boolean" }).notNull().default(true),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull(),
  releasedBy: text("released_by"),
  releasedAt: text("released_at"),
});

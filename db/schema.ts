import { sql } from "drizzle-orm";
import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const workspaces = sqliteTable("workspaces", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
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
  status: text("status", { enum: ["Planned", "Awaiting approval", "Stopped", "Completed"] }).notNull(),
  requestedBy: text("requested_by").notNull(),
  approvedBy: text("approved_by"),
  authorizationDigest: text("authorization_digest").notNull(),
  planSignature: text("plan_signature").notNull(),
  findings: integer("findings").notNull().default(0),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
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

CREATE TABLE `workspaces` (
  `id` text PRIMARY KEY NOT NULL,
  `name` text NOT NULL,
  `created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `memberships` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `email` text NOT NULL,
  `role` text NOT NULL CHECK (`role` IN ('admin', 'operator', 'reviewer', 'viewer')),
  `created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `membership_workspace_email` ON `memberships` (`workspace_id`,`email`);
--> statement-breakpoint
CREATE TABLE `guardrail_policies` (
  `workspace_id` text PRIMARY KEY NOT NULL,
  `require_approval` integer DEFAULT 1 NOT NULL CHECK (`require_approval` IN (0, 1)),
  `canary_only` integer DEFAULT 1 NOT NULL CHECK (`canary_only` IN (0, 1)),
  `redact_evidence` integer DEFAULT 1 NOT NULL CHECK (`redact_evidence` IN (0, 1)),
  `cleanup_required` integer DEFAULT 1 NOT NULL CHECK (`cleanup_required` IN (0, 1)),
  `max_concurrency` integer DEFAULT 2 NOT NULL CHECK (`max_concurrency` BETWEEN 1 AND 4),
  `max_session_minutes` integer DEFAULT 15 NOT NULL CHECK (`max_session_minutes` BETWEEN 1 AND 30),
  `updated_by` text NOT NULL,
  `updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `validation_runs` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `attack_path_id` text NOT NULL,
  `name` text NOT NULL,
  `mode` text NOT NULL CHECK (`mode` IN ('Read-only', 'Active canary')),
  `status` text NOT NULL CHECK (`status` IN ('Planned', 'Awaiting approval', 'Stopped', 'Completed')),
  `requested_by` text NOT NULL,
  `approved_by` text,
  `authorization_digest` text NOT NULL,
  `plan_signature` text NOT NULL,
  `findings` integer DEFAULT 0 NOT NULL,
  `created_at` text NOT NULL,
  `updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `validation_runs_workspace_created` ON `validation_runs` (`workspace_id`,`created_at`);
--> statement-breakpoint
CREATE TABLE `audit_events` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `actor_email` text NOT NULL,
  `action` text NOT NULL,
  `target` text NOT NULL,
  `details_json` text NOT NULL,
  `previous_hash` text NOT NULL,
  `event_hash` text NOT NULL,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `audit_events_workspace_created` ON `audit_events` (`workspace_id`,`created_at`);
--> statement-breakpoint
CREATE UNIQUE INDEX `audit_events_chain_link` ON `audit_events` (`workspace_id`,`previous_hash`);
--> statement-breakpoint
CREATE TABLE `rate_limits` (
  `key` text PRIMARY KEY NOT NULL,
  `count` integer NOT NULL,
  `expires_at` integer NOT NULL
);

ALTER TABLE `validation_runs` ADD `plan_envelope_json` text;
--> statement-breakpoint
ALTER TABLE `validation_runs` ADD `plan_payload_json` text;
--> statement-breakpoint
ALTER TABLE `validation_runs` ADD `plan_key_id` text;
--> statement-breakpoint
ALTER TABLE `validation_runs` ADD `plan_algorithm` text;
--> statement-breakpoint
ALTER TABLE `validation_runs` ADD `approval_id` text;
--> statement-breakpoint
ALTER TABLE `validation_runs` ADD `version` integer DEFAULT 1 NOT NULL;
--> statement-breakpoint
CREATE TABLE `signing_keys` (
  `key_id` text PRIMARY KEY NOT NULL,
  `algorithm` text NOT NULL CHECK (`algorithm` = 'PS256'),
  `public_jwk` text NOT NULL,
  `status` text NOT NULL CHECK (`status` IN ('active', 'retired', 'revoked')),
  `not_before` text NOT NULL,
  `not_after` text,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `approval_envelopes` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `run_id` text NOT NULL,
  `plan_digest` text NOT NULL,
  `decision` text NOT NULL CHECK (`decision` IN ('approve', 'reject', 'cancel')),
  `payload_json` text NOT NULL,
  `envelope_json` text NOT NULL,
  `signature` text NOT NULL,
  `key_id` text NOT NULL,
  `nonce` text NOT NULL,
  `created_by` text NOT NULL,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `approval_workspace_run_decision` ON `approval_envelopes` (`workspace_id`, `run_id`, `decision`);
--> statement-breakpoint
CREATE UNIQUE INDEX `approval_nonce` ON `approval_envelopes` (`nonce`);
--> statement-breakpoint
CREATE INDEX `approval_workspace_created` ON `approval_envelopes` (`workspace_id`, `created_at`);
--> statement-breakpoint
CREATE TABLE `consumed_artifact_nonces` (
  `nonce` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `artifact_domain` text NOT NULL,
  `consumed_by` text NOT NULL,
  `consumed_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `consumed_nonce_workspace` ON `consumed_artifact_nonces` (`workspace_id`, `consumed_at`);
--> statement-breakpoint
CREATE TABLE `atomic_guards` (`id` integer PRIMARY KEY NOT NULL CHECK (`id` = 1));
--> statement-breakpoint
CREATE INDEX `membership_email_workspace` ON `memberships` (`email`, `workspace_id`);
--> statement-breakpoint
CREATE TABLE `security_event_outbox` (
  `id` text PRIMARY KEY NOT NULL,
  `event_json` text NOT NULL,
  `event_digest` text NOT NULL,
  `attempts` integer DEFAULT 0 NOT NULL,
  `next_attempt_at` integer NOT NULL,
  `last_error` text,
  `delivered_at` text,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `security_outbox_retry` ON `security_event_outbox` (`delivered_at`, `next_attempt_at`);
--> statement-breakpoint
CREATE TABLE `audit_anchors` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `chain_head` text NOT NULL,
  `event_count` integer NOT NULL,
  `payload_json` text NOT NULL,
  `envelope_json` text NOT NULL,
  `signature` text NOT NULL,
  `key_id` text NOT NULL,
  `created_by` text NOT NULL,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `audit_anchor_workspace_head` ON `audit_anchors` (`workspace_id`, `chain_head`);
--> statement-breakpoint
CREATE TABLE `legal_holds` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `reason` text NOT NULL,
  `active` integer DEFAULT 1 NOT NULL CHECK (`active` IN (0, 1)),
  `created_by` text NOT NULL,
  `created_at` text NOT NULL,
  `released_by` text,
  `released_at` text
);
--> statement-breakpoint
CREATE INDEX `legal_hold_workspace_active` ON `legal_holds` (`workspace_id`, `active`);
--> statement-breakpoint
PRAGMA optimize;

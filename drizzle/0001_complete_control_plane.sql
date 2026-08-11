ALTER TABLE `workspaces` ADD `data_mode` text DEFAULT 'demo' NOT NULL CHECK (`data_mode` IN ('demo', 'live'));
--> statement-breakpoint
ALTER TABLE `validation_runs` RENAME TO `validation_runs_legacy`;
--> statement-breakpoint
DROP INDEX `validation_runs_workspace_created`;
--> statement-breakpoint
CREATE TABLE `validation_runs` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `attack_path_id` text NOT NULL,
  `name` text NOT NULL,
  `mode` text NOT NULL CHECK (`mode` IN ('Read-only', 'Active canary')),
  `status` text NOT NULL CHECK (`status` IN ('Planned', 'Awaiting approval', 'Approved', 'Rejected', 'Expired', 'Stopped', 'Completed')),
  `requested_by` text NOT NULL,
  `approved_by` text,
  `authorization_digest` text NOT NULL,
  `plan_signature` text NOT NULL,
  `expires_at` text NOT NULL,
  `decision_reason` text,
  `findings` integer DEFAULT 0 NOT NULL,
  `created_at` text NOT NULL,
  `updated_at` text NOT NULL
);
--> statement-breakpoint
INSERT INTO `validation_runs` (`id`, `workspace_id`, `attack_path_id`, `name`, `mode`, `status`, `requested_by`, `approved_by`, `authorization_digest`, `plan_signature`, `expires_at`, `decision_reason`, `findings`, `created_at`, `updated_at`)
SELECT `id`, `workspace_id`, `attack_path_id`, `name`, `mode`, `status`, `requested_by`, `approved_by`, `authorization_digest`, `plan_signature`, datetime(`created_at`, '+15 minutes'), NULL, `findings`, `created_at`, `updated_at`
FROM `validation_runs_legacy`;
--> statement-breakpoint
DROP TABLE `validation_runs_legacy`;
--> statement-breakpoint
CREATE INDEX `validation_runs_workspace_created` ON `validation_runs` (`workspace_id`,`created_at`);
--> statement-breakpoint
CREATE TABLE `connectors` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `provider` text DEFAULT 'AWS' NOT NULL CHECK (`provider` = 'AWS'),
  `name` text NOT NULL,
  `account_id` text NOT NULL,
  `status` text NOT NULL CHECK (`status` IN ('Draft', 'Awaiting verification', 'Verified', 'Runner required', 'Disabled', 'Error')),
  `external_id_digest` text NOT NULL,
  `external_id_hint` text NOT NULL,
  `created_by` text NOT NULL,
  `created_at` text NOT NULL,
  `updated_at` text NOT NULL,
  `last_sync_at` text,
  `error_message` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `connector_workspace_account` ON `connectors` (`workspace_id`,`account_id`);
--> statement-breakpoint
CREATE TABLE `evidence_packages` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `path_id` text NOT NULL,
  `classification` text NOT NULL,
  `digest` text NOT NULL,
  `signature` text NOT NULL,
  `key_id` text NOT NULL,
  `created_by` text NOT NULL,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `remediations` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `path_id` text NOT NULL,
  `title` text NOT NULL,
  `status` text NOT NULL CHECK (`status` IN ('Open', 'In progress', 'Risk accepted', 'Ready to revalidate', 'Closed')),
  `priority` text NOT NULL CHECK (`priority` IN ('Critical', 'High', 'Medium', 'Low')),
  `owner` text NOT NULL,
  `due_at` text NOT NULL,
  `guidance` text NOT NULL,
  `created_by` text NOT NULL,
  `created_at` text NOT NULL,
  `updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `discovery_jobs` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `connector_id` text NOT NULL,
  `status` text NOT NULL CHECK (`status` IN ('Planned', 'Runner required', 'Completed', 'Failed')),
  `scope_json` text NOT NULL,
  `executable` integer DEFAULT 0 NOT NULL CHECK (`executable` = 0),
  `created_by` text NOT NULL,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `runner_enrollments` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `name` text NOT NULL,
  `status` text NOT NULL CHECK (`status` IN ('Pending', 'Disabled')),
  `public_key_fingerprint` text NOT NULL,
  `executable` integer DEFAULT 0 NOT NULL CHECK (`executable` = 0),
  `created_by` text NOT NULL,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `exposure_snapshots` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `source` text NOT NULL CHECK (`source` IN ('demo-seed', 'aws-read-only')),
  `status` text NOT NULL CHECK (`status` IN ('Complete', 'Partial')),
  `collected_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `cloud_accounts` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `snapshot_id` text NOT NULL,
  `provider_account_id` text NOT NULL,
  `data_json` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `cloud_account_workspace_provider_id` ON `cloud_accounts` (`workspace_id`,`provider_account_id`);
--> statement-breakpoint
CREATE TABLE `cloud_assets` (`id` text PRIMARY KEY NOT NULL, `workspace_id` text NOT NULL, `snapshot_id` text NOT NULL, `data_json` text NOT NULL);
--> statement-breakpoint
CREATE TABLE `exposure_paths` (`id` text PRIMARY KEY NOT NULL, `workspace_id` text NOT NULL, `snapshot_id` text NOT NULL, `data_json` text NOT NULL);
--> statement-breakpoint
CREATE TABLE `graph_edges` (`id` text PRIMARY KEY NOT NULL, `workspace_id` text NOT NULL, `snapshot_id` text NOT NULL, `source_node` text NOT NULL, `target_node` text NOT NULL, `relationship` text NOT NULL, `evidence_json` text NOT NULL);
--> statement-breakpoint
CREATE INDEX `connectors_workspace_created` ON `connectors` (`workspace_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX `evidence_workspace_created` ON `evidence_packages` (`workspace_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX `remediations_workspace_updated` ON `remediations` (`workspace_id`,`updated_at`);
--> statement-breakpoint
CREATE INDEX `exposure_paths_workspace_snapshot` ON `exposure_paths` (`workspace_id`,`snapshot_id`);
--> statement-breakpoint
CREATE INDEX `cloud_assets_workspace_snapshot` ON `cloud_assets` (`workspace_id`,`snapshot_id`);
--> statement-breakpoint
CREATE INDEX `graph_edges_workspace_snapshot` ON `graph_edges` (`workspace_id`,`snapshot_id`);
--> statement-breakpoint
PRAGMA optimize;

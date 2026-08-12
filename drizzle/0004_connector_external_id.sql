ALTER TABLE `connectors` RENAME TO `connectors_legacy`;
--> statement-breakpoint
DROP INDEX `connector_workspace_account`;
--> statement-breakpoint
DROP INDEX `connectors_workspace_created`;
--> statement-breakpoint
CREATE TABLE `connectors` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `provider` text DEFAULT 'AWS' NOT NULL CHECK (`provider` = 'AWS'),
  `name` text NOT NULL,
  `account_id` text NOT NULL,
  `status` text NOT NULL CHECK (`status` IN ('Draft', 'Awaiting verification', 'Verified', 'Runner required', 'Disabled', 'Error')),
  `external_id_status` text DEFAULT 'not-retained' NOT NULL CHECK (`external_id_status` = 'not-retained'),
  `created_by` text NOT NULL,
  `created_at` text NOT NULL,
  `updated_at` text NOT NULL,
  `last_sync_at` text,
  `error_message` text
);
--> statement-breakpoint
INSERT INTO `connectors` (`id`, `workspace_id`, `provider`, `name`, `account_id`, `status`, `external_id_status`, `created_by`, `created_at`, `updated_at`, `last_sync_at`, `error_message`)
SELECT `id`, `workspace_id`, `provider`, `name`, `account_id`, `status`, 'not-retained', `created_by`, `created_at`, `updated_at`, `last_sync_at`, `error_message`
FROM `connectors_legacy`;
--> statement-breakpoint
DROP TABLE `connectors_legacy`;
--> statement-breakpoint
CREATE UNIQUE INDEX `connector_workspace_account` ON `connectors` (`workspace_id`, `account_id`);
--> statement-breakpoint
CREATE INDEX `connectors_workspace_created` ON `connectors` (`workspace_id`, `created_at`);

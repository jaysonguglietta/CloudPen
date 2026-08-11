CREATE UNIQUE INDEX `remediation_workspace_open_path`
ON `remediations` (`workspace_id`, `path_id`)
WHERE `status` != 'Closed';
--> statement-breakpoint
ALTER TABLE `remediations` ADD `version` integer DEFAULT 1 NOT NULL;
--> statement-breakpoint
ALTER TABLE `remediations` ADD `transition_reason` text;
--> statement-breakpoint
ALTER TABLE `remediations` ADD `risk_accepted_by` text;
--> statement-breakpoint
ALTER TABLE `remediations` ADD `risk_acceptance_reason` text;
--> statement-breakpoint
ALTER TABLE `remediations` ADD `risk_acceptance_expires_at` text;
--> statement-breakpoint
ALTER TABLE `remediations` ADD `revalidation_evidence_id` text;
--> statement-breakpoint
CREATE INDEX `audit_events_workspace_sequence`
ON `audit_events` (`workspace_id`, `created_at`, `id`);

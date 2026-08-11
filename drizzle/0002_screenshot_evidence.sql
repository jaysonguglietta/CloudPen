CREATE TABLE `screenshot_evidence` (
  `id` text PRIMARY KEY NOT NULL,
  `workspace_id` text NOT NULL,
  `framework_id` text NOT NULL,
  `framework_label` text NOT NULL,
  `control_id` text NOT NULL,
  `control_label` text NOT NULL,
  `title` text NOT NULL,
  `notes` text DEFAULT '' NOT NULL,
  `stored_filename` text NOT NULL,
  `object_key` text NOT NULL,
  `folder_path` text NOT NULL,
  `banner_position` text NOT NULL CHECK (`banner_position` IN ('top', 'bottom')),
  `include_timestamp` integer NOT NULL DEFAULT 1 CHECK (`include_timestamp` IN (0, 1)),
  `include_actor` integer NOT NULL DEFAULT 1 CHECK (`include_actor` IN (0, 1)),
  `captured_at` text NOT NULL,
  `width` integer NOT NULL CHECK (`width` BETWEEN 1 AND 12000),
  `height` integer NOT NULL CHECK (`height` BETWEEN 1 AND 12000),
  `size_bytes` integer NOT NULL CHECK (`size_bytes` BETWEEN 1 AND 12582912),
  `sha256_digest` text NOT NULL,
  `created_by` text NOT NULL,
  `created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `screenshot_evidence_object_key` ON `screenshot_evidence` (`object_key`);
--> statement-breakpoint
CREATE INDEX `screenshot_evidence_workspace_control_created` ON `screenshot_evidence` (`workspace_id`,`framework_id`,`control_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX `screenshot_evidence_workspace_created` ON `screenshot_evidence` (`workspace_id`,`created_at`);
--> statement-breakpoint
PRAGMA optimize;

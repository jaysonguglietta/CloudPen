export type Severity = "Critical" | "High" | "Medium" | "Low";
export type PathStatus = "Validated" | "Inferred" | "Mitigated";
export type ViewKey =
  | "overview"
  | "paths"
  | "assets"
  | "runs"
  | "connectors"
  | "remediation"
  | "evidence"
  | "audit"
  | "reports"
  | "administration"
  | "guardrails";

export type AttackStep = {
  label: string;
  type: "identity" | "permission" | "service" | "data";
  detail: string;
};

export type AttackPath = {
  id: string;
  title: string;
  summary: string;
  severity: Severity;
  status: PathStatus;
  score: number;
  account: string;
  region: string;
  target: string;
  targetType: string;
  updated: string;
  techniques: string[];
  steps: AttackStep[];
  evidence: string[];
  rootCause: string;
  remediation: string;
};

export type CloudAccount = {
  id: string;
  name: string;
  environment: string;
  assets: number;
  paths: number;
  health: "Healthy" | "Attention";
  lastSync: string;
};

export type CloudAsset = {
  id: string;
  name: string;
  type: string;
  account: string;
  region: string;
  exposure: "Internet" | "Cross-account" | "Private";
  paths: number;
  owner: string;
};

export type ValidationRun = {
  id: string;
  name: string;
  mode: "Read-only" | "Active canary";
  status: "Completed" | "Running" | "Stopped" | "Planned" | "Awaiting approval" | "Approved" | "Rejected" | "Expired";
  pathCount: number;
  findings: number;
  requestedBy: string;
  started: string;
  duration: string;
  attackPathId?: string;
  authorizationDigest?: string;
  signature?: string;
  expiresAt?: string;
  approvedBy?: string | null;
  decisionReason?: string | null;
};

export type WorkspaceSummary = {
  id: string;
  name: string;
  dataMode: "demo" | "live";
  role: "admin" | "operator" | "reviewer" | "viewer";
};

export type ConnectorRecord = {
  id: string;
  name: string;
  accountId: string;
  provider: "AWS";
  status: "Draft" | "Awaiting verification" | "Verified" | "Runner required" | "Disabled" | "Error";
  externalIdHint: string;
  createdBy: string;
  createdAt: string;
  lastSyncAt: string | null;
  errorMessage: string | null;
};

export type EvidenceRecord = {
  id: string;
  pathId: string;
  classification: string;
  digest: string;
  keyId: string;
  createdBy: string;
  createdAt: string;
};

export type RemediationRecord = {
  id: string;
  pathId: string;
  title: string;
  status: "Open" | "In progress" | "Risk accepted" | "Ready to revalidate" | "Closed";
  priority: Severity;
  owner: string;
  dueAt: string;
  guidance: string;
  createdAt: string;
  updatedAt: string;
  version: number;
  transitionReason: string | null;
  riskAcceptedBy: string | null;
  riskAcceptanceReason: string | null;
  riskAcceptanceExpiresAt: string | null;
  revalidationEvidenceId: string | null;
};

export type AuditRecord = {
  id: string;
  actorEmail: string;
  action: string;
  target: string;
  eventHash: string;
  previousHash: string;
  createdAt: string;
};

export type RunnerRecord = {
  id: string;
  name: string;
  status: "Pending" | "Disabled";
  publicKeyFingerprint: string;
  executable: false;
  createdBy: string;
  createdAt: string;
};

export type ControlPlaneSnapshot = {
  workspace: WorkspaceSummary;
  runs: ValidationRun[];
  connectors: ConnectorRecord[];
  evidence: EvidenceRecord[];
  remediations: RemediationRecord[];
  audit: AuditRecord[];
  runners: RunnerRecord[];
  auditChainValid: boolean;
};

export type ExposureCatalog = {
  accounts: CloudAccount[];
  assets: CloudAsset[];
  attackPaths: AttackPath[];
  snapshot: { id: string; source: "demo-seed" | "aws-read-only"; status: "Complete" | "Partial"; collectedAt: string };
};

export const accounts: CloudAccount[] = [
  {
    id: "4107-8821-1034",
    name: "Northstar Production",
    environment: "Production",
    assets: 1864,
    paths: 9,
    health: "Healthy",
    lastSync: "4 min ago",
  },
  {
    id: "6082-1940-7731",
    name: "Data Platform",
    environment: "Production",
    assets: 743,
    paths: 4,
    health: "Healthy",
    lastSync: "7 min ago",
  },
  {
    id: "9928-0441-6195",
    name: "Sandbox & Labs",
    environment: "Development",
    assets: 428,
    paths: 3,
    health: "Attention",
    lastSync: "2 hr ago",
  },
];

export const attackPaths: AttackPath[] = [
  {
    id: "CP-1042",
    title: "CI role can become production administrator",
    summary:
      "A deploy role trusted by GitHub Actions can pass a privileged execution role to Lambda and invoke it with administrator permissions.",
    severity: "Critical",
    status: "Validated",
    score: 9.6,
    account: "Northstar Production",
    region: "us-east-1",
    target: "customer-export-prod",
    targetType: "S3 bucket",
    updated: "18 min ago",
    techniques: ["T1078.004", "T1098", "T1530"],
    steps: [
      {
        label: "github-deploy",
        type: "identity",
        detail: "Federated role · initial foothold",
      },
      {
        label: "iam:PassRole",
        type: "permission",
        detail: "Unscoped role delegation",
      },
      {
        label: "billing-worker-admin",
        type: "service",
        detail: "Lambda execution role",
      },
      {
        label: "customer-export-prod",
        type: "data",
        detail: "Restricted customer exports",
      },
    ],
    evidence: [
      "STS role assumption completed with a 15-minute test session",
      "iam:PassRole allowed for arn:aws:iam::*:role/*",
      "Canary object read succeeded; payload discarded in runner memory",
      "CloudTrail recorded all 6 validation events",
    ],
    rootCause:
      "The deploy role permits iam:PassRole without an iam:PassedToService condition or a resource allowlist.",
    remediation:
      "Restrict iam:PassRole to the two approved deployment roles and require iam:PassedToService=lambda.amazonaws.com.",
  },
  {
    id: "CP-1037",
    title: "Vendor support trust accepts any external session",
    summary:
      "A third-party support role lacks an ExternalId condition and can reach a data-processing role through nested trust.",
    severity: "High",
    status: "Validated",
    score: 8.4,
    account: "Data Platform",
    region: "us-west-2",
    target: "analytics-pipeline-role",
    targetType: "IAM role",
    updated: "2 hr ago",
    techniques: ["T1078.004", "T1550"],
    steps: [
      {
        label: "external-vendor",
        type: "identity",
        detail: "Third-party AWS account",
      },
      {
        label: "support-access",
        type: "permission",
        detail: "Missing ExternalId condition",
      },
      {
        label: "analytics-pipeline-role",
        type: "service",
        detail: "Cross-role assumption",
      },
    ],
    evidence: [
      "Trust policy permits the registered vendor account without ExternalId",
      "Role assumption validated using the authorized canary principal",
      "GuardDuty did not generate a finding during the validation window",
    ],
    rootCause:
      "The vendor trust relationship relies only on the supplier account ID and does not bind sessions to this customer.",
    remediation:
      "Add a unique ExternalId condition, restrict the role session name, and alert on assumptions outside approved support windows.",
  },
  {
    id: "CP-1031",
    title: "Build instance profile can decrypt release signing key",
    summary:
      "A build worker role inherits KMS decrypt access through a wildcard resource policy and can reach the release-signing key.",
    severity: "High",
    status: "Inferred",
    score: 7.9,
    account: "Northstar Production",
    region: "us-east-1",
    target: "alias/release-signing",
    targetType: "KMS key",
    updated: "Yesterday",
    techniques: ["T1552.005", "T1078.004"],
    steps: [
      {
        label: "buildkite-worker",
        type: "identity",
        detail: "EC2 instance profile",
      },
      {
        label: "kms:Decrypt",
        type: "permission",
        detail: "Wildcard key resource",
      },
      {
        label: "alias/release-signing",
        type: "data",
        detail: "Production signing key",
      },
    ],
    evidence: [
      "Identity policy grants kms:Decrypt on resource *",
      "Key policy delegates access to the account root principal",
      "Active validation withheld: protected key is not tagged for testing",
    ],
    rootCause:
      "The build worker policy uses a wildcard KMS resource and the key policy delegates authorization back to IAM.",
    remediation:
      "Scope the worker to its artifact-encryption key and add an explicit deny for keys tagged DataClass=Restricted.",
  },
  {
    id: "CP-1024",
    title: "Support role retains direct database snapshot access",
    summary:
      "A legacy incident-support role can copy encrypted production snapshots into the shared operations account.",
    severity: "Medium",
    status: "Mitigated",
    score: 5.8,
    account: "Northstar Production",
    region: "us-east-2",
    target: "orders-primary-snapshots",
    targetType: "RDS snapshots",
    updated: "Jul 29",
    techniques: ["T1537"],
    steps: [
      {
        label: "incident-support",
        type: "identity",
        detail: "Human support role",
      },
      {
        label: "rds:CopyDBSnapshot",
        type: "permission",
        detail: "Legacy incident permission",
      },
      {
        label: "orders-primary-snapshots",
        type: "data",
        detail: "Production database backup",
      },
    ],
    evidence: [
      "Path was validated on July 21 against a canary snapshot",
      "Permission boundary deployed on July 28",
      "Retest confirms rds:CopyDBSnapshot is now denied",
    ],
    rootCause:
      "A temporary incident-response statement remained attached after the support event ended.",
    remediation:
      "Completed: the permission is now gated by an incident tag and a four-hour access package.",
  },
];

export const assets: CloudAsset[] = [
  { id: "AST-9812", name: "customer-export-prod", type: "S3 bucket", account: "Northstar Production", region: "us-east-1", exposure: "Private", paths: 3, owner: "Data Engineering" },
  { id: "AST-9744", name: "billing-worker-admin", type: "IAM role", account: "Northstar Production", region: "Global", exposure: "Cross-account", paths: 4, owner: "Payments" },
  { id: "AST-9517", name: "analytics-pipeline-role", type: "IAM role", account: "Data Platform", region: "Global", exposure: "Cross-account", paths: 2, owner: "Data Platform" },
  { id: "AST-9305", name: "alias/release-signing", type: "KMS key", account: "Northstar Production", region: "us-east-1", exposure: "Private", paths: 1, owner: "Release Engineering" },
  { id: "AST-9160", name: "partner-api", type: "API Gateway", account: "Data Platform", region: "us-west-2", exposure: "Internet", paths: 2, owner: "Integrations" },
  { id: "AST-9028", name: "eks-analytics-prod", type: "EKS cluster", account: "Data Platform", region: "us-west-2", exposure: "Private", paths: 1, owner: "Platform Security" },
];

export const initialRuns: ValidationRun[] = [
  { id: "RUN-0291", name: "Weekly production identity validation", mode: "Read-only", status: "Completed", pathCount: 14, findings: 2, requestedBy: "Sample operator", started: "Today, 09:12", duration: "8m 42s" },
  { id: "RUN-0287", name: "Vendor trust retest", mode: "Active canary", status: "Completed", pathCount: 3, findings: 1, requestedBy: "Sample reviewer", started: "Yesterday, 14:30", duration: "4m 18s" },
  { id: "RUN-0278", name: "July remediation verification", mode: "Read-only", status: "Completed", pathCount: 8, findings: 0, requestedBy: "Sample operator", started: "Jul 29, 11:05", duration: "6m 09s" },
  { id: "RUN-0269", name: "Sandbox active validation", mode: "Active canary", status: "Stopped", pathCount: 2, findings: 0, requestedBy: "Sample operator", started: "Jul 26, 16:44", duration: "1m 51s" },
];

export const severityRank: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

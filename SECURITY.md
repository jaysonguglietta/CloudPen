# CloudPen security policy and boundary

CloudPen is a security-validation control plane. It does not currently execute AWS API calls. Any future runner must remain a separate customer-hosted component and must reject plans unless every signature, expiry, workspace, account, module, region, resource tag, operation, concurrency, and cleanup constraint is valid.

## Implemented controls

- Sites provides the external identity boundary; application roles are enforced from explicit email allowlists.
- Local development binds to loopback and uses a development identity only in explicit local mode or while `NODE_ENV=development`.
- Mutation APIs require same-origin requests, bounded JSON or multipart bodies, authorization, and D1-backed rate limits.
- Validation requests create server-owned HMAC-signed plans. Plans are explicitly non-executable in this release.
- Active canary plans enter `Awaiting approval`; the requester cannot cause execution.
- Evidence exports are generated server-side, redacted, signed, and logged.
- Screenshot uploads require explicit capture authorization; the service accepts only bounded PNG data, validates its signature and dimensions, computes a SHA-256 digest, stores bytes privately in R2, and retains workspace-scoped control metadata in D1.
- Audit events form an append-only hash chain in D1.
- Production safety controls cannot be disabled through the API.
- Security headers, clean build outputs, dependency auditing, tests, and CI gates are enforced.

## Production prerequisites

Set `CLOUDPEN_ADMIN_EMAILS` and a unique secret `CLOUDPEN_PLAN_SIGNING_KEY` in the Sites environment. Keep access mode private/custom. Do not place credentials in source, browser storage, D1, logs, or evidence.

## Deliberately disabled

- AWS role assumption and all cloud mutations
- Runner enrollment and outbound command delivery
- Plan approval and execution APIs
- Customer data collection

These controls require a customer-hosted runner, workload identity, KMS-backed asymmetric signing, one-time nonces, account-ownership proof, separate approvers, per-module AWS allowlists, egress restrictions, and independent security review.

## Reporting

Report suspected vulnerabilities privately through GitHub's private vulnerability reporting for this repository when available. If that channel is unavailable, contact the repository owner through a previously established trusted private channel before sending technical details.

Do not open a public issue for a suspected vulnerability. Do not include credentials, customer payloads, live exploit data, personal data, internal hostnames, or production account identifiers in a report.

Include, when safe:

- affected commit or version;
- prerequisite identity/role and deployment mode;
- minimal synthetic reproduction;
- security impact and likely attack path;
- relevant logs with secrets and tenant data removed;
- suggested mitigation, if known.

## Supported versions

CloudPen is pre-production and has no stable supported release line. Only the latest maintained commit is considered for security fixes. Older snapshots, forks, and local modifications are unsupported.

## Safe research expectations

- Test only systems and accounts you own or are explicitly authorized to assess.
- Use local or synthetic environments.
- Do not attempt denial of service, social engineering, persistence, data access, or cloud actions against third parties.
- Stop and report if testing encounters real credentials, customer data, or an unexpected production service.
- Give maintainers reasonable time to investigate and remediate before disclosure.

This policy does not grant authorization to test hosted services, GitHub, Sites, Cloudflare, AWS, or any third-party infrastructure.

# CloudPen documentation

This directory is the source of truth for the current CloudPen control-plane prototype. Documentation describes the code in this repository, not an aspirational production service, unless a section is explicitly labeled as future design.

## Start here

| Audience | Read first | Purpose |
| --- | --- | --- |
| Product and security leaders | [Architecture](./architecture.md) | Scope, trust boundaries, and what is deliberately unavailable |
| Application engineers | [API reference](./api.md) | Routes, roles, validation, and response contracts |
| Security reviewers | [Security review](./security-review.md) | Threat model, findings, mitigations, and residual risk |
| Release owners | [Production hardening](./production-hardening.md) | Implemented controls, evidence, and external launch gates |
| Operators | [Deployment](./deployment.md) and [Operations](./operations.md) | Safe configuration, startup, monitoring, incidents, and recovery |
| Runner engineers | [Runner security design](./runner-security-design.md) | Mandatory controls before any AWS action is enabled |
| Product owners | [Feature delivery status](./feature-roadmap.md) | Implemented workflows, partial foundations, and execution launch gates |
| Contributors and release owners | [Testing and release](./testing-and-release.md) | Quality gates and release evidence |

## Document map

- [Architecture and trust boundaries](./architecture.md)
- [Data model](./data-model.md)
- [API reference](./api.md)
- [Adversarial security review](./security-review.md)
- [Production hardening program](./production-hardening.md)
- [Signed artifact protocol](./cryptographic-protocol.md)
- [SIEM integration contract](./siem-integration.md)
- [Data lifecycle and recovery](./data-lifecycle.md)
- [Configuration and deployment](./deployment.md)
- [Operations and incident response](./operations.md)
- [Customer-hosted runner security design](./runner-security-design.md)
- [Feature delivery status and remaining launch gates](./feature-roadmap.md)
- [Testing and release gates](./testing-and-release.md)
- [Architecture decision: fail-closed control plane](./decisions/0001-fail-closed-control-plane.md)

## Documentation rules

1. Do not describe a planned control as implemented.
2. Keep examples synthetic; never commit customer account IDs, credentials, tokens, resource names, evidence, or incident data.
3. Update the API and data-model documents in the same change as their code or migration.
4. Update the security review when a trust boundary, execution capability, identity source, cryptographic control, or outbound network path changes.
5. Treat contradictions between documentation and code as release blockers.

# Contributing to CloudPen

CloudPen is security-sensitive software. Contributions are welcome, but convenience must not weaken authorization, evidence integrity, tenant boundaries, or the fail-closed execution posture.

## Development workflow

1. Use Node.js 22.13.0 or later.
2. Install exactly from the lockfile with `npm ci`.
3. Build before starting the local Worker: `npm run build`.
4. Run locally with `npm start` and use only `http://127.0.0.1:8787`.
5. Keep environment files ignored and use `.env.example` only as a key reference.

Before submitting a change, run:

```bash
npm run lint
npm run typecheck
npm run docs:check
npm test
npm run security:check
npm run security:audit
```

## Security requirements

- Every server mutation must enforce a capability, same-origin JSON requests, a bounded body, explicit schema validation, rate limits, sanitized errors, and an audit event.
- Never trust browser state as an approval, result, evidence record, tenant identifier, role, or execution instruction.
- Parameterize all database input. Do not build SQL from request-controlled strings.
- Never introduce generic outbound URL fetching. Any future egress destination requires an explicit allowlist and SSRF review.
- Never add shell execution, dynamic module loading, `eval`, unsafe deserialization, or user-controlled file paths without a dedicated security design and review.
- Never log credentials, tokens, External IDs, customer payloads, evidence contents, or signing keys.
- A runner-facing change requires updates to the threat model, runner design, protocol tests, and an independent review plan.
- Keep live cloud execution disabled unless all mandatory gates in `docs/runner-security-design.md` are satisfied.

## Database changes

Update all of the following together:

- `db/schema.ts`
- a reviewed SQL migration under `drizzle/`
- runtime compatibility initialization in `lib/server/control-plane.ts`, if it remains necessary
- `docs/data-model.md`
- migration and rollback validation in the release evidence

Migrations must be additive where practical, bounded in runtime, and tested against a copy of representative synthetic data. Never test a destructive migration against the only production copy.

## Pull requests

Describe:

- the problem and intended user impact;
- the trust boundaries or data classifications affected;
- abuse cases considered;
- validation performed;
- migration, rollback, and monitoring implications;
- documentation changed.

Do not include sensitive screenshots, live evidence, credentials, internal URLs, or customer identifiers in commits, issues, or pull requests.

## Dependency changes

Prefer existing dependencies and standard platform APIs. New dependencies require a clear need, a maintained upstream, compatible licensing review by the repository owner, a lockfile update, and a clean `npm audit`. Never suppress npm peer-resolution failures to merge an update. CI actions must be pinned to full commit SHAs, and multi-step actions such as CodeQL must use one matching SHA throughout the workflow. Follow the dependency-review procedure in [Testing and release gates](./docs/testing-and-release.md#dependency-and-action-update-review).

## License and external contributions

This repository does not currently declare an open-source license. No license grant should be inferred. The repository owner must choose and add a license before accepting external contributions or redistributing the software.

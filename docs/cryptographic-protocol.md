# Signed artifact protocol

CloudPen signs canonical JSON envelopes, not arbitrary request bodies. Protocol v2 uses RSA-PSS with SHA-256 (`PS256`) and a 32-byte salt. A signed artifact contains the envelope, base64url signature, and public JWK for transport convenience. Verifiers must pin an independently obtained keyset; they must never trust the embedded JWK by itself.

The envelope binds schema and protocol version, artifact domain, algorithm, key ID, workspace, audience, issue/expiry times, a random nonce, and the SHA-256 base64url digest of the canonical payload. Security-critical verifiers reject unknown protocol versions, algorithms other than PS256, wrong domain/workspace/audience, untrusted or revoked keys, not-yet-valid or expired artifacts, consumed nonces, payload mismatch, and invalid signatures.

Domains separate plans, approvals, evidence, guardrails, assessments, audit anchors, and backup manifests. A valid evidence signature therefore cannot be replayed as a runner plan. Plans and approvals expire within 31 days; archival artifacts have longer bounded lifetimes. Runner consumption must persist the nonce atomically before execution.

Use the independent verifier with a keyset distributed outside the artifact channel:

```bash
npm run verify:artifact -- artifact.json \
  --keyset trusted-keyset.json \
  --domain cloudpen.plan.v2 \
  --workspace northstar-labs \
  --audience cloudpen-runner.v1
```

The trusted keyset format is:

```json
{"keys":[{"keyId":"arn:aws:kms:...","algorithm":"PS256","status":"active","publicKeyJwk":{"kty":"RSA","n":"...","e":"AQAB"},"notBefore":"2026-08-12T00:00:00.000Z","notAfter":null}]}
```

Retired keys may verify artifacts issued during their validity window. Revoked keys fail verification. Rotation publishes a new key before issuance switches, retains old public keys for historical validation, and records the cutoff. Private keys never enter Sites, D1, source, logs, backup exports, or verifier keysets.

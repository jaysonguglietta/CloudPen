# AWS KMS signer

This stack is CloudPen's production signing boundary. It creates a retained RSA-3072 KMS signing key, a generated bearer credential in Secrets Manager, a narrowly permissioned Lambda, a throttled HTTP API exposing only `POST /v1/sign`, 90-day Lambda logs, X-Ray tracing, and an error alarm.

The private key is non-exportable. The Lambda may call only `kms:Sign` on this key and read only its signer credential. The control plane sends the canonical artifact envelope; the signer never receives a cloud credential, plan payload, evidence payload, or customer AWS access.

## Deploy

Use an explicitly selected production AWS account and region:

```bash
sam build --template-file infra/aws-kms-signer/template.yaml
sam deploy --guided --stack-name cloudpen-production-signer --capabilities CAPABILITY_IAM
```

Record the `SignerUrl`, `SigningKeyId`, and `SignerTokenSecretArn` outputs. Retrieve the generated credential through an approved secrets workflow, not shell history or CI logs. Generate the public JWK with:

```bash
node scripts/aws-kms-public-jwk.mjs KEY_ARN REGION > cloudpen-production-public-jwk.json
```

Configure the Sites secrets/bindings documented in `docs/deployment.md`, validate `/api/admin/readiness`, issue a synthetic plan, and independently verify it before enabling production mode.

KMS automatic rotation does not support asymmetric keys. Rotate by deploying a new key, publishing and pinning its public JWK/key ID, retaining the old public key for historical verification, retiring issuance with the old key, and revoking it only when compromise or policy requires.

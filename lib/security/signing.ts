import { canonicalJson, fromBase64Url, sha256Base64Url, toBase64Url, utf8 } from "./canonical";
import { configuredOrigin, runtimeBindings } from "./runtime";

export const SIGNED_ARTIFACT_SCHEMA = "cloudpen.signed-artifact.v2" as const;
export const SIGNING_ALGORITHM = "PS256" as const;

export type ArtifactDomain =
  | "cloudpen.plan.v2"
  | "cloudpen.approval.v2"
  | "cloudpen.evidence.v2"
  | "cloudpen.guardrails.v2"
  | "cloudpen.assessment.v2"
  | "cloudpen.audit-anchor.v2"
  | "cloudpen.backup-manifest.v2";

export type SignedArtifactEnvelope = {
  schema: typeof SIGNED_ARTIFACT_SCHEMA;
  protocolVersion: 2;
  domain: ArtifactDomain;
  algorithm: typeof SIGNING_ALGORITHM;
  keyId: string;
  workspaceId: string;
  audience: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  payloadDigest: string;
};

export type SignedArtifact = {
  envelope: SignedArtifactEnvelope;
  signature: string;
  publicKeyJwk: JsonWebKey;
};

type SignContext = {
  domain: ArtifactDomain;
  workspaceId: string;
  audience: string;
  expiresAt: string;
  nonce?: string;
  issuedAt?: string;
};

type VerifyContext = {
  domain: ArtifactDomain;
  workspaceId: string;
  audience: string;
  now?: Date;
  revokedKeyIds?: ReadonlySet<string>;
  consumedNonces?: ReadonlySet<string>;
};

type LocalSigner = { privateKey: CryptoKey; publicKeyJwk: JsonWebKey; keyId: string };
const localSignerKey = Symbol.for("cloudpen.runtime.local-asymmetric-signer");
type SigningGlobal = typeof globalThis & { [localSignerKey]?: Promise<LocalSigner> };

export async function signArtifact(payload: unknown, context: SignContext): Promise<SignedArtifact> {
  validateContext(context);
  const issuedAt = context.issuedAt ?? new Date().toISOString();
  const external = externalSignerConfiguration();
  const local = external ? null : await ephemeralLocalSigner();
  const keyId = external ? configuredKeyId() : local!.keyId;
  const envelope: SignedArtifactEnvelope = {
    schema: SIGNED_ARTIFACT_SCHEMA,
    protocolVersion: 2,
    domain: context.domain,
    algorithm: SIGNING_ALGORITHM,
    keyId,
    workspaceId: context.workspaceId,
    audience: context.audience,
    issuedAt,
    expiresAt: context.expiresAt,
    nonce: context.nonce ?? crypto.randomUUID(),
    payloadDigest: await sha256Base64Url(canonicalJson(payload)),
  };
  const input = canonicalJson(envelope);
  if (external) {
    const response = await fetch(external.url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${external.token}`,
        "content-type": "application/json",
        "x-cloudpen-signer-protocol": SIGNED_ARTIFACT_SCHEMA,
      },
      body: JSON.stringify({ algorithm: SIGNING_ALGORITHM, keyId, message: toBase64Url(utf8(input).buffer) }),
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error(`The production signer rejected the request (${response.status}).`);
    const body = await response.json() as Record<string, unknown>;
    const signature = typeof body.signature === "string" && /^[A-Za-z0-9_-]{128,1024}$/.test(body.signature)
      ? body.signature : null;
    if (!signature) throw new Error("The production signer returned an invalid signature.");
    const publicKeyJwk = configuredPublicKey();
    const artifact = { envelope, signature, publicKeyJwk };
    if (!(await verifySignedArtifact(payload, artifact, context))) throw new Error("The production signer returned an unverifiable signature.");
    return artifact;
  }

  const localSigner = local!;
  const signature = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    localSigner.privateKey,
    utf8(input),
  );
  return { envelope, signature: toBase64Url(signature), publicKeyJwk: localSigner.publicKeyJwk };
}

export async function verifySignedArtifact(
  payload: unknown,
  artifact: SignedArtifact,
  expected: VerifyContext,
): Promise<boolean> {
  const { envelope } = artifact;
  if (envelope.schema !== SIGNED_ARTIFACT_SCHEMA || envelope.protocolVersion !== 2 || envelope.algorithm !== SIGNING_ALGORITHM) return false;
  if (envelope.domain !== expected.domain || envelope.workspaceId !== expected.workspaceId || envelope.audience !== expected.audience) return false;
  if (expected.revokedKeyIds?.has(envelope.keyId) || expected.consumedNonces?.has(envelope.nonce)) return false;
  const now = (expected.now ?? new Date()).valueOf();
  const issued = new Date(envelope.issuedAt).valueOf();
  const expires = new Date(envelope.expiresAt).valueOf();
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + 60_000 || expires <= now || expires <= issued) return false;
  if (envelope.payloadDigest !== await sha256Base64Url(canonicalJson(payload))) return false;
  if (!isPublicSigningJwk(artifact.publicKeyJwk)) return false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      artifact.publicKeyJwk,
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      key,
      fromBase64Url(artifact.signature),
      utf8(canonicalJson(envelope)),
    );
  } catch {
    return false;
  }
}

function validateContext(context: SignContext): void {
  if (!/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(context.workspaceId)) throw new Error("Invalid signing workspace.");
  if (!/^[a-z0-9][a-z0-9.:/-]{2,127}$/.test(context.audience)) throw new Error("Invalid signing audience.");
  const expires = new Date(context.expiresAt).valueOf();
  const maxLifetimeDays = context.domain === "cloudpen.audit-anchor.v2" || context.domain === "cloudpen.backup-manifest.v2"
    ? 3_653
    : context.domain === "cloudpen.evidence.v2" || context.domain === "cloudpen.assessment.v2"
      ? 366
      : 31;
  if (!Number.isFinite(expires) || expires <= Date.now() || expires > Date.now() + maxLifetimeDays * 86_400_000) {
    throw new Error(`Signed ${context.domain} artifacts must expire within ${maxLifetimeDays} days.`);
  }
}

function configuredKeyId(): string {
  const keyId = runtimeBindings().CLOUDPEN_SIGNING_KEY_ID?.trim();
  if (!keyId || !/^[A-Za-z0-9._:/-]{8,200}$/.test(keyId)) {
    if (localSigningAllowed()) return "cloudpen-local-ephemeral-ps256-v2";
    throw new Error("CLOUDPEN_SIGNING_KEY_ID is not configured.");
  }
  return keyId;
}

function configuredPublicKey(): JsonWebKey {
  const raw = runtimeBindings().CLOUDPEN_SIGNING_PUBLIC_JWK?.trim();
  if (!raw) throw new Error("CLOUDPEN_SIGNING_PUBLIC_JWK is not configured.");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error("CLOUDPEN_SIGNING_PUBLIC_JWK is invalid JSON."); }
  if (!isPublicSigningJwk(value)) throw new Error("CLOUDPEN_SIGNING_PUBLIC_JWK must be a public RSA PS256 JWK.");
  return value;
}

function externalSignerConfiguration(): { url: string; token: string } | null {
  const bindings = runtimeBindings();
  const rawUrl = bindings.CLOUDPEN_SIGNER_URL?.trim();
  const token = bindings.CLOUDPEN_SIGNER_TOKEN?.trim();
  if (!rawUrl && !token) return null;
  if (!rawUrl || !token || token.length < 32) throw new Error("The production signer URL and token must both be configured.");
  const url = new URL(rawUrl);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/v1/sign") {
    throw new Error("CLOUDPEN_SIGNER_URL must be an exact HTTPS /v1/sign endpoint.");
  }
  return { url: url.href, token };
}

function localSigningAllowed(): boolean {
  const bindings = runtimeBindings();
  if (bindings.CLOUDPEN_LOCAL_MODE !== "1" && bindings.CLOUDPEN_EPHEMERAL_SIGNER !== "1") return false;
  const hostname = new URL(configuredOrigin()).hostname;
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

async function ephemeralLocalSigner(): Promise<LocalSigner> {
  if (!localSigningAllowed()) throw new Error("A production KMS-backed signer is required outside loopback development.");
  const runtime = globalThis as SigningGlobal;
  runtime[localSignerKey] ??= (async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "RSA-PSS", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
    const exportedJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const publicKeyJwk = JSON.parse(JSON.stringify(exportedJwk)) as JsonWebKey;
    if (!isPublicSigningJwk(publicKeyJwk)) throw new Error("The local signer exported an invalid public key.");
    const fingerprint = (await sha256Base64Url(canonicalJson(publicKeyJwk))).slice(0, 16);
    return { privateKey: pair.privateKey, publicKeyJwk, keyId: `cloudpen-local-${fingerprint}` };
  })();
  return runtime[localSignerKey];
}

function isPublicSigningJwk(value: unknown): value is JsonWebKey {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const jwk = value as JsonWebKey;
  return jwk.kty === "RSA" && typeof jwk.n === "string" && typeof jwk.e === "string" && !jwk.d
    && (!jwk.alg || jwk.alg === SIGNING_ALGORITHM) && (!jwk.key_ops || jwk.key_ops.includes("verify"));
}

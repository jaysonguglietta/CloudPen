const encoder = new TextEncoder();

export async function verifyArtifact(payload, artifact, expected, trustedKeyset) {
  const envelope = artifact?.envelope;
  if (!envelope || envelope.schema !== "cloudpen.signed-artifact.v2" || envelope.protocolVersion !== 2) return failure("protocol");
  if (envelope.algorithm !== "PS256") return failure("algorithm");
  if (envelope.domain !== expected.domain || envelope.workspaceId !== expected.workspaceId || envelope.audience !== expected.audience) {
    return failure("scope");
  }
  const key = trustedKeyset?.keys?.find((candidate) => candidate.keyId === envelope.keyId);
  if (!key || key.status === "revoked") return failure("untrusted_key");
  if (key.algorithm !== "PS256" || canonicalJson(key.publicKeyJwk) !== canonicalJson(artifact.publicKeyJwk)) return failure("key_mismatch");
  const now = (expected.now ?? new Date()).valueOf();
  const issued = new Date(envelope.issuedAt).valueOf();
  const expires = new Date(envelope.expiresAt).valueOf();
  const notBefore = key.notBefore ? new Date(key.notBefore).valueOf() : Number.NEGATIVE_INFINITY;
  const notAfter = key.notAfter ? new Date(key.notAfter).valueOf() : Number.POSITIVE_INFINITY;
  if (![issued, expires, notBefore, notAfter].every((value) => Number.isFinite(value) || Math.abs(value) === Infinity)) return failure("time_format");
  if (issued > now + 60_000 || expires <= now || expires <= issued || issued < notBefore || issued >= notAfter) return failure("time_window");
  if (expected.revokedKeyIds?.has(envelope.keyId)) return failure("revoked_key");
  if (expected.consumedNonces?.has(envelope.nonce)) return failure("replay");
  if (envelope.payloadDigest !== await sha256Base64Url(canonicalJson(payload))) return failure("payload_digest");
  if (!isPublicRsaJwk(key.publicKeyJwk) || !/^[A-Za-z0-9_-]{128,1024}$/.test(artifact.signature ?? "")) return failure("key_or_signature_format");
  try {
    const publicKey = await crypto.subtle.importKey("jwk", key.publicKeyJwk, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      fromBase64Url(artifact.signature),
      encoder.encode(canonicalJson(envelope)),
    );
    return valid ? { valid: true, reason: "verified" } : failure("signature");
  } catch {
    return failure("signature_error");
  }
}

export async function verifyBackupDocument(document, expected, trustedKeyset) {
  if (document?.archive?.format !== "cloudpen.workspace-backup.v1" || document.archive.workspaceId !== expected.workspaceId) {
    return failure("backup_scope");
  }
  if (document?.manifest?.schema !== "cloudpen.backup-manifest.v2" || document.manifest.workspaceId !== expected.workspaceId) {
    return failure("manifest_scope");
  }
  const digest = await sha256Base64Url(canonicalJson(document.archive));
  if (digest !== document.manifest.archiveDigest) return failure("archive_digest");
  const actualCounts = Object.fromEntries(Object.entries(document.archive.tables ?? {}).map(([name, rows]) => [name, Array.isArray(rows) ? rows.length : -1]));
  if (canonicalJson(actualCounts) !== canonicalJson(document.manifest.rowCounts)) return failure("row_counts");
  return verifyArtifact(document.manifest, document.integrity, {
    ...expected,
    domain: "cloudpen.backup-manifest.v2",
    audience: "cloudpen-backup-verifier.v1",
  }, trustedKeyset);
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Canonical JSON does not support undefined values.");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

async function sha256Base64Url(value) {
  return toBase64Url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

function toBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function fromBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Invalid base64url value.");
  return Buffer.from(value, "base64url");
}

function isPublicRsaJwk(jwk) {
  return jwk && jwk.kty === "RSA" && typeof jwk.n === "string" && typeof jwk.e === "string" && !jwk.d;
}

function failure(reason) {
  return { valid: false, reason };
}

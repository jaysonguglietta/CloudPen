#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createPublicKey } from "node:crypto";

const [keyId, region] = process.argv.slice(2);
if (!keyId || !region || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) {
  console.error("Usage: node scripts/aws-kms-public-jwk.mjs KEY_ID AWS_REGION");
  process.exit(2);
}
const raw = execFileSync("aws", ["kms", "get-public-key", "--key-id", keyId, "--region", region, "--output", "json"], {
  encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], maxBuffer: 1_000_000,
});
const response = JSON.parse(raw);
if (response.KeyUsage !== "SIGN_VERIFY" || response.KeySpec !== "RSA_3072" || !response.SigningAlgorithms?.includes("RSASSA_PSS_SHA_256")) {
  throw new Error("The KMS key is not an RSA-3072 PS256 signing key.");
}
const der = Buffer.from(response.PublicKey, "base64");
const jwk = createPublicKey({ key: der, format: "der", type: "spki" }).export({ format: "jwk" });
console.log(JSON.stringify({ ...jwk, alg: "PS256", key_ops: ["verify"], use: "sig" }));

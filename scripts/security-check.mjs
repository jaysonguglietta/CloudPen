import assert from "node:assert/strict";
import { access, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

const forbiddenArtifacts = [
  "dist/client/favicon.svg",
  "dist/client/file.svg",
  "dist/client/globe.svg",
  "dist/client/window.svg",
];

for (const file of forbiddenArtifacts) {
  await assert.rejects(access(file), `stale artifact was packaged: ${file}`);
}

const worker = await readFile("dist/server/index.js", "utf8");
const serverBundle = (await readJavaScriptTree("dist/server")).join("\n");
assert.doesNotMatch(worker, /Maya Chen/, "hard-coded operator identity leaked into the server bundle");
assert.match(worker, /Content-Security-Policy/, "security headers are missing from the worker bundle");
assert.match(worker, /script-src-attr 'none'/, "inline script attributes are not blocked");
assert.doesNotMatch(worker, /script-src 'self' 'unsafe-inline'/, "unsafe-inline script execution leaked into CSP");
assert.match(worker, /cloudpen\.security-event\.v1/, "structured security telemetry is missing");
assert.match(worker, /security_event_outbox/, "durable SIEM failure handling is missing");
assert.match(serverBundle, /cloudpen\.signed-artifact\.v2/, "versioned asymmetric artifact signing is missing");
assert.doesNotMatch(serverBundle, /CLOUDPEN_PLAN_SIGNING_KEY/, "legacy shared HMAC signing remains in the deployed worker");
assert.doesNotMatch(worker, /image-size/, "build-only image parser leaked into the deployed worker bundle");
assert.doesNotMatch(worker, /CREATE TABLE IF NOT EXISTS/, "request-time schema creation leaked into the deployed worker bundle");

const localStart = await readFile("scripts/start-local.mjs", "utf8");
assert.match(localStart, /"--ip", "127\.0\.0\.1"/, "local server must bind to loopback");
assert.doesNotMatch(localStart, /0\.0\.0\.0/, "local server must not bind to every interface");
assert.match(localStart, /"d1", "migrations", "apply"/, "local startup must apply D1 migrations before serving traffic");

const codeqlWorkflow = await readFile(".github/workflows/codeql.yml", "utf8");
assert.match(codeqlWorkflow, /security-events: write/, "CodeQL must be able to publish analysis results");
assert.match(codeqlWorkflow, /languages: javascript-typescript/, "CodeQL must scan JavaScript and TypeScript");
assert.doesNotMatch(
  codeqlWorkflow,
  /uses:\s+[^\s@]+@(?![0-9a-f]{40}(?:\s|$))[^\s]+/m,
  "CodeQL workflow actions must be pinned to full commit SHAs",
);

const releaseWorkflow = await readFile(".github/workflows/release-provenance.yml", "utf8");
assert.match(releaseWorkflow, /attestations: write/, "release provenance workflow lacks attestation permission");
assert.match(
  releaseWorkflow,
  /actions\/attest-build-provenance@[0-9a-f]{40}/,
  "release workflow must create a separately verifiable SLSA build-provenance statement",
);
assert.match(releaseWorkflow, /sbom-path:/, "release provenance workflow must attest the SBOM");
assert.match(
  releaseWorkflow,
  /steps\.provenance\.outputs\.bundle-path/,
  "release workflow must retain the build-provenance bundle for offline verification",
);
assert.match(
  releaseWorkflow,
  /steps\.sbom\.outputs\.bundle-path/,
  "release workflow must retain the SBOM-attestation bundle for offline verification",
);
assert.doesNotMatch(
  releaseWorkflow,
  /uses:\s+[^\s@]+@(?![0-9a-f]{40}(?:\s|$))[^\s]+/m,
  "release workflow actions must be pinned to full commit SHAs",
);

const dependabot = await readFile(".github/dependabot.yml", "utf8");
assert.match(dependabot, /package-ecosystem: npm/, "Dependabot must monitor npm dependencies");
assert.match(dependabot, /package-ecosystem: github-actions/, "Dependabot must monitor GitHub Actions");

console.log("Security artifact checks passed.");

async function readJavaScriptTree(directory) {
  const values = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) values.push(...await readJavaScriptTree(path));
    else if (entry.isFile() && entry.name.endsWith(".js")) values.push(await readFile(path, "utf8"));
  }
  return values;
}

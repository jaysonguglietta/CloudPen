import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";

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
assert.doesNotMatch(worker, /Maya Chen/, "hard-coded operator identity leaked into the server bundle");
assert.match(worker, /Content-Security-Policy/, "security headers are missing from the worker bundle");
assert.match(worker, /script-src-attr 'none'/, "inline script attributes are not blocked");
assert.doesNotMatch(worker, /script-src 'self' 'unsafe-inline'/, "unsafe-inline script execution leaked into CSP");
assert.match(worker, /cloudpen\.security-event\.v1/, "structured security telemetry is missing");
assert.doesNotMatch(worker, /image-size/, "build-only image parser leaked into the deployed worker bundle");
assert.doesNotMatch(worker, /CREATE TABLE IF NOT EXISTS/, "request-time schema creation leaked into the deployed worker bundle");

const localStart = await readFile("scripts/start-local.mjs", "utf8");
assert.match(localStart, /"--ip", "127\.0\.0\.1"/, "local server must bind to loopback");
assert.doesNotMatch(localStart, /0\.0\.0\.0/, "local server must not bind to every interface");
assert.match(localStart, /"d1", "migrations", "apply"/, "local startup must apply D1 migrations before serving traffic");

console.log("Security artifact checks passed.");

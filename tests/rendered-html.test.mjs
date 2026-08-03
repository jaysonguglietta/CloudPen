import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

const port = 32000 + (process.pid % 1000);
const origin = `http://127.0.0.1:${port}`;
const identityHeaders = {
  "oai-authenticated-user-email": "admin@example.com",
  "oai-authenticated-user-full-name": "Security%20Administrator",
  "oai-authenticated-user-full-name-encoding": "percent-encoded-utf-8",
};
let server;
let output = "";
let stateDirectory;

before(async () => {
  stateDirectory = await mkdtemp(join(tmpdir(), "cloudpen-security-tests-"));
  server = spawn("./node_modules/.bin/wrangler", [
    "dev",
    "--config", "dist/server/wrangler.json",
    "--ip", "127.0.0.1",
    "--port", String(port),
    "--persist-to", stateDirectory,
    "--var", "CLOUDPEN_ADMIN_EMAILS:admin@example.com",
    "--var", "CLOUDPEN_VIEWER_EMAILS:viewer@example.com",
    "--var", "CLOUDPEN_PLAN_SIGNING_KEY:integration-test-signing-key-with-at-least-32-bytes",
    "--var", `PUBLIC_APP_ORIGIN:${origin}`,
  ], {
    cwd: new URL("..", import.meta.url),
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout.on("data", (chunk) => { output += chunk; });
  server.stderr.on("data", (chunk) => { output += chunk; });

  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${origin}/access-denied`);
      if (response.status === 200) return;
    } catch {
      // Server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`CloudPen test server did not start.\n${output}`);
});

after(async () => {
  if (server && !server.killed) {
    server.kill("SIGTERM");
    await Promise.race([
      new Promise((resolve) => server.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 1_000)),
    ]);
  }
  if (stateDirectory) await rm(stateDirectory, { recursive: true, force: true });
});

async function render(extraHeaders = {}) {
  return fetch(`${origin}/`, {
    headers: { accept: "text/html", ...identityHeaders, ...extraHeaders },
    redirect: "manual",
  });
}

test("requires identity and application membership", async () => {
  const response = await fetch(`${origin}/`, { redirect: "manual" });
  assert.equal(response.status, 307);
  const location = new URL(response.headers.get("location") ?? "", origin);
  assert.equal(location.pathname, "/signin-with-chatgpt");
  assert.equal(location.searchParams.get("return_to"), "/");
});

test("server-renders the authorized CloudPen application shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");

  const html = await response.text();
  assert.match(html, /CloudPen/);
  assert.match(html, /Exposure overview/);
  assert.match(html, /Priority exposure/);
  assert.match(html, /New validation/);
  assert.match(html, /Runner disabled/);
  assert.match(html, /Security Administrator/);
  assert.doesNotMatch(html, /codex-preview/);
});

test("includes accessible navigation and controls", async () => {
  const html = await (await render()).text();
  assert.match(html, /aria-label="Primary navigation"/);
  assert.match(html, /aria-label="Global search"/);
  assert.match(html, /aria-label="Select cloud account"/);
});

test("does not trust Host when generating social metadata", async () => {
  const html = await (await render({ host: "attacker.example" })).text();
  assert.doesNotMatch(html, /attacker\.example\/og\.png/);
  assert.match(html, new RegExp(`${origin.replaceAll("/", "\\/")}\\/og\\.png`));
});

test("rejects cross-origin mutations before business logic", async () => {
  const response = await fetch(`${origin}/api/validation-runs`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin: "https://attacker.example" },
    body: JSON.stringify({ attackPathId: "CP-1042", mode: "Read-only", acknowledged: false }),
  });
  assert.equal(response.status, 403);
});

test("creates a durable signed non-executable plan", async () => {
  const response = await fetch(`${origin}/api/validation-runs`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ attackPathId: "CP-1042", mode: "Read-only", acknowledged: false }),
  });
  const raw = await response.text();
  assert.equal(response.status, 201, raw);
  const body = JSON.parse(raw);
  assert.equal(body.run.status, "Planned");
  assert.equal(body.run.duration, "Not executed");
  assert.equal(body.receipt.executable, false);
  assert.equal(body.receipt.algorithm, "HMAC-SHA-256");
  assert.match(body.receipt.authorizationDigest, /^[A-Za-z0-9_-]{43}$/);
  assert.match(body.receipt.signature, /^[A-Za-z0-9_-]{43}$/);
});

test("holds active canary plans for separate approval", async () => {
  const response = await fetch(`${origin}/api/validation-runs`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ attackPathId: "CP-1037", mode: "Active canary", acknowledged: true }),
  });
  const body = await response.json();
  assert.equal(response.status, 201);
  assert.equal(body.run.status, "Awaiting approval");
  assert.equal(body.receipt.executable, false);
});

test("does not allow core safety guardrails to be disabled", async () => {
  const response = await fetch(`${origin}/api/guardrails`, {
    method: "PATCH",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ canaryOnly: false }),
  });
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /cannot be disabled/i);
});

test("enforces application roles independently of identity", async () => {
  const response = await fetch(`${origin}/api/validation-runs`, {
    method: "POST",
    headers: {
      ...identityHeaders,
      "oai-authenticated-user-email": "viewer@example.com",
      "content-type": "application/json",
      origin,
    },
    body: JSON.stringify({ attackPathId: "CP-1042", mode: "Read-only", acknowledged: false }),
  });
  assert.equal(response.status, 403);
});

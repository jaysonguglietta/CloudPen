import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { BoundedBodyReadError, readBoundedUtf8Stream } from "../lib/security/bounded-body.mjs";

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

describe("CloudPen built Worker", { concurrency: false }, () => {
before(async () => {
  stateDirectory = await mkdtemp(join(tmpdir(), "cloudpen-security-tests-"));
  const migration = spawnSync("./node_modules/.bin/wrangler", [
    "d1", "migrations", "apply", "site-creator-d1",
    "--local",
    "--config", "dist/server/wrangler.json",
    "--persist-to", stateDirectory,
  ], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, WRANGLER_LOG_PATH: join(stateDirectory, "migration.log") },
    encoding: "utf8",
  });
  assert.equal(migration.status, 0, `${migration.stdout ?? ""}\n${migration.stderr ?? ""}`);
  server = spawn("./node_modules/.bin/wrangler", [
    "dev",
    "--config", "dist/server/wrangler.json",
    "--ip", "127.0.0.1",
    "--port", String(port),
    "--persist-to", stateDirectory,
    "--var", "CLOUDPEN_ADMIN_EMAILS:admin@example.com",
    "--var", "CLOUDPEN_VIEWER_EMAILS:viewer@example.com",
    "--var", "CLOUDPEN_REVIEWER_EMAILS:reviewer@example.com",
    "--var", "CLOUDPEN_PLAN_SIGNING_KEY:integration-test-signing-key-with-at-least-32-bytes",
    "--var", `PUBLIC_APP_ORIGIN:${origin}`,
  ], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, WRANGLER_LOG_PATH: join(stateDirectory, "server.log") },
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

test("uses the configured origin for social metadata", async () => {
  const html = await (await render()).text();
  assert.match(html, new RegExp(`${origin.replaceAll("/", "\\/")}\\/og\\.png`));
});

test("rejects identity headers delivered on an alternate origin", async () => {
  const response = await fetch(`http://localhost:${port}/`, {
    headers: { accept: "text/html", ...identityHeaders },
    redirect: "manual",
  });
  assert.equal(response.status, 403);
});

test("rejects cross-origin mutations before business logic", async () => {
  const response = await fetch(`${origin}/api/validation-runs`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin: "https://attacker.example" },
    body: JSON.stringify({ attackPathId: "CP-1042", mode: "Read-only", acknowledged: false }),
  });
  assert.equal(response.status, 403);
});

test("bounds streamed request bodies without retaining bytes over the limit", async () => {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(`{"value":"${"x".repeat(9_000)}"}`));
      controller.close();
    },
  });
  await assert.rejects(
    readBoundedUtf8Stream(body, 8_192),
    (error) => error instanceof BoundedBodyReadError && error.code === "body_size",
  );
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

test("returns explicit demo provenance and authoritative empty workflow records", async () => {
  const response = await fetch(`${origin}/api/control-plane`, { headers: identityHeaders });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.workspace.dataMode, "demo");
  assert.equal(body.auditChainValid, true);
  assert.ok(Array.isArray(body.connectors));
  assert.ok(Array.isArray(body.remediations));
  assert.ok(Array.isArray(body.evidence));
});

test("persists connector records without returning the raw external ID", async () => {
  const externalId = "northstar-integration-secret-value";
  const response = await fetch(`${origin}/api/connectors`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ name: "Payments Production", accountId: "123456789012", externalId }),
  });
  const raw = await response.text();
  assert.equal(response.status, 202, raw);
  const created = JSON.parse(raw);
  assert.equal(created.status, "Runner required");
  assert.match(created.id, /^CON-[A-Z0-9]{8}$/);

  const snapshot = await (await fetch(`${origin}/api/control-plane`, { headers: identityHeaders })).json();
  assert.equal(snapshot.connectors.length, 1);
  assert.equal(snapshot.connectors[0].accountId, "123456789012");
  assert.equal(snapshot.connectors[0].externalIdHint, "••••alue");
  assert.doesNotMatch(JSON.stringify(snapshot), new RegExp(externalId));

  const discovery = await fetch(`${origin}/api/connectors/${created.id}/discovery`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: "{}",
  });
  const discoveryBody = await discovery.json();
  assert.equal(discovery.status, 202);
  assert.equal(discoveryBody.status, "Runner required");
  assert.equal(discoveryBody.scope.executable, false);
});

test("enforces separation of duties for active-plan approval", async () => {
  const create = await fetch(`${origin}/api/validation-runs`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ attackPathId: "CP-1037", mode: "Active canary", acknowledged: true }),
  });
  const created = await create.json();
  assert.equal(create.status, 201);

  const selfApproval = await fetch(`${origin}/api/validation-runs/${created.run.id}`, {
    method: "PATCH",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ decision: "approve", reason: "Authorized integration validation" }),
  });
  assert.equal(selfApproval.status, 400);

  const reviewerHeaders = { ...identityHeaders, "oai-authenticated-user-email": "reviewer@example.com" };
  const approval = await fetch(`${origin}/api/validation-runs/${created.run.id}`, {
    method: "PATCH",
    headers: { ...reviewerHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ decision: "approve", reason: "Scope and canary controls reviewed" }),
  });
  const approved = await approval.json();
  assert.equal(approval.status, 200);
  assert.equal(approved.executable, false);
});

test("creates retained evidence manifests and tracked remediation", async () => {
  const evidence = await fetch(`${origin}/api/evidence/CP-1042`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: "{}",
  });
  const evidenceBody = await evidence.json();
  assert.equal(evidence.status, 200);
  assert.match(evidenceBody.packageId, /^EV-[A-Z0-9]{8}$/);
  assert.equal(evidenceBody.payload.redaction.credentials, "removed");

  const dueAt = new Date(Date.now() + 7 * 86_400_000).toISOString();
  const remediation = await fetch(`${origin}/api/remediations`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ pathId: "CP-1042", owner: "Platform Security", dueAt }),
  });
  const remediationBody = await remediation.json();
  assert.equal(remediation.status, 201);
  assert.equal(remediationBody.remediation.status, "Open");

  const update = await fetch(`${origin}/api/remediations/${remediationBody.remediation.id}`, {
    method: "PATCH",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ status: "In progress" }),
  });
  assert.equal(update.status, 200);

  const snapshot = await (await fetch(`${origin}/api/control-plane`, { headers: identityHeaders })).json();
  assert.equal(snapshot.auditChainValid, true);
  assert.ok(snapshot.evidence.some((item) => item.id === evidenceBody.packageId));
  assert.ok(snapshot.remediations.some((item) => item.id === remediationBody.remediation.id && item.status === "In progress"));
});

test("exports a signed guardrail policy that remains non-executable", async () => {
  const response = await fetch(`${origin}/api/guardrails/export`, { headers: identityHeaders });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.payload.executable, false);
  assert.equal(body.integrity.algorithm, "HMAC-SHA-256");
  assert.match(body.integrity.signature, /^[A-Za-z0-9_-]{43}$/);
});

test("stages runner enrollment without creating an execution capability", async () => {
  const response = await fetch(`${origin}/api/runners`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: JSON.stringify({ name: "Production security runner", publicKeyFingerprint: "a".repeat(64) }),
  });
  const body = await response.json();
  assert.equal(response.status, 201);
  assert.equal(body.runner.status, "Pending");
  assert.equal(body.runner.executable, false);

  const snapshot = await (await fetch(`${origin}/api/control-plane`, { headers: identityHeaders })).json();
  assert.ok(snapshot.runners.some((runner) => runner.id === body.runner.id && runner.executable === false));
});

test("exports a signed assessment with provenance and no execution authority", async () => {
  const response = await fetch(`${origin}/api/reports/export`, {
    method: "POST",
    headers: { ...identityHeaders, "content-type": "application/json", origin },
    body: "{}",
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.payload.schema, "cloudpen.assessment.v1");
  assert.equal(body.payload.assurance.dataMode, "demo");
  assert.equal(body.payload.assurance.executable, false);
  assert.equal(body.payload.assurance.auditChainValid, true);
  assert.match(body.integrity.signature, /^[A-Za-z0-9_-]{43}$/);
});
});

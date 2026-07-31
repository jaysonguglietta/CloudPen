import assert from "node:assert/strict";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the CloudPen application shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /CloudPen/);
  assert.match(html, /Exposure overview/);
  assert.match(html, /Priority exposure/);
  assert.match(html, /New validation/);
  assert.match(html, /Runner connected/);
  assert.doesNotMatch(html, /codex-preview/);
  assert.doesNotMatch(html, /react-loading-skeleton/);
});

test("includes accessible navigation and controls", async () => {
  const html = await (await render()).text();
  assert.match(html, /aria-label="Primary navigation"/);
  assert.match(html, /aria-label="Global search"/);
  assert.match(html, /aria-label="Select cloud account"/);
  assert.match(html, /role="status"|Runner connected/);
});

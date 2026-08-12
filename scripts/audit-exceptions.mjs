import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";

const exception = {
  owner: "CloudPen maintainers",
  expires: "2026-09-30T00:00:00.000Z",
  packages: new Set(["image-size", "vinext"]),
  advisories: new Set([
    "https://github.com/advisories/GHSA-w3rx-r6r6-pgpr",
    "https://github.com/advisories/GHSA-5p2g-fcmc-qvqq",
  ]),
};

assert.ok(Date.now() < Date.parse(exception.expires), `The image parser exception owned by ${exception.owner} has expired.`);
const audit = spawnSync("npm", ["audit", "--json"], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
assert.ok(audit.stdout, audit.stderr || "npm audit did not return JSON.");
const report = JSON.parse(audit.stdout);
const vulnerabilities = Object.entries(report.vulnerabilities ?? {})
  .filter(([, value]) => value.severity === "high" || value.severity === "critical");

for (const [name, vulnerability] of vulnerabilities) {
  assert.ok(exception.packages.has(name), `Unapproved ${vulnerability.severity} advisory affects ${name}.`);
  for (const via of vulnerability.via ?? []) {
    if (typeof via === "string") {
      assert.ok(exception.packages.has(via), `Unapproved indirect advisory ${via} affects ${name}.`);
    } else {
      assert.ok(exception.advisories.has(via.url), `Unapproved advisory ${via.url} affects ${name}.`);
    }
  }
}

const packageJson = JSON.parse(await readFile("package.json", "utf8"));
assert.ok(packageJson.devDependencies?.vinext, "Vinext must remain a development-only build dependency.");
const worker = await readFile("dist/server/index.js", "utf8");
assert.doesNotMatch(worker, /image-size/, "The excepted parser must not be present in the deployed Worker.");

console.log(`Approved build-only audit exception is valid through ${exception.expires}; no other High/Critical advisories found.`);

import assert from "node:assert/strict";
import { access, readdir, readFile } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";

const root = process.cwd();
const ignoredDirectories = new Set([".git", ".next", ".wrangler", "dist", "node_modules"]);

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isDirectory() && !ignoredDirectories.has(entry.name)) {
      files.push(...await markdownFiles(resolve(directory, entry.name)));
    } else if (entry.isFile() && extname(entry.name).toLowerCase() === ".md") {
      files.push(resolve(directory, entry.name));
    }
  }
  return files;
}

const files = await markdownFiles(root);
assert(files.length >= 10, "expected the repository documentation set");

const failures = [];
for (const file of files) {
  const source = await readFile(file, "utf8");
  const links = source.matchAll(/\[[^\]]*\]\(([^)]+)\)/g);
  for (const match of links) {
    const destination = match[1].trim().replace(/^<|>$/g, "");
    if (!destination || destination.startsWith("#") || /^[a-z][a-z0-9+.-]*:/i.test(destination)) continue;
    const filePart = decodeURIComponent(destination.split("#", 1)[0]);
    if (!filePart) continue;
    const target = resolve(dirname(file), filePart);
    try {
      await access(target);
    } catch {
      failures.push(`${file.slice(root.length + 1)} -> ${destination}`);
    }
  }
}

assert.deepEqual(failures, [], `broken documentation links:\n${failures.join("\n")}`);
console.log(`Documentation checks passed for ${files.length} Markdown files.`);

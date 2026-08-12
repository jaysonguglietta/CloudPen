#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { verifyBackupDocument } from "./lib/artifact-verifier.mjs";

const values = process.argv.slice(2);
const documentPath = values[0];
const keysetIndex = values.indexOf("--keyset");
const workspaceIndex = values.indexOf("--workspace");
if (!documentPath || keysetIndex < 0 || workspaceIndex < 0 || !values[keysetIndex + 1] || !values[workspaceIndex + 1]) {
  console.error("Usage: npm run verify:backup -- BACKUP.json --keyset TRUSTED-KEYSET.json --workspace WORKSPACE");
  process.exitCode = 2;
} else {
  const document = JSON.parse(await readFile(documentPath, "utf8"));
  const keyset = JSON.parse(await readFile(values[keysetIndex + 1], "utf8"));
  const result = await verifyBackupDocument(document, { workspaceId: values[workspaceIndex + 1] }, keyset);
  console.log(JSON.stringify(result));
  if (!result.valid) process.exitCode = 1;
}

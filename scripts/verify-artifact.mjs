#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { verifyArtifact } from "./lib/artifact-verifier.mjs";

const options = parseArguments(process.argv.slice(2));
if (!options.document || !options.keyset || !options.domain || !options.workspace || !options.audience) {
  console.error("Usage: npm run verify:artifact -- DOCUMENT.json --keyset TRUSTED-KEYSET.json --domain DOMAIN --workspace WORKSPACE --audience AUDIENCE [--payload-key payload|manifest]");
  process.exitCode = 2;
} else {
  const document = JSON.parse(await readFile(options.document, "utf8"));
  const keyset = JSON.parse(await readFile(options.keyset, "utf8"));
  const payloadKey = options.payloadKey ?? ("payload" in document ? "payload" : "manifest");
  const artifact = document.integrity ?? document.receipt;
  const result = await verifyArtifact(document[payloadKey], artifact, {
    domain: options.domain,
    workspaceId: options.workspace,
    audience: options.audience,
  }, keyset);
  console.log(JSON.stringify(result));
  if (!result.valid) process.exitCode = 1;
}

function parseArguments(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("-") && !result.document) result.document = value;
    else if (value === "--keyset") result.keyset = values[++index];
    else if (value === "--domain") result.domain = values[++index];
    else if (value === "--workspace") result.workspace = values[++index];
    else if (value === "--audience") result.audience = values[++index];
    else if (value === "--payload-key") result.payloadKey = values[++index];
    else throw new Error(`Unknown argument: ${value}`);
  }
  return result;
}

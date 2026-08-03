import { rm } from "node:fs/promises";
import { basename, resolve } from "node:path";

const output = resolve(process.cwd(), "dist");

if (basename(output) !== "dist" || output === resolve("/", "dist")) {
  throw new Error(`Refusing to clean unexpected output path: ${output}`);
}

await rm(output, { force: true, recursive: true });

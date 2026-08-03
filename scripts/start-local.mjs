import { spawn } from "node:child_process";
import { resolve } from "node:path";

const wrangler = resolve("node_modules/wrangler/bin/wrangler.js");
const config = resolve("dist/server/wrangler.json");
const persistence = resolve(".wrangler/state");

const child = spawn(process.execPath, [
  wrangler,
  "dev",
  "--config", config,
  "--ip", "127.0.0.1",
  "--port", "8787",
  "--persist-to", persistence,
  "--var", "CLOUDPEN_LOCAL_MODE:1",
  "--var", "PUBLIC_APP_ORIGIN:http://127.0.0.1:8787",
], {
  env: {
    ...process.env,
    WRANGLER_LOG_PATH: resolve(".wrangler/wrangler.log"),
  },
  stdio: "inherit",
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});

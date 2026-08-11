export type CloudPenRole = "admin" | "operator" | "reviewer" | "viewer";

export type RuntimeBindings = {
  DB?: D1Database;
  CLOUDPEN_ADMIN_EMAILS?: string;
  CLOUDPEN_OPERATOR_EMAILS?: string;
  CLOUDPEN_REVIEWER_EMAILS?: string;
  CLOUDPEN_VIEWER_EMAILS?: string;
  CLOUDPEN_LOCAL_DEV_EMAIL?: string;
  CLOUDPEN_LOCAL_MODE?: string;
  CLOUDPEN_PLAN_SIGNING_KEY?: string;
  PUBLIC_APP_ORIGIN?: string;
};

const bindingKey = Symbol.for("cloudpen.runtime.bindings");
const localSigningKeyKey = Symbol.for("cloudpen.runtime.local-signing-key");
type RuntimeGlobal = typeof globalThis & {
  [bindingKey]?: RuntimeBindings;
  [localSigningKeyKey]?: string;
};

export function installRuntimeBindings(bindings: RuntimeBindings): void {
  (globalThis as RuntimeGlobal)[bindingKey] = bindings;
}

export function runtimeBindings(): RuntimeBindings {
  const installed = (globalThis as RuntimeGlobal)[bindingKey] ?? {};
  return {
    ...process.env,
    ...installed,
  } as RuntimeBindings;
}

export function configuredOrigin(): string {
  const configured = runtimeBindings().PUBLIC_APP_ORIGIN?.trim();
  if (!configured) {
    return process.env.NODE_ENV === "production"
      ? "https://cloudpen-validation.jayson-guglietta.chatgpt.site"
      : "http://127.0.0.1:3000";
  }

  const url = new URL(configured);
  if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.pathname !== "/") {
    throw new Error("PUBLIC_APP_ORIGIN must be an absolute HTTP(S) origin without credentials or a path.");
  }
  return url.origin;
}

export function signingKey(): string {
  const configured = runtimeBindings().CLOUDPEN_PLAN_SIGNING_KEY?.trim();
  if (configured && configured.length >= 32) return configured;

  if (runtimeBindings().CLOUDPEN_LOCAL_MODE === "1") {
    const runtime = globalThis as RuntimeGlobal;
    runtime[localSigningKeyKey] ??= randomBase64Url(32);
    return runtime[localSigningKeyKey];
  }

  throw new Error("CLOUDPEN_PLAN_SIGNING_KEY is not configured.");
}

function randomBase64Url(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function roleForEmail(email: string): CloudPenRole | null {
  const normalized = email.trim().toLowerCase();
  const bindings = runtimeBindings();
  const lists: Array<[CloudPenRole, string | undefined]> = [
    ["admin", bindings.CLOUDPEN_ADMIN_EMAILS],
    ["operator", bindings.CLOUDPEN_OPERATOR_EMAILS],
    ["reviewer", bindings.CLOUDPEN_REVIEWER_EMAILS],
    ["viewer", bindings.CLOUDPEN_VIEWER_EMAILS],
  ];

  for (const [role, value] of lists) {
    if (parseEmailList(value).has(normalized)) return role;
  }
  return null;
}

function parseEmailList(value: string | undefined): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),
  );
}

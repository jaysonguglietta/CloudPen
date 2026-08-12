export type CloudPenRole = "admin" | "operator" | "reviewer" | "viewer";

export type RuntimeBindings = {
  DB?: D1Database;
  CLOUDPEN_ADMIN_EMAILS?: string;
  CLOUDPEN_OPERATOR_EMAILS?: string;
  CLOUDPEN_REVIEWER_EMAILS?: string;
  CLOUDPEN_VIEWER_EMAILS?: string;
  CLOUDPEN_LOCAL_DEV_EMAIL?: string;
  CLOUDPEN_LOCAL_MODE?: string;
  CLOUDPEN_WORKSPACE_ID?: string;
  CLOUDPEN_EPHEMERAL_SIGNER?: string;
  CLOUDPEN_SIGNER_URL?: string;
  CLOUDPEN_SIGNER_TOKEN?: string;
  CLOUDPEN_SIGNING_KEY_ID?: string;
  CLOUDPEN_SIGNING_PUBLIC_JWK?: string;
  CLOUDPEN_SIEM_URL?: string;
  CLOUDPEN_SIEM_TOKEN?: string;
  CLOUDPEN_PRODUCTION_MODE?: string;
  PUBLIC_APP_ORIGIN?: string;
};

const bindingKey = Symbol.for("cloudpen.runtime.bindings");
type RuntimeGlobal = typeof globalThis & {
  [bindingKey]?: RuntimeBindings;
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

export function configuredWorkspaceId(): string {
  const value = runtimeBindings().CLOUDPEN_WORKSPACE_ID?.trim() || "northstar-labs";
  if (!/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(value)) {
    throw new Error("CLOUDPEN_WORKSPACE_ID must be a 3–64 character lowercase workspace slug.");
  }
  return value;
}

export function productionRuntimeProblems(bindings: RuntimeBindings = runtimeBindings()): string[] {
  const problems: string[] = [];
  if (!bindings.DB) problems.push("durable_database");
  let origin: URL | null = null;
  try { origin = new URL(bindings.PUBLIC_APP_ORIGIN?.trim() ?? ""); } catch { problems.push("canonical_https_origin"); }
  if (origin && (origin.protocol !== "https:" || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash)) {
    problems.push("canonical_https_origin");
  }
  if (bindings.CLOUDPEN_LOCAL_MODE === "1") problems.push("local_mode_disabled");
  if (bindings.CLOUDPEN_EPHEMERAL_SIGNER === "1") problems.push("ephemeral_signer_disabled");
  if (!validExactHttpsEndpoint(bindings.CLOUDPEN_SIGNER_URL, "/v1/sign")) problems.push("external_signer");
  if ((bindings.CLOUDPEN_SIGNER_TOKEN?.trim().length ?? 0) < 32) problems.push("signer_token");
  if (!/^[A-Za-z0-9._:/-]{8,200}$/.test(bindings.CLOUDPEN_SIGNING_KEY_ID?.trim() ?? "")) problems.push("signing_key_id");
  if (!validPublicJwk(bindings.CLOUDPEN_SIGNING_PUBLIC_JWK)) problems.push("signing_public_key");
  if (!validExactHttpsEndpoint(bindings.CLOUDPEN_SIEM_URL, "/v1/events")) problems.push("siem_endpoint");
  if ((bindings.CLOUDPEN_SIEM_TOKEN?.trim().length ?? 0) < 32) problems.push("siem_token");
  return [...new Set(problems)];
}

function validExactHttpsEndpoint(raw: string | undefined, pathname: string): boolean {
  if (!raw) return false;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && url.pathname === pathname;
  } catch {
    return false;
  }
}

function validPublicJwk(raw: string | undefined): boolean {
  if (!raw) return false;
  try {
    const jwk = JSON.parse(raw) as JsonWebKey;
    return jwk.kty === "RSA" && typeof jwk.n === "string" && typeof jwk.e === "string" && !jwk.d;
  } catch {
    return false;
  }
}

function parseEmailList(value: string | undefined): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),
  );
}

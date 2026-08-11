/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";
import { AUTHENTICATED_USER_EMAIL_HEADER, LOCAL_IDENTITY_VERIFIED_HEADER } from "../lib/security/headers";
import { configuredOrigin, installRuntimeBindings, roleForEmail, type RuntimeBindings } from "../lib/security/runtime";

interface Env extends RuntimeBindings {
  ASSETS: Fetcher;
  DB?: D1Database;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const startedAt = Date.now();
    const requestId = crypto.randomUUID();
    installRuntimeBindings(env);
    const prepared = prepareTrustedRequest(request, env, requestId);
    let response: Response;

    if (prepared instanceof Response) {
      response = prepared;
    } else {
      const url = new URL(prepared.url);

      if (url.pathname === "/_vinext/image") {
        const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
        response = await handleImageOptimization(prepared, {
          fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, prepared.url))),
          transformImage: async (body, { width, format, quality }) => {
            const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
            return result.response();
          },
        }, allowedWidths);
      } else {
        response = await handler.fetch(prepared, env, ctx);
      }
    }

    const category = response.headers.get("x-cloudpen-security-event") ?? categoryForStatus(response.status);
    const hardened = hardenResponse(prepared instanceof Response ? request : prepared, response, requestId);
    ctx.waitUntil(emitRequestTelemetry(request, env, requestId, response.status, category, Date.now() - startedAt));
    return hardened;
  },
};

function prepareTrustedRequest(request: Request, env: Env, requestId: string): Request | Response {
  const url = new URL(request.url);
  const headers = new Headers(request.headers);
  headers.delete(LOCAL_IDENTITY_VERIFIED_HEADER);
  headers.delete("x-cloudpen-request-id");
  headers.set("x-cloudpen-request-id", requestId);

  if (headers.has(AUTHENTICATED_USER_EMAIL_HEADER) && url.origin !== configuredOrigin()) {
    return new Response("Identity is not trusted on this origin.", {
      status: 403,
      headers: { "x-cloudpen-security-event": "identity_origin_denied" },
    });
  }

  if (env.CLOUDPEN_LOCAL_MODE === "1") {
    if (!isLoopbackHostname(url.hostname)) {
      return new Response("Local mode is restricted to the loopback interface.", {
        status: 403,
        headers: { "x-cloudpen-security-event": "local_mode_network_denied" },
      });
    }
    headers.set(LOCAL_IDENTITY_VERIFIED_HEADER, "1");
  }

  return new Request(request, { headers });
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]" || hostname === "::1";
}

function hardenResponse(request: Request, response: Response, requestId: string): Response {
  let securedResponse = response;
  let headers = new Headers(securedResponse.headers);
  const contentType = headers.get("content-type") ?? "";
  const isHtml = contentType.toLowerCase().startsWith("text/html");
  let scriptNonce: string | null = null;

  if (isHtml) {
    scriptNonce = randomNonce();
    securedResponse = new HTMLRewriter()
      .on("script", {
        element(element) {
          element.setAttribute("nonce", scriptNonce!);
        },
      })
      .transform(securedResponse);
    headers = new Headers(securedResponse.headers);
  }

  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.delete("server");
  headers.delete("x-powered-by");
  headers.delete("x-cloudpen-security-event");
  headers.set("x-request-id", requestId);

  if (isHtml) {
    const policy = [
      "default-src 'self'",
      "base-uri 'none'",
      "connect-src 'self'",
      "font-src 'self' data:",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "img-src 'self' data: blob:",
      "object-src 'none'",
      `script-src 'nonce-${scriptNonce}' 'strict-dynamic'`,
      "script-src-attr 'none'",
      "style-src 'self' 'unsafe-inline'",
    ];
    if (new URL(request.url).protocol === "https:") policy.push("upgrade-insecure-requests");
    headers.set("content-security-policy", policy.join("; "));
  }

  if (new URL(request.url).protocol === "https:") {
    headers.set("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
  }
  if (new URL(request.url).pathname.startsWith("/api/")) {
    headers.set("cache-control", "no-store, private");
  }

  return new Response(securedResponse.body, { status: securedResponse.status, statusText: securedResponse.statusText, headers });
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function emitRequestTelemetry(
  request: Request,
  env: Env,
  requestId: string,
  status: number,
  category: string,
  durationMs: number,
): Promise<void> {
  const url = new URL(request.url);
  const email = request.headers.get(AUTHENTICATED_USER_EMAIL_HEADER)?.trim().toLowerCase() ?? null;
  const actorId = email ? (await sha256Text(email)).slice(0, 16) : null;
  console.log(JSON.stringify({
    schema: "cloudpen.security-event.v1",
    timestamp: new Date().toISOString(),
    requestId,
    category,
    method: request.method,
    route: routeTemplate(url.pathname),
    status,
    outcome: status < 400 ? "allowed" : "denied",
    actorId,
    role: email ? roleForEmail(email) : null,
    capability: capabilityFor(request.method, url.pathname),
    durationMs,
    localMode: env.CLOUDPEN_LOCAL_MODE === "1",
  }));
}

function categoryForStatus(status: number): string {
  if (status === 409) return "state_conflict";
  if (status === 413) return "body_size_denied";
  if (status === 429) return "rate_limit_denied";
  if (status === 401 || status === 403) return "authorization_denied";
  if (status >= 500) return "internal_failure";
  return "request_completed";
}

function routeTemplate(pathname: string): string {
  return pathname
    .replace(/\/(?:CON|RUN|REM|EV)-[A-Z0-9]{8}(?=\/|$)/g, "/:id")
    .replace(/\/CP-\d{4}(?=\/|$)/g, "/:pathId");
}

function capabilityFor(method: string, pathname: string): string | null {
  if (!pathname.startsWith("/api/")) return null;
  if (pathname.startsWith("/api/guardrails") && method === "PATCH") return "configure";
  if (pathname.startsWith("/api/runners")) return "enroll";
  if (pathname.startsWith("/api/connectors")) return "connect";
  if (pathname.startsWith("/api/validation-runs") && method === "PATCH") return "approve-or-plan";
  if (pathname.startsWith("/api/remediations") && method !== "GET") return "governed-remediation";
  if (method === "GET" || pathname.includes("/export") || pathname.startsWith("/api/evidence")) return "read";
  return "plan";
}

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export default worker;

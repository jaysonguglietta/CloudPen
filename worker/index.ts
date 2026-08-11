/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";
import { AUTHENTICATED_USER_EMAIL_HEADER, LOCAL_IDENTITY_VERIFIED_HEADER } from "../lib/security/headers";
import { configuredOrigin, installRuntimeBindings, type RuntimeBindings } from "../lib/security/runtime";

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
    installRuntimeBindings(env);
    const prepared = prepareTrustedRequest(request, env);
    if (prepared instanceof Response) return hardenResponse(request, prepared);
    const url = new URL(prepared.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      const response = await handleImageOptimization(prepared, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, prepared.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
      return hardenResponse(prepared, response);
    }

    return hardenResponse(prepared, await handler.fetch(prepared, env, ctx));
  },
};

function prepareTrustedRequest(request: Request, env: Env): Request | Response {
  const url = new URL(request.url);
  const headers = new Headers(request.headers);
  headers.delete(LOCAL_IDENTITY_VERIFIED_HEADER);

  if (headers.has(AUTHENTICATED_USER_EMAIL_HEADER) && url.origin !== configuredOrigin()) {
    return new Response("Identity is not trusted on this origin.", { status: 403 });
  }

  if (env.CLOUDPEN_LOCAL_MODE === "1") {
    if (!isLoopbackHostname(url.hostname)) {
      return new Response("Local mode is restricted to the loopback interface.", { status: 403 });
    }
    headers.set(LOCAL_IDENTITY_VERIFIED_HEADER, "1");
  }

  return new Request(request, { headers });
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]" || hostname === "::1";
}

function hardenResponse(request: Request, response: Response): Response {
  const headers = new Headers(response.headers);
  const contentType = headers.get("content-type") ?? "";
  const isHtml = contentType.toLowerCase().startsWith("text/html");

  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.delete("server");
  headers.delete("x-powered-by");

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
      "script-src 'self' 'unsafe-inline'",
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

  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default worker;

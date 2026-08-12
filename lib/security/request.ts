import { BoundedBodyReadError, readBoundedUtf8Stream } from "./bounded-body.mjs";

const MAX_JSON_BYTES = 8_192;

export class RequestSecurityError extends Error {
  constructor(public readonly status: 400 | 403 | 404 | 409 | 413 | 415 | 429, message: string) {
    super(message);
  }
}

export function enforceMutationRequest(request: Request): void {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new RequestSecurityError(415, "Requests must use application/json.");
  }

  const rawContentLength = request.headers.get("content-length");
  if (rawContentLength !== null) {
    if (!/^\d+$/.test(rawContentLength)) {
      throw new RequestSecurityError(400, "Content-Length must be a non-negative integer.");
    }
    const contentLength = Number(rawContentLength);
    if (!Number.isSafeInteger(contentLength)) {
      throw new RequestSecurityError(400, "Content-Length is invalid.");
    }
    if (contentLength > MAX_JSON_BYTES) {
      throw new RequestSecurityError(413, "Request body is too large.");
    }
  }

  const origin = request.headers.get("origin");
  if (!origin || origin !== new URL(request.url).origin) {
    throw new RequestSecurityError(403, "Cross-origin mutation requests are not allowed.");
  }

  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin") {
    throw new RequestSecurityError(403, "Cross-site mutation requests are not allowed.");
  }
}

export async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  let text: string;
  try {
    text = await readBoundedUtf8Stream(request.body, MAX_JSON_BYTES);
  } catch (error) {
    if (error instanceof BoundedBodyReadError) {
      if (error.code === "body_size") {
        throw new RequestSecurityError(413, error.message);
      }
      throw new RequestSecurityError(400, error.message);
    }
    throw error;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new RequestSecurityError(400, "Malformed JSON request body.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new RequestSecurityError(400, "A JSON object is required.");
  }
  return value as Record<string, unknown>;
}

export function safeApiError(error: unknown): Response {
  if (error instanceof RequestSecurityError) {
    const category = error.status === 413 ? "body_size_denied"
      : error.status === 403 ? "cross_origin_denied"
      : "request_validation_denied";
    return Response.json({ error: error.message }, {
      status: error.status,
      headers: { "x-cloudpen-security-event": category },
    });
  }
  const candidateStatus = error && typeof error === "object" && "status" in error ? Number(error.status) : 500;
  const status = [400, 401, 403, 404, 409, 413, 415, 429].includes(candidateStatus) ? candidateStatus : 500;
  const message = status === 500 ? "The request could not be completed." : (error as Error).message;
  console.error("CloudPen API request failed", {
    name: error instanceof Error ? error.name : "UnknownError",
    message: error instanceof Error ? sanitizeDiagnostic(error.message) : "Unknown failure",
    status,
  });
  const category = status === 429 ? "rate_limit_denied"
    : status === 409 ? "state_conflict"
    : status === 401 || status === 403 ? "authorization_denied"
    : status >= 500 ? "internal_failure"
    : "request_validation_denied";
  return Response.json({ error: message }, {
    status,
    headers: { "x-cloudpen-security-event": category },
  });
}

function sanitizeDiagnostic(value: string): string {
  return value.replace(/[\r\n\t]/g, " ").replace(/\s+/g, " ").slice(0, 240);
}

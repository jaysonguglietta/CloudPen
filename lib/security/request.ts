const MAX_JSON_BYTES = 8_192;
const MAX_SCREENSHOT_UPLOAD_BYTES = 13 * 1024 * 1024;

export class RequestSecurityError extends Error {
  constructor(public readonly status: 400 | 403 | 404 | 409 | 413 | 415 | 429, message: string) {
    super(message);
  }
}

export function enforceMutationRequest(request: Request): void {
  enforceSameOriginRequest(request);
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new RequestSecurityError(415, "Requests must use application/json.");
  }

  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BYTES) {
    throw new RequestSecurityError(413, "Request body is too large.");
  }

}

export function enforceScreenshotUploadRequest(request: Request): void {
  enforceSameOriginRequest(request);
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("multipart/form-data;")) {
    throw new RequestSecurityError(415, "Screenshot uploads must use multipart/form-data.");
  }
  const contentLengthHeader = request.headers.get("content-length");
  if (contentLengthHeader) {
    const contentLength = Number(contentLengthHeader);
    if (!Number.isFinite(contentLength) || contentLength < 1) {
      throw new RequestSecurityError(400, "Invalid upload content length.");
    }
    if (contentLength > MAX_SCREENSHOT_UPLOAD_BYTES) {
      throw new RequestSecurityError(413, "Screenshot upload is too large.");
    }
  }
}

function enforceSameOriginRequest(request: Request): void {
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
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_JSON_BYTES) {
    throw new RequestSecurityError(413, "Request body is too large.");
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
    return Response.json({ error: error.message }, { status: error.status });
  }
  const candidateStatus = error && typeof error === "object" && "status" in error ? Number(error.status) : 500;
  const status = [400, 401, 403, 404, 409, 413, 415, 429].includes(candidateStatus) ? candidateStatus : 500;
  const message = status === 500 ? "The request could not be completed." : (error as Error).message;
  console.error("CloudPen API request failed", {
    name: error instanceof Error ? error.name : "UnknownError",
    status,
  });
  return Response.json({ error: message }, { status });
}

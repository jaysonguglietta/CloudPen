export class BoundedBodyReadError extends Error {
  constructor(code) {
    super(code === "body_size" ? "Request body is too large."
      : code === "utf8" ? "Request body must be valid UTF-8."
      : "Request body could not be read.");
    this.name = "BoundedBodyReadError";
    this.code = code;
  }
}

export async function readBoundedUtf8Stream(stream, maxBytes) {
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  let exceededLimit = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (exceededLimit) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        exceededLimit = true;
        chunks.length = 0;
        continue;
      }
      chunks.push(value);
    }
  } catch {
    throw new BoundedBodyReadError(exceededLimit ? "body_size" : "body_read");
  }

  if (exceededLimit) throw new BoundedBodyReadError("body_size");

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new BoundedBodyReadError("utf8");
  }
}

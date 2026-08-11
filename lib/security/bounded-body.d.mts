export type BoundedBodyErrorCode = "body_size" | "body_read" | "utf8";

export class BoundedBodyReadError extends Error {
  readonly code: BoundedBodyErrorCode;
  constructor(code: BoundedBodyErrorCode);
}

export function readBoundedUtf8Stream(
  stream: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<string>;

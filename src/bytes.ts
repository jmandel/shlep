const enc = new TextEncoder();

type ByteChunk = string | ArrayBuffer | ArrayBufferView;

function hasMethod<T extends string>(value: unknown, method: T): value is Record<T, (...args: never[]) => unknown> {
  return value != null && typeof (value as Record<T, unknown>)[method] === "function";
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return value != null && typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function";
}

function isReadableStream(value: unknown): value is ReadableStream<Uint8Array> {
  return typeof ReadableStream !== "undefined" && value instanceof ReadableStream;
}

export function bytesFromChunk(chunk: ByteChunk): Uint8Array {
  if (typeof chunk === "string") return enc.encode(chunk);
  if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk);
  if (ArrayBuffer.isView(chunk)) return new Uint8Array(chunk.buffer as ArrayBuffer, chunk.byteOffset, chunk.byteLength);
  throw new TypeError("expected a byte chunk");
}

export function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export async function bodyToBytes(body: unknown): Promise<Uint8Array> {
  if (body == null) return new Uint8Array(0);
  if (typeof body === "string" || body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return bytesFromChunk(body);

  if (hasMethod(body, "transformToByteArray")) {
    return bytesFromChunk((await body.transformToByteArray()) as ByteChunk);
  }
  if (hasMethod(body, "arrayBuffer")) {
    return new Uint8Array((await body.arrayBuffer()) as ArrayBuffer);
  }
  if (isReadableStream(body)) {
    return new Uint8Array(await new Response(body).arrayBuffer());
  }
  if (isAsyncIterable(body)) {
    const chunks: Uint8Array[] = [];
    for await (const chunk of body) chunks.push(bytesFromChunk(chunk as ByteChunk));
    return concatBytes(chunks);
  }

  throw new TypeError("unsupported byte body");
}

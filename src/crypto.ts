/**
 * crypto.ts — compact JWE (alg "dir", enc "A256GCM") + small helpers, ported
 * from the IG's viewer-src/jwe.mjs so ciphertext round-trips with the existing
 * viewer (shl.mjs) byte-for-byte. WebCrypto + CompressionStream only, so it runs
 * unchanged in Bun, Node, Deno, and the browser.
 *
 * ONE DELIBERATE DIVERGENCE from jwe.mjs: encryptCompact defaults `deflate` to
 * FALSE here (jwe.mjs defaults true). The SHL guidance is "uncompressed for
 * unknown viewers" because some `jose` builds dropped JWE `zip`. Callers wiring
 * encryptCompact directly should know the manager passes deflate=false by default.
 *
 * WebCrypto + standard globals only — no Node built-ins — so this bundles for the
 * browser landing-page demo as-is.
 */
const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = globalThis.crypto.subtle;

export function b64uFromBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function bytesFromB64u(b64u: string): Uint8Array {
  const s = atob(b64u.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
const b64uFromStr = (str: string) => b64uFromBytes(enc.encode(str));

/** 32 random bytes = an A256GCM key. */
export function genKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}
/** Unguessable id. 16 bytes = 128 bits, ~22 url-safe chars (keeps shlink `url` short). */
export function randomId(bytes = 16): string {
  return b64uFromBytes(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}
/** High-entropy bearer secret (manage token / ticket key material). */
export function randomToken(bytes = 32): string {
  return b64uFromBytes(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256Hex(input: string): Promise<string> {
  const d = new Uint8Array(await subtle.digest("SHA-256", enc.encode(input)));
  let h = "";
  for (const b of d) h += b.toString(16).padStart(2, "0");
  return h;
}
/** Constant-time compare of two equal-length hex strings (no Node built-ins). */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
/** HMAC-SHA256 hex (used for location-rail tickets). */
export async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await subtle.sign("HMAC", key, enc.encode(message)));
  let h = "";
  for (const b of sig) h += b.toString(16).padStart(2, "0");
  return h;
}

async function pipe(bytes: Uint8Array, mode: "deflate" | "inflate"): Promise<Uint8Array> {
  const stream = mode === "deflate" ? new CompressionStream("deflate-raw") : new DecompressionStream("deflate-raw");
  const w = stream.writable.getWriter();
  w.write(bytes);
  w.close();
  return new Uint8Array(await new Response(stream.readable).arrayBuffer());
}
async function importAesKey(keyBytes: Uint8Array) {
  if (keyBytes.length !== 32) throw new Error(`A256GCM key must be 32 bytes, got ${keyBytes.length}`);
  return subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export interface EncryptOptions {
  deflate?: boolean; // default false (see file header)
  contentType?: string;
}

export async function encryptCompact(plaintext: string, keyBytes: Uint8Array, opts: EncryptOptions = {}): Promise<string> {
  const deflate = opts.deflate === true;
  const contentType = opts.contentType || "application/fhir+json";
  const key = await importAesKey(keyBytes);
  const header = { alg: "dir", enc: "A256GCM", ...(deflate ? { zip: "DEF" } : {}), cty: contentType };
  const protectedB64 = b64uFromStr(JSON.stringify(header));
  let payload = enc.encode(plaintext);
  if (deflate) payload = await pipe(payload, "deflate");
  // SHL requires a unique nonce per encryption (the key may be reused across a
  // link's files/updates). We always generate a fresh random 96-bit IV — there
  // is deliberately no way to pin it, so nonce reuse is structurally impossible.
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ctAndTag = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(protectedB64), tagLength: 128 }, key, payload),
  );
  const ct = ctAndTag.slice(0, ctAndTag.length - 16);
  const tag = ctAndTag.slice(ctAndTag.length - 16);
  return [protectedB64, "", b64uFromBytes(iv), b64uFromBytes(ct), b64uFromBytes(tag)].join(".");
}

export async function decryptCompact(jwe: string, keyBytes: Uint8Array): Promise<string> {
  const [protectedB64, , ivB64, ctB64, tagB64] = jwe.trim().split(".");
  if (!protectedB64 || !ivB64 || !ctB64 || tagB64 == null) throw new Error("malformed compact JWE");
  const header = JSON.parse(dec.decode(bytesFromB64u(protectedB64)));
  const key = await importAesKey(keyBytes);
  const iv = bytesFromB64u(ivB64);
  const ct = bytesFromB64u(ctB64);
  const tag = bytesFromB64u(tagB64);
  const data = new Uint8Array(ct.length + tag.length);
  data.set(ct);
  data.set(tag, ct.length);
  let plain = new Uint8Array(
    await subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode(protectedB64), tagLength: 128 }, key, data),
  );
  if (header.zip === "DEF") plain = await pipe(plain, "inflate");
  return dec.decode(plain);
}

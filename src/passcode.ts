/**
 * passcode.ts — passcode hashing for the optional access gate, using WebCrypto
 * PBKDF2 (salted, iterated). WebCrypto-only — no node:crypto — so the manager and
 * handler run on any Web-standard runtime (Bun, Node, Deno, Cloudflare Workers).
 *
 * Stored format: `pbkdf2$<iterations>$<salt b64url>$<hash b64url>`. The per-share
 * salt defeats rainbow tables / cross-share correlation; the iteration count slows
 * offline brute force. A passcode is a host-enforced gate on retrieving the
 * still-encrypted ciphertext, so this hash is defense-in-depth against sidecar
 * exfiltration (see docs/api-design.md §7), and the small online attempt budget is
 * the primary brute-force defense. PBKDF2 is the strongest KDF in WebCrypto
 * (scrypt/argon2 aren't available there); we trade memory-hardness for portability.
 */
import { b64uFromBytes, bytesFromB64u, timingSafeEqualHex } from "./crypto";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const ITERATIONS = 210_000; // OWASP PBKDF2-HMAC-SHA256 guidance
const KEYLEN = 32;
const bs = (u: Uint8Array): BufferSource => u as BufferSource;

async function derive(passcode: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await subtle.importKey("raw", bs(enc.encode(passcode)), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: bs(salt), iterations }, key, KEYLEN * 8);
  return new Uint8Array(bits);
}

export async function hashPasscode(passcode: string): Promise<string> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const dk = await derive(passcode, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${b64uFromBytes(salt)}$${b64uFromBytes(dk)}`;
}

export async function verifyPasscode(passcode: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isFinite(iterations) || iterations < 1) return false;
  const dk = await derive(passcode, bytesFromB64u(parts[2]!), iterations);
  return timingSafeEqualHex(b64uFromBytes(dk), parts[3]!);
}

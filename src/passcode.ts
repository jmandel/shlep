/**
 * passcode.ts — best-practice passcode hashing for the optional access gate.
 * Salted scrypt (a memory-hard KDF) via node:crypto — no extra dependency.
 *
 * Server-only: this is never imported by the browser-bundled client, so the
 * node:crypto dependency is fine.
 *
 * Stored format: `scrypt$<N>$<r>$<p>$<salt b64url>$<hash b64url>`. The per-share
 * salt defeats rainbow tables and cross-share correlation; the work factor slows
 * brute force. (A passcode is a host-enforced gate on retrieving the still-
 * encrypted ciphertext, so this hash is defense-in-depth against sidecar
 * exfiltration — see docs/api-design.md §7.)
 */
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";

const PARAMS = { N: 16384, r: 8, p: 1 } as const; // ~tens of ms; OWASP-reasonable
const KEYLEN = 32;

function scrypt(passcode: string, salt: Buffer, keylen: number, params: { N: number; r: number; p: number }): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scryptCb(passcode, salt, keylen, params, (err, dk) => (err ? reject(err) : resolve(dk as Buffer))),
  );
}

export async function hashPasscode(passcode: string): Promise<string> {
  const salt = randomBytes(16);
  const dk = await scrypt(passcode, salt, KEYLEN, PARAMS);
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString("base64url")}$${dk.toString("base64url")}`;
}

export async function verifyPasscode(passcode: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, n, r, p, saltB64, hashB64] = parts;
  const salt = Buffer.from(saltB64!, "base64url");
  const expected = Buffer.from(hashB64!, "base64url");
  let dk: Buffer;
  try {
    dk = await scrypt(passcode, salt, expected.length, { N: Number(n), r: Number(r), p: Number(p) });
  } catch {
    return false;
  }
  return dk.length === expected.length && timingSafeEqual(dk, expected);
}

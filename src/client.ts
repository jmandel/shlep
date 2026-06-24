/**
 * client.ts — the CLIENT side of the blind boundary. These run wherever the
 * plaintext already lives (the app / the user's device), NEVER on the service.
 * They produce the ciphertext that gets uploaded and the link that carries the
 * key in its fragment. The service never imports this file.
 *
 * Flow:
 *   const sealed = await encryptBundle(bundleJson)        // key born here
 *   const { fileUrl } = await POST /shares { ciphertext: sealed.jwe, ... }
 *   const link = composeViewerLink(viewerPrefix, fileUrl, sealed.keyB64, { label })
 *   // sealed.key / sealed.keyB64 stay client-side; only sealed.jwe was uploaded.
 */
import { b64uFromBytes, decryptCompact, encryptCompact, genKey } from "./crypto";
import { encodeShlink, viewerLink } from "./shlink";

export interface SealedBundle {
  /** Compact JWE to upload as `ciphertext`. */
  jwe: string;
  /** The AES-256 content key — keep client-side; place keyB64 in the link fragment. */
  key: Uint8Array;
  keyB64: string;
}

/** Encrypt a FHIR bundle (or any UTF-8) under a fresh content key. Uncompressed by default. */
export async function encryptBundle(plaintext: string, opts: { deflate?: boolean } = {}): Promise<SealedBundle> {
  const key = genKey();
  const jwe = await encryptCompact(plaintext, key, { deflate: opts.deflate === true });
  return { jwe, key, keyB64: b64uFromBytes(key) };
}

export interface LinkOptions {
  /**
   * SHL flags. Default: omitted (manifest rail) — works for any share. Pass "U"
   * (direct-file GET) ONLY for a single-file share with no passcode; SHL forbids
   * combining "U" with "P" (passcode).
   */
  flag?: string;
  /** Human label. Travels in the link fragment only; the service never sees it. */
  label?: string;
  exp?: number;
}

/** Compose the bare `shlink:/…` from the service's fileUrl + the client's key. */
export function composeShlink(fileUrl: string, keyB64: string, opts: LinkOptions = {}): string {
  return encodeShlink({ url: fileUrl, key: keyB64, flag: opts.flag, label: opts.label, exp: opts.exp });
}

/** Compose `${viewerPrefix}#shlink:/…` — the QR/copy target a recipient opens. */
export function composeViewerLink(viewerPrefix: string, fileUrl: string, keyB64: string, opts: LinkOptions = {}): string {
  return viewerLink(viewerPrefix, composeShlink(fileUrl, keyB64, opts));
}

/** Decrypt a resolved JWE with the content key (receiver side; for tests/round-trip). */
export async function openSealed(jwe: string, key: Uint8Array): Promise<string> {
  return decryptCompact(jwe, key);
}

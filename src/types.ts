/**
 * Core types for the bucket-based SHLink service.
 *
 * BLIND-HOST INVARIANT (the whole point): the service stores only ciphertext +
 * a hashed capability token + opaque metadata. It NEVER sees the content
 * encryption key or the plaintext. The key is derived client-side (e.g. via
 * HKDF from an owner secret) and lives only in the link fragment; the receiver
 * decrypts in their browser. The service serves opaque JWE bytes and enforces
 * link *settings* (expiry / use-limits / revoke) without ever being able to read
 * the content. This mirrors the kill-the-clipboard-skill server model.
 *
 * A "share" is one of two modes:
 *   - "direct"   : the shlink `url` IS the bucket object. Receivers fetch storage
 *                  directly; the service is not in the read path. `?recipient=` is
 *                  accepted by the client but IGNORED by storage (documented
 *                  limitation: no per-recipient log, no use-count; revoke = delete
 *                  the object). Mode 1.
 *   - "mediated" : the shlink `url` is a service endpoint (`${baseUrl}/shl/${id}`).
 *                  The service consumes `recipient` (never forwarding it to
 *                  storage) and enforces expiry / use-limits / passcode / pause /
 *                  revoke / audit. Mode 2.
 */

export type ShareMode = "direct" | "mediated";

/** Persisted state. Effective (servable) status is derived from this + exp/useCount. */
export type ShareStatus = "active" | "paused" | "revoked";

/** Status as reported to the holder of the capability token (adds derived terminal states). */
export type EffectiveStatus = ShareStatus | "expired" | "exhausted";

export interface SharePolicy {
  /** Expiry, epoch seconds. Enforced in mediated mode; advisory (lifecycle hint) in direct mode. */
  exp?: number;
  /** Max successful resolves before exhaustion. Mediated mode only. */
  maxUses?: number;
  /**
   * Human label (<=80 chars). NOTE: storing it here is a small metadata leak to
   * the host — the authoritative label rides in the link fragment. Blind-strict
   * clients should omit it (or pass a pre-encrypted blob).
   */
  label?: string;
  /** Optional passcode (mediated only). Stored only as a hash; never echoed. */
  passcode?: string;
}

export interface RecipientEntry {
  at: number; // epoch seconds
  recipient: string;
}

/**
 * The sidecar metadata object persisted in the bucket alongside the ciphertext.
 * INVARIANT: never contains the AES key or any plaintext.
 */
export interface ShareRecord {
  id: string;
  mode: ShareMode;
  status: ShareStatus;
  createdAt: number;
  flag: string; // SHL flags; "U" = direct-file rail
  cipherKey: string; // object-store key of the ciphertext
  cipherLen: number;
  label?: string;
  exp?: number;
  maxUses?: number;
  useCount: number;
  manageTokenHash: string; // sha256(capability token) — the only auth the host holds
  passcodeHash?: string;
  recipients: RecipientEntry[];
}

/** Holder-facing view of a record (sensitive hashes stripped, effective status added). */
export interface ShareView {
  id: string;
  mode: ShareMode;
  status: EffectiveStatus;
  createdAt: number;
  flag: string;
  label?: string;
  exp?: number;
  maxUses?: number;
  useCount: number;
  cipherLen: number;
  recipientCount: number;
}

export interface ShlinkPayload {
  url: string;
  key: string;
  flag?: string;
  label?: string;
  exp?: number;
  v?: number;
}

export interface CreateInput {
  mode?: ShareMode;
  /**
   * The pre-encrypted compact JWE. This is the ONLY way content enters the
   * service — the client encrypts; the service stores opaque bytes and never
   * sees the key or plaintext. Bytes or a JWE string.
   */
  ciphertext: Uint8Array | string;
  policy?: SharePolicy;
}

export interface CreateResult {
  id: string;
  mode: ShareMode;
  status: ShareStatus;
  /** Where the ciphertext lives: the object URL (direct) or `${baseUrl}/shl/${id}` (mediated). */
  fileUrl: string;
  /**
   * Returned ONCE, here and nowhere else. The capability to manage/revoke this
   * share. The client stores it; the service keeps only sha256(it). It can never
   * decrypt content — it governs link settings only.
   */
  manageToken: string;
}

export interface ResolveOptions {
  recipient?: string;
  passcode?: string;
  /** Manifest rail: max bytes the receiver will accept inline before a `location` is used. */
  embeddedLengthMax?: number;
}

export interface ResolveResult {
  jwe: string;
  label?: string;
  contentType: string; // always "application/jose"
}

export class ShlError extends Error {
  constructor(public code: string, message: string, public httpStatus: number) {
    super(message);
    this.name = "ShlError";
  }
}

export const Errors = {
  /** Used for BOTH "missing" and "wrong capability token" so existence never leaks (KTC rule). */
  notFound: () => new ShlError("not_found", "not found", 404),
  /** Uniform "not available" for the public data plane (hides revoked/expired/exhausted/paused). */
  notServable: () => new ShlError("not_servable", "not found", 404),
  unsupportedControl: (c: string, why: string) =>
    new ShlError("unsupported_control", `control "${c}" unavailable: ${why}`, 409),
  passcodeRequired: () => new ShlError("passcode_required", "passcode required or incorrect", 401),
  conflict: () => new ShlError("conflict", "write conflict after retries", 409),
  badRequest: (m: string) => new ShlError("bad_request", m, 400),
};

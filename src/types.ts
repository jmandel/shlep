/**
 * Core types for shlep — a blind, revocable SMART Health Link service over an
 * object store.
 *
 * Every share's link points at the service (`${baseUrl}/shl/${id}`), and every
 * read is resolved through it, so revocation, expiry, passcode, pause, use-limits,
 * and an opt-in access log are all enforceable.
 *
 * BLIND-HOST INVARIANT: the service stores only ciphertext + sha256(manageToken)
 * + opaque metadata. It never sees the content encryption key or the plaintext.
 * The key is generated client-side and lives only in the link fragment; the
 * receiver decrypts in their browser.
 *
 * COST: a resolve always READS the sidecar (to enforce revoke/expiry/passcode).
 * It only WRITES (a CAS update to bump the counter / append the recipient) when
 * the share opts into `maxUses` or `audit` — so an unlimited, unaudited share is
 * a cheap read-only resolve.
 */

/** Persisted state. Effective (servable) status is derived from this + exp/useCount. */
export type ShareStatus = "active" | "paused" | "revoked";

/** Status as reported to the holder of the capability token (adds derived terminals). */
export type EffectiveStatus = ShareStatus | "expired" | "exhausted";

export interface SharePolicy {
  /** Expiry, epoch seconds. Enforced on every resolve. */
  exp?: number;
  /** Max successful resolves before exhaustion (requires a CAS-capable backend). */
  maxUses?: number;
  /** Optional passcode. Stored only as a hash; never echoed. */
  passcode?: string;
  /**
   * Record each recipient (and bump the access count) on resolve. Opt-in because
   * it (a) turns every resolve into a sidecar WRITE and (b) records recipient
   * strings on the host — metadata a blind-strict deployment may not want.
   */
  audit?: boolean;
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
  status: ShareStatus;
  createdAt: number;
  flag: string; // SHL flags; "U" = the direct-file retrieval rail (GET)
  cipherKey: string; // object-store key of the ciphertext
  cipherLen: number;
  exp?: number;
  maxUses?: number;
  audit?: boolean;
  useCount: number;
  manageTokenHash: string; // sha256(capability token) — the only auth the host holds
  passcodeHash?: string;
  recipients: RecipientEntry[];
}

/** Holder-facing view of a record (sensitive hashes stripped, effective status added). */
export interface ShareView {
  id: string;
  status: EffectiveStatus;
  createdAt: number;
  flag: string;
  exp?: number;
  maxUses?: number;
  audit: boolean;
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
  status: ShareStatus;
  /** The shlink `url`: `${baseUrl}/shl/${id}`. */
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
  contentType: string; // always "application/jose"
}

export class ShlError extends Error {
  constructor(public code: string, message: string, public httpStatus: number) {
    super(message);
    this.name = "ShlError";
  }
}

export const Errors = {
  /** Used for BOTH "missing" and "wrong capability token" so existence never leaks. */
  notFound: () => new ShlError("not_found", "not found", 404),
  /** Uniform "not available" for the public data plane (hides revoked/expired/exhausted/paused). */
  notServable: () => new ShlError("not_servable", "not found", 404),
  unsupportedControl: (c: string, why: string) =>
    new ShlError("unsupported_control", `control "${c}" unavailable: ${why}`, 409),
  passcodeRequired: () => new ShlError("passcode_required", "passcode required or incorrect", 401),
  conflict: () => new ShlError("conflict", "write conflict after retries", 409),
  badRequest: (m: string) => new ShlError("bad_request", m, 400),
};

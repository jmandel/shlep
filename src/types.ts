/**
 * Core types for shlep — a blind, revocable SMART Health Link service over an
 * object store.
 *
 * Every share's link points at the service (`${baseUrl}/shl/${id}`), and every
 * read is resolved through it, so revocation, expiry, passcode, pause, use-limits,
 * and an opt-in access log are all enforceable.
 *
 * A share is a COLLECTION OF FILES (0..N), each an independently
 * add/replace/delete-able ciphertext, all under the link's one key. Recipients
 * read via the manifest rail (any file count) or, when the share has exactly one
 * file, the direct-file "U" rail (a single GET). A U-flagged link is the client's
 * assertion that the share has one file; if that stops being true, only that
 * shortcut breaks (the manifest still works).
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
export type EffectiveStatus = ShareStatus | "expired" | "exhausted" | "disabled";

export interface SharePolicy {
  /** Expiry, epoch seconds. Enforced on every resolve. */
  exp?: number;
  /** Max successful resolves before exhaustion (requires a CAS-capable backend). */
  maxUses?: number;
  /** Optional passcode. Stored only as a salted-PBKDF2 hash; never echoed. */
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

/** The SHL-defined content types describing a file's DECRYPTED payload (closed set). */
export const ALLOWED_CONTENT_TYPES = [
  "application/fhir+json",
  "application/smart-health-card",
  "application/smart-api-access",
] as const;
export const DEFAULT_CONTENT_TYPE = "application/fhir+json";

/** One encrypted file within a share. The cipherKey is server-internal. */
export interface FileEntry {
  fileId: string;
  cipherKey: string; // object-store key of this file's ciphertext
  len: number;
  /** The DECRYPTED payload's content type (manifest `files[].contentType`), e.g. application/fhir+json. */
  contentType: string;
}

/**
 * The sidecar metadata object persisted in the bucket alongside the ciphertext.
 * INVARIANT: never contains the AES key or any plaintext.
 */
export interface ShareRecord {
  id: string;
  status: ShareStatus;
  files: FileEntry[];
  exp?: number;
  maxUses?: number;
  audit?: boolean;
  useCount: number;
  manageTokenHash: string; // sha256(capability token) — the only auth the host holds
  passcodeHash?: string;
  /** Lifetime count of incorrect passcode attempts (SHL brute-force protection). */
  passcodeFailures: number;
  recipients: RecipientEntry[];
}

/** Holder-facing file descriptor (no internal storage key). */
export interface FileView {
  fileId: string;
  len: number;
  contentType: string;
}

/** Holder-facing view of a record (sensitive hashes stripped, effective status added). */
export interface ShareView {
  id: string;
  status: EffectiveStatus;
  files: FileView[];
  /** Whether the direct-file (U) rail will currently serve — i.e. exactly one file. */
  directServable: boolean;
  exp?: number;
  maxUses?: number;
  audit: boolean;
  useCount: number;
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

/** Pre-encrypted compact JWE(s). The client encrypts; the service stores opaque bytes. */
export type Ciphertext = Uint8Array | string;

/** A file to store: bare ciphertext (contentType defaults to application/fhir+json) or with a type. */
export type FileInput = Ciphertext | { ciphertext: Ciphertext; contentType?: string };

export interface CreateInput {
  /** A single file's ciphertext (the common case). */
  ciphertext?: Ciphertext;
  /** The single file's decrypted content type (manifest contentType). Default application/fhir+json. */
  contentType?: string;
  /** Or several files at once. At least one of `ciphertext` / `files` is required. */
  files?: FileInput[];
  policy?: SharePolicy;
}

export interface CreateResult {
  id: string;
  status: ShareStatus;
  /** The shlink `url`: `${baseUrl}/shl/${id}`. */
  fileUrl: string;
  /** The file id(s) created — use them to replace/delete individual files later. */
  fileIds: string[];
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
  constructor(public code: string, message: string, public httpStatus: number, public body?: Record<string, unknown>) {
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
  /** SHL: 401 with a {remainingAttempts} body. */
  passcodeRequired: (remainingAttempts?: number) =>
    new ShlError("passcode_required", "passcode required or incorrect", 401, remainingAttempts != null ? { remainingAttempts } : undefined),
  conflict: () => new ShlError("conflict", "write conflict after retries", 409),
  badRequest: (m: string) => new ShlError("bad_request", m, 400),
  tooLarge: (m: string) => new ShlError("too_large", m, 413),
};

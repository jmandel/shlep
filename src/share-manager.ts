/**
 * share-manager.ts — the high-level surface app developers call. It turns "host
 * a revocable, browser-fetchable SHLink in a bucket" into method calls and never
 * exposes a raw bucket/key/presign operation.
 *
 * Blind only: create takes pre-encrypted ciphertext; the manager stores
 * ciphertext + sha256(manageToken) + opaque metadata and never sees the content
 * key or plaintext. Clients do NOT pick the id — it is 128-bit random, minted here.
 *
 * Every link points at the service and is resolved through it, so
 * revoke/expiry/passcode/pause/use-limits are always enforceable.
 *
 * Durability invariants:
 *   CREATE  : RESERVE the id by writing the sidecar create-if-absent FIRST, then
 *             write ciphertext. Reserving first makes id allocation atomic: a
 *             (cosmically unlikely) 128-bit collision is retried with a fresh id,
 *             never surfaced, and can never clobber an existing share's ciphertext.
 *             A crash after the reservation but before the cipher write leaves an
 *             orphan sidecar (unreferenced; resolves to 404) — sweepable, never
 *             corrupting. On non-CAS backends, fall back to head+put.
 *   REVOKE  : flip the sidecar to `revoked` FIRST (CAS), then delete the
 *             ciphertext. Enforcement reads the sidecar, so even if the delete
 *             lags, nothing is servable.
 *
 * Resolve always READS the sidecar (enforce revoke/expiry/passcode). It only
 * WRITES (CAS bump of useCount, optional recipient log) when the share opts into
 * maxUses or audit — an unlimited, unaudited share is a read-only resolve.
 */
import { hmacHex, randomId, randomToken, sha256Hex, timingSafeEqualHex } from "./crypto";
import type { ObjectStore } from "./object-store";
import { hashPasscode, verifyPasscode } from "./passcode";
import {
  type CreateInput,
  type CreateResult,
  type EffectiveStatus,
  Errors,
  type ResolveOptions,
  type ResolveResult,
  type ShareRecord,
  type ShareView,
} from "./types";

export interface ManagerConfig {
  store: ObjectStore;
  /** Public base for the service endpoints, e.g. "https://shl.example.com". No trailing slash. */
  baseUrl: string;
  /** Key namespace inside the bucket. Default "shl/". */
  prefix?: string;
  maxRecipientsLogged?: number;
  casMaxRetries?: number;
  /** Cap on inline manifest bytes regardless of the receiver's embeddedLengthMax. */
  maxEmbeddedBytes?: number;
  /** HMAC secret for location-rail tickets. Defaults to a per-process random (single-node only). */
  ticketSecret?: string;
}

export interface ManifestFile {
  contentType: "application/jose";
  embedded?: string;
  location?: string;
}
export interface Manifest {
  files: ManifestFile[];
}

const teEncode = (s: string) => new TextEncoder().encode(s);
const tdDecode = (b: Uint8Array) => new TextDecoder().decode(b);
const nowSec = () => Math.floor(Date.now() / 1000);

export class ShareManager {
  private store: ObjectStore;
  private baseUrl: string;
  private prefix: string;
  private maxRecipients: number;
  private maxRetries: number;
  private maxEmbedded: number;
  private ticketSecret: string;

  constructor(cfg: ManagerConfig) {
    this.store = cfg.store;
    this.baseUrl = cfg.baseUrl.replace(/\/+$/, "");
    this.prefix = cfg.prefix ?? "shl/";
    this.maxRecipients = cfg.maxRecipientsLogged ?? 50;
    this.maxRetries = cfg.casMaxRetries ?? 8;
    this.maxEmbedded = cfg.maxEmbeddedBytes ?? 100_000;
    this.ticketSecret = cfg.ticketSecret ?? randomToken();
  }

  private cipherKeyFor(id: string) {
    return `${this.prefix}c/${id}.jwe`;
  }
  private metaKeyFor(id: string) {
    return `${this.prefix}m/${id}.json`;
  }

  // ---------- create ----------

  async create(input: CreateInput): Promise<CreateResult> {
    const policy = input.policy ?? {};
    if (policy.maxUses != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("maxUses", "this backend lacks conditional writes for race-safe counting");
    }
    if (input.ciphertext == null) throw Errors.badRequest("`ciphertext` is required (encrypt client-side; the service is blind)");
    const cipherBytes = typeof input.ciphertext === "string" ? teEncode(input.ciphertext) : input.ciphertext;

    const token = randomToken(); // the service mints the manage token and returns it once
    const manageTokenHash = await sha256Hex(token);
    const passcodeHash = policy.passcode != null ? await hashPasscode(policy.passcode) : undefined;

    // 1) RESERVE the id by writing the sidecar create-if-absent (atomic id
    // allocation: a 128-bit collision is retried, never clobbers anything).
    let id = "";
    for (let attempt = 0; ; attempt++) {
      if (attempt >= this.maxRetries) throw Errors.conflict();
      id = randomId();
      const record: ShareRecord = {
        id,
        status: "active",
        flag: "U",
        cipherKey: this.cipherKeyFor(id),
        cipherLen: cipherBytes.length,
        exp: policy.exp,
        maxUses: policy.maxUses,
        audit: policy.audit === true ? true : undefined,
        useCount: 0,
        manageTokenHash,
        passcodeHash,
        recipients: [],
      };
      const body = teEncode(JSON.stringify(record));
      const metaKey = this.metaKeyFor(id);
      if (this.store.capabilities.conditionalWrite) {
        if (await this.store.conditionalPut(metaKey, body, null)) break; // reserved
      } else if (!(await this.store.head(metaKey))) {
        await this.store.put(metaKey, body); // no CAS; 128-bit collision is negligible
        break;
      }
    }

    // 2) Write ciphertext. The id is reserved, so this can't clobber anything.
    const cipherKey = this.cipherKeyFor(id);
    try {
      await this.store.put(cipherKey, cipherBytes, { contentType: "application/jose", cacheControl: "no-store" });
    } catch (e) {
      await this.store.delete(this.metaKeyFor(id)).catch(() => {}); // release the reservation
      throw e;
    }

    return { id, status: "active", fileUrl: `${this.baseUrl}/shl/${id}`, manageToken: token };
  }

  // ---------- data plane (public) ----------

  /** Direct-file rail: GET <url>?recipient=. Returns the JWE; counts/logs iff the share opts in. */
  async resolveDirect(id: string, opts: ResolveOptions = {}): Promise<ResolveResult> {
    const record = await this.checkAndCount(id, opts);
    return this.fetchCipher(record);
  }

  /** Manifest rail: POST <url> {recipient,passcode?,embeddedLengthMax?}. */
  async resolveManifest(id: string, opts: ResolveOptions = {}): Promise<Manifest> {
    const record = await this.checkAndCount(id, opts);
    const cap = Math.min(opts.embeddedLengthMax ?? this.maxEmbedded, this.maxEmbedded);
    if (record.cipherLen <= cap) {
      const { jwe } = await this.fetchCipher(record);
      return { files: [{ contentType: "application/jose", embedded: jwe }] };
    }
    const fileId = "0";
    const ticket = await this.signTicket(id, fileId);
    return { files: [{ contentType: "application/jose", location: `${this.baseUrl}/shl/${id}/f/${fileId}?t=${ticket}` }] };
  }

  /** Ticketed file rail (manifest `location`). Does NOT count — the manifest POST already did. */
  async resolveFileTicket(id: string, fileId: string, ticket: string): Promise<ResolveResult> {
    if (!(await this.verifyTicket(id, fileId, ticket))) throw Errors.notServable();
    const loaded = await this.loadRecord(id);
    if (!loaded || !this.isServable(loaded.record)) throw Errors.notServable();
    return this.fetchCipher(loaded.record);
  }

  /**
   * Read the sidecar, enforce servability, and — only if the share opts into
   * maxUses or audit — atomically bump the counter / append the recipient via CAS.
   * Unlimited, unaudited shares short-circuit to a single read (no write).
   */
  private async checkAndCount(id: string, opts: ResolveOptions): Promise<ShareRecord> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const loaded = await this.loadRecord(id);
      if (!loaded) throw Errors.notServable();
      const { record, etag } = loaded;

      if (record.passcodeHash != null) {
        const ok = opts.passcode != null && (await verifyPasscode(opts.passcode, record.passcodeHash));
        if (!ok) throw Errors.passcodeRequired();
      }
      if (!this.isServable(record)) throw Errors.notServable();

      const mustWrite = record.maxUses != null || record.audit === true;
      if (!mustWrite) return record; // read-only resolve

      const next: ShareRecord = {
        ...record,
        useCount: record.useCount + 1,
        recipients: record.audit === true
          ? [...record.recipients, { at: nowSec(), recipient: opts.recipient ?? "Unknown" }].slice(-this.maxRecipients)
          : record.recipients,
      };
      const ok = await this.store.conditionalPut(this.metaKeyFor(id), teEncode(JSON.stringify(next)), etag);
      if (ok != null) return next;
      // lost the CAS race — reload and retry
    }
    throw Errors.conflict();
  }

  /** Servable = active, not expired, not exhausted. (Passcode checked separately.) */
  private isServable(r: ShareRecord): boolean {
    if (r.status !== "active") return false;
    if (r.exp != null && nowSec() >= r.exp) return false;
    if (r.maxUses != null && r.useCount >= r.maxUses) return false;
    return true;
  }

  private async fetchCipher(record: ShareRecord): Promise<ResolveResult> {
    const obj = await this.store.get(record.cipherKey);
    if (!obj) throw Errors.notServable();
    return { jwe: tdDecode(obj.bytes).trim(), contentType: "application/jose" };
  }

  // ---------- control plane (capability-token authed) ----------

  async get(id: string, token: string): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    return this.toView(record);
  }

  async revoke(id: string, token: string): Promise<ShareView> {
    // stop serving first (sidecar), then reclaim storage.
    const updated = await this.casUpdate(id, token, (r) => ({ ...r, status: "revoked" }));
    await this.store.delete(updated.cipherKey).catch(() => {});
    return this.toView(updated);
  }

  async pause(id: string, token: string): Promise<ShareView> {
    return this.toView(await this.casUpdate(id, token, (r) => (r.status === "active" ? { ...r, status: "paused" } : r)));
  }

  async resume(id: string, token: string): Promise<ShareView> {
    return this.toView(await this.casUpdate(id, token, (r) => (r.status === "paused" ? { ...r, status: "active" } : r)));
  }

  async extend(id: string, token: string, exp: number | undefined): Promise<ShareView> {
    return this.toView(await this.casUpdate(id, token, (r) => ({ ...r, exp })));
  }

  async setLimits(id: string, token: string, maxUses: number | undefined): Promise<ShareView> {
    if (maxUses != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("maxUses", "this backend lacks conditional writes for race-safe counting");
    }
    return this.toView(await this.casUpdate(id, token, (r) => ({ ...r, maxUses })));
  }

  async accessLog(id: string, token: string) {
    const { record } = await this.requireOwner(id, token);
    return record.recipients;
  }

  async delete(id: string, token: string): Promise<void> {
    const { record } = await this.requireOwner(id, token);
    await this.store.delete(record.cipherKey).catch(() => {});
    await this.store.delete(this.metaKeyFor(id)).catch(() => {});
  }

  // ---------- internals ----------

  private async loadRecord(id: string): Promise<{ record: ShareRecord; etag: string } | null> {
    const obj = await this.store.get(this.metaKeyFor(id));
    if (!obj) return null;
    return { record: JSON.parse(tdDecode(obj.bytes)) as ShareRecord, etag: obj.etag };
  }

  /** Load + verify the capability token. Wrong/missing token throws notFound (existence never leaks). */
  private async requireOwner(id: string, token: string): Promise<{ record: ShareRecord; etag: string }> {
    const loaded = await this.loadRecord(id);
    if (!loaded) throw Errors.notFound();
    if (!(await this.tokenMatches(token, loaded.record))) throw Errors.notFound();
    return loaded;
  }
  private async tokenMatches(token: string, record: ShareRecord): Promise<boolean> {
    return token != null && timingSafeEqualHex(await sha256Hex(token), record.manageTokenHash);
  }

  /** CAS read-modify-write that also verifies the capability token on every attempt. */
  private async casUpdate(id: string, token: string, mutate: (r: ShareRecord) => ShareRecord): Promise<ShareRecord> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const loaded = await this.loadRecord(id);
      if (!loaded) throw Errors.notFound();
      if (!(await this.tokenMatches(token, loaded.record))) throw Errors.notFound();
      const next = mutate(loaded.record);
      if (next === loaded.record) return loaded.record; // no-op
      const ok = await this.store.conditionalPut(this.metaKeyFor(id), teEncode(JSON.stringify(next)), loaded.etag);
      if (ok != null) return next;
    }
    throw Errors.conflict();
  }

  private effectiveStatus(r: ShareRecord): EffectiveStatus {
    if (r.status !== "active") return r.status;
    if (r.exp != null && nowSec() >= r.exp) return "expired";
    if (r.maxUses != null && r.useCount >= r.maxUses) return "exhausted";
    return "active";
  }
  private toView(r: ShareRecord): ShareView {
    return {
      id: r.id,
      status: this.effectiveStatus(r),
      flag: r.flag,
      exp: r.exp,
      maxUses: r.maxUses,
      audit: r.audit === true,
      useCount: r.useCount,
      cipherLen: r.cipherLen,
      recipientCount: r.recipients.length,
    };
  }

  private async signTicket(id: string, fileId: string): Promise<string> {
    const exp = nowSec() + 300;
    const sig = await hmacHex(this.ticketSecret, `${id}.${fileId}.${exp}`);
    return `${exp}.${sig}`;
  }
  private async verifyTicket(id: string, fileId: string, ticket: string): Promise<boolean> {
    const [expStr, sig] = (ticket ?? "").split(".");
    const exp = Number(expStr);
    if (!Number.isFinite(exp) || nowSec() > exp || !sig) return false;
    return timingSafeEqualHex(sig, await hmacHex(this.ticketSecret, `${id}.${fileId}.${exp}`));
  }
}

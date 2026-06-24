/**
 * share-manager.ts — the high-level surface app developers actually call. It
 * turns "host a revocable, browser-fetchable SHLink in a bucket" into method
 * calls and never exposes a raw bucket/key/presign operation.
 *
 * Blind only: create takes pre-encrypted ciphertext; the manager stores
 * ciphertext + sha256(manageToken) + opaque metadata and never sees the content
 * key or plaintext. Clients do NOT pick the id — it is 128-bit random, minted here.
 *
 * Durability invariants (close the create/revoke atomicity + id-conflict question):
 *   CREATE  : RESERVE the id by writing the sidecar create-if-absent FIRST, then
 *             write ciphertext. Reserving first makes id allocation atomic: a
 *             (cosmically unlikely) 128-bit collision is retried with a fresh id,
 *             never surfaced, and can never clobber an existing share's ciphertext.
 *             A crash after the reservation but before the cipher write leaves an
 *             orphan sidecar (unreferenced; resolves to 404) — sweepable, never
 *             corrupting. On non-CAS backends, fall back to head+put.
 *   REVOKE  : (mediated) flip sidecar -> revoked FIRST, then delete ciphertext.
 *             Enforcement reads the sidecar, so even if the delete lags, nothing
 *             is servable. (direct) delete the object FIRST (that IS the revoke,
 *             reads bypass the service), then mark the sidecar.
 *
 * Use-counting is race-safe via the store's conditionalPut (CAS) with a bounded
 * retry loop; refused on backends without conditional writes (honesty rule).
 */
import { hmacHex, randomId, randomToken, sha256Hex, timingSafeEqualHex } from "./crypto";
import type { ObjectStore } from "./object-store";
import {
  type CreateInput,
  type CreateResult,
  type EffectiveStatus,
  Errors,
  type ResolveOptions,
  type ResolveResult,
  type ShareMode,
  type ShareRecord,
  type ShareView,
} from "./types";

export interface ManagerConfig {
  store: ObjectStore;
  /** Public base for mediated endpoints, e.g. "https://shl.example.com". No trailing slash. */
  baseUrl: string;
  /** Key namespace inside the bucket. Default "shl/". */
  prefix?: string;
  defaultMode?: ShareMode;
  maxRecipientsLogged?: number;
  casMaxRetries?: number;
  /** Cap on inline manifest bytes regardless of the receiver's embeddedLengthMax. */
  maxEmbeddedBytes?: number;
  /** HMAC secret for location-rail tickets. Defaults to a per-process random (fine for single-node). */
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
  private defaultMode: ShareMode;
  private maxRecipients: number;
  private maxRetries: number;
  private maxEmbedded: number;
  private ticketSecret: string;

  constructor(cfg: ManagerConfig) {
    this.store = cfg.store;
    this.baseUrl = cfg.baseUrl.replace(/\/+$/, "");
    this.prefix = cfg.prefix ?? "shl/";
    this.defaultMode = cfg.defaultMode ?? "mediated";
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
    const mode = input.mode ?? this.defaultMode;
    const policy = input.policy ?? {};

    // Honesty rule: refuse controls the chosen mode/backend can't enforce.
    if (mode === "direct") {
      if (policy.maxUses != null) throw Errors.unsupportedControl("maxUses", "direct shares are fetched from storage and cannot count opens");
      if (policy.passcode != null) throw Errors.unsupportedControl("passcode", "direct shares bypass the service");
    }
    if (policy.maxUses != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("maxUses", "this backend lacks conditional writes for race-safe counting");
    }
    if (mode === "direct" && !(this.store.capabilities.publicUrl && this.store.publicUrl)) {
      throw Errors.badRequest("this backend has no public object URL; use mediated mode");
    }
    if (input.ciphertext == null) throw Errors.badRequest("`ciphertext` is required (encrypt client-side; the service is blind)");
    const cipherBytes = typeof input.ciphertext === "string" ? teEncode(input.ciphertext) : input.ciphertext;

    const token = randomToken(); // the service mints the manage token and returns it once
    const manageTokenHash = await sha256Hex(token);
    const passcodeHash = policy.passcode != null ? await sha256Hex(policy.passcode) : undefined;

    // 1) RESERVE the id by writing the sidecar create-if-absent. Clients never
    // pick the id (it is 128-bit random, unguessable). Reserving the metadata
    // slot first makes allocation atomic: a (cosmically unlikely) collision is
    // retried with a fresh id, never surfaced, and — crucially — can never
    // clobber an existing share's ciphertext (which a "ciphertext-first" write
    // would, since the cipher key is derived from the id).
    let id = "";
    for (let attempt = 0; ; attempt++) {
      if (attempt >= this.maxRetries) throw Errors.conflict();
      id = randomId();
      const record: ShareRecord = {
        id,
        mode,
        status: "active",
        createdAt: nowSec(),
        flag: "U",
        cipherKey: this.cipherKeyFor(id),
        cipherLen: cipherBytes.length,
        label: policy.label,
        exp: policy.exp,
        maxUses: policy.maxUses,
        useCount: 0,
        manageTokenHash,
        passcodeHash,
        recipients: [],
      };
      const body = teEncode(JSON.stringify(record));
      const metaKey = this.metaKeyFor(id);
      if (this.store.capabilities.conditionalWrite) {
        if (await this.store.conditionalPut(metaKey, body, null)) break; // reserved
        // id taken -> retry with a fresh id
      } else if (!(await this.store.head(metaKey))) {
        await this.store.put(metaKey, body); // no CAS available; 128-bit collision is negligible
        break;
      }
    }

    // 2) Write ciphertext. The id is reserved, so this can't clobber anything.
    // A crash before this leaves an orphan sidecar (unreferenced; resolves to a
    // 404 because the cipher is missing) — sweepable, never corrupting.
    const cipherKey = this.cipherKeyFor(id);
    try {
      await this.store.put(cipherKey, cipherBytes, {
        contentType: "application/jose",
        publicRead: mode === "direct",
        cacheControl: mode === "direct" ? "public, max-age=31536000, immutable" : "no-store",
      });
    } catch (e) {
      await this.store.delete(this.metaKeyFor(id)).catch(() => {}); // release the reservation
      throw e;
    }

    const fileUrl = mode === "direct" ? this.directUrl(cipherKey) : `${this.baseUrl}/shl/${id}`;
    return { id, mode, status: "active", fileUrl, manageToken: token };
  }

  private directUrl(cipherKey: string): string {
    if (!this.store.capabilities.publicUrl || !this.store.publicUrl) {
      throw Errors.badRequest("this backend has no public object URL; use mediated mode");
    }
    return this.store.publicUrl(cipherKey);
  }

  // ---------- data plane (public) ----------

  /** Direct-file rail: GET <url>?recipient=. Counts one use, returns the JWE. */
  async resolveDirect(id: string, opts: ResolveOptions = {}): Promise<ResolveResult> {
    const record = await this.checkAndCount(id, opts);
    return this.fetchCipher(record);
  }

  /** Manifest rail: POST <url> {recipient,passcode?,embeddedLengthMax?}. Counts one use. */
  async resolveManifest(id: string, opts: ResolveOptions = {}): Promise<Manifest> {
    const record = await this.checkAndCount(id, opts);
    const cap = Math.min(opts.embeddedLengthMax ?? this.maxEmbedded, this.maxEmbedded);
    if (record.cipherLen <= cap) {
      const { jwe } = await this.fetchCipher(record);
      return { files: [{ contentType: "application/jose", embedded: jwe }] };
    }
    // Large payload: hand back a stateless, short-lived ticketed location (no re-count on fetch).
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

  private async checkAndCount(id: string, opts: ResolveOptions): Promise<ShareRecord> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const loaded = await this.loadRecord(id);
      if (!loaded) throw Errors.notServable();
      const { record, etag } = loaded;

      if (record.passcodeHash != null) {
        const ok = opts.passcode != null && timingSafeEqualHex(await sha256Hex(opts.passcode), record.passcodeHash);
        if (!ok) throw Errors.passcodeRequired();
      }
      if (!this.isServable(record)) throw Errors.notServable();

      const next: ShareRecord = {
        ...record,
        useCount: record.useCount + 1,
        recipients: [...record.recipients, { at: nowSec(), recipient: opts.recipient ?? "Unknown" }].slice(-this.maxRecipients),
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
    return { jwe: tdDecode(obj.bytes).trim(), label: record.label, contentType: "application/jose" };
  }

  // ---------- control plane (capability-token authed) ----------

  async get(id: string, token: string): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    return this.toView(record);
  }

  async revoke(id: string, token: string): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    if (record.mode === "direct") {
      // reads bypass the service: deleting the object IS the revoke.
      await this.store.delete(record.cipherKey).catch(() => {});
      return this.toView(await this.casUpdate(id, (r) => ({ ...r, status: "revoked" })));
    }
    // mediated: stop serving first (sidecar), then reclaim storage.
    const updated = await this.casUpdate(id, (r) => ({ ...r, status: "revoked" }));
    await this.store.delete(record.cipherKey).catch(() => {});
    return this.toView(updated);
  }

  async pause(id: string, token: string): Promise<ShareView> {
    this.requireMediated(await this.peek(id, token), "pause");
    return this.toView(await this.casUpdate(id, (r) => (r.status === "active" ? { ...r, status: "paused" } : r)));
  }

  async resume(id: string, token: string): Promise<ShareView> {
    this.requireMediated(await this.peek(id, token), "resume");
    return this.toView(await this.casUpdate(id, (r) => (r.status === "paused" ? { ...r, status: "active" } : r)));
  }

  async extend(id: string, token: string, exp: number | undefined): Promise<ShareView> {
    this.requireMediated(await this.peek(id, token), "extend");
    return this.toView(await this.casUpdate(id, (r) => ({ ...r, exp })));
  }

  async setLimits(id: string, token: string, maxUses: number | undefined): Promise<ShareView> {
    const record = await this.peek(id, token);
    this.requireMediated(record, "setLimits");
    if (maxUses != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("maxUses", "this backend lacks conditional writes for race-safe counting");
    }
    return this.toView(await this.casUpdate(id, (r) => ({ ...r, maxUses })));
  }

  async accessLog(id: string, token: string) {
    const record = await this.peek(id, token);
    this.requireMediated(record, "accessLog");
    return record.recipients;
  }

  async delete(id: string, token: string): Promise<void> {
    const { record } = await this.requireOwner(id, token);
    await this.store.delete(record.cipherKey).catch(() => {});
    await this.store.delete(this.metaKeyFor(id)).catch(() => {});
  }

  /**
   * Ops/maintenance only — scans the metadata prefix. NOT a blind-model feature
   * (there are no accounts); the HTTP layer must gate this behind an admin token.
   */
  async list(): Promise<ShareView[]> {
    const keys = await this.store.list(`${this.prefix}m/`);
    const views: ShareView[] = [];
    for (const k of keys) {
      const obj = await this.store.get(k);
      if (obj) views.push(this.toView(JSON.parse(tdDecode(obj.bytes)) as ShareRecord));
    }
    return views;
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
    const ok = token != null && timingSafeEqualHex(await sha256Hex(token), loaded.record.manageTokenHash);
    if (!ok) throw Errors.notFound();
    return loaded;
  }
  private async peek(id: string, token: string): Promise<ShareRecord> {
    return (await this.requireOwner(id, token)).record;
  }
  private requireMediated(record: ShareRecord, control: string): void {
    if (record.mode !== "mediated") throw Errors.unsupportedControl(control, "only mediated shares support this control");
  }

  private async casUpdate(id: string, mutate: (r: ShareRecord) => ShareRecord): Promise<ShareRecord> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const loaded = await this.loadRecord(id);
      if (!loaded) throw Errors.notFound();
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
      mode: r.mode,
      status: this.effectiveStatus(r),
      createdAt: r.createdAt,
      flag: r.flag,
      label: r.label,
      exp: r.exp,
      maxUses: r.maxUses,
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

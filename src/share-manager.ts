/**
 * share-manager.ts — the high-level surface app developers call. It turns "host
 * revocable, browser-fetchable SHLink files in a bucket" into method calls and
 * never exposes a raw bucket/key/presign operation.
 *
 * A share is a collection of files (0..N), each its own ciphertext object, all
 * under the link's one key. Management (add/replace/delete files, settings,
 * revoke) is uniform regardless of how a recipient reads:
 *   - manifest rail (POST /shl/:id) serves any file count;
 *   - direct "U" rail (GET /shl/:id?recipient=) serves iff exactly one file.
 *
 * Blind only: the client encrypts; the manager stores ciphertext +
 * sha256(manageToken) + opaque metadata, never the content key or plaintext.
 * Clients do NOT pick ids — they are server-minted random.
 *
 * Durability:
 *   CREATE     reserve the sidecar (create-if-absent) FIRST, then write ciphertext
 *              objects. Atomic id allocation; a crash leaves an unreferenced,
 *              unservable share (sweepable), never a clobber. (head+put on non-CAS.)
 *   ADD FILE   write the ciphertext FIRST, then add the file entry — a crash leaves
 *              an orphan object, never a dangling reference.
 *   DELETE FILE / REVOKE   remove the reference FIRST (stop serving), then delete
 *              the ciphertext object(s).
 *
 * Use-counting is race-safe via the store's conditionalPut (CAS) and refused on
 * non-CAS backends. Management writes fall back to last-writer-wins on non-CAS
 * backends (low-concurrency owner actions), so revoke/pause/etc. work everywhere.
 */
import { hmacHex, randomId, randomToken, sha256Hex, timingSafeEqualHex } from "./crypto";
import type { ObjectStore } from "./object-store";
import { hashPasscode, verifyPasscode } from "./passcode";
import {
  type Ciphertext,
  type CreateInput,
  type CreateResult,
  type EffectiveStatus,
  Errors,
  type FileEntry,
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
const toBytes = (c: Ciphertext): Uint8Array => (typeof c === "string" ? teEncode(c) : c);

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

  /** This instance's public base URL (for docs / llms.txt). */
  get serviceBaseUrl(): string {
    return this.baseUrl;
  }
  /** Whether the backend supports CAS, i.e. whether `maxUses` is available. */
  get useLimitsSupported(): boolean {
    return this.store.capabilities.conditionalWrite;
  }

  private metaKeyFor(id: string) {
    return `${this.prefix}m/${id}.json`;
  }
  private fileKeyFor(id: string, fileId: string) {
    return `${this.prefix}c/${id}/${fileId}.jwe`;
  }
  private newFileId(existing: FileEntry[]): string {
    const taken = new Set(existing.map((f) => f.fileId));
    let fid = randomId(6);
    while (taken.has(fid)) fid = randomId(6);
    return fid;
  }

  // ---------- create ----------

  async create(input: CreateInput): Promise<CreateResult> {
    const policy = input.policy ?? {};
    if (policy.maxUses != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("maxUses", "this backend lacks conditional writes for race-safe counting");
    }
    const cts: Uint8Array[] = [];
    if (input.ciphertext != null) cts.push(toBytes(input.ciphertext));
    for (const f of input.files ?? []) cts.push(toBytes(f));
    if (cts.length === 0) throw Errors.badRequest("provide `ciphertext` or `files` (encrypt client-side; the service is blind)");

    const token = randomToken();
    const manageTokenHash = await sha256Hex(token);
    const passcodeHash = policy.passcode != null ? await hashPasscode(policy.passcode) : undefined;

    // 1) reserve the sidecar (atomic id allocation), with file entries referencing
    //    the to-be-written ciphertext objects.
    let id = "";
    let files: FileEntry[] = [];
    for (let attempt = 0; ; attempt++) {
      if (attempt >= this.maxRetries) throw Errors.conflict();
      id = randomId();
      files = [];
      for (const ct of cts) {
        const fileId = this.newFileId(files);
        files.push({ fileId, cipherKey: this.fileKeyFor(id, fileId), len: ct.length });
      }
      const record: ShareRecord = {
        id,
        status: "active",
        files,
        exp: policy.exp,
        maxUses: policy.maxUses,
        audit: policy.audit === true ? true : undefined,
        useCount: 0,
        manageTokenHash,
        passcodeHash,
        recipients: [],
      };
      const metaKey = this.metaKeyFor(id);
      const body = teEncode(JSON.stringify(record));
      if (this.store.capabilities.conditionalWrite) {
        if (await this.store.conditionalPut(metaKey, body, null)) break;
      } else if (!(await this.store.head(metaKey))) {
        await this.store.put(metaKey, body);
        break;
      }
    }

    // 2) write ciphertext objects.
    try {
      for (let i = 0; i < files.length; i++) {
        await this.store.put(files[i]!.cipherKey, cts[i]!, { contentType: "application/jose", cacheControl: "no-store" });
      }
    } catch (e) {
      for (const f of files) await this.store.delete(f.cipherKey).catch(() => {});
      await this.store.delete(this.metaKeyFor(id)).catch(() => {});
      throw e;
    }

    return {
      id,
      status: "active",
      fileUrl: `${this.baseUrl}/shl/${id}`,
      fileIds: files.map((f) => f.fileId),
      manageToken: token,
    };
  }

  // ---------- data plane (public) ----------

  /** Direct-file rail: GET <url>?recipient=. Serves ONLY when the share has exactly one file. */
  async resolveDirect(id: string, opts: ResolveOptions = {}): Promise<ResolveResult> {
    const record = await this.checkAndCount(id, opts);
    if (record.files.length !== 1) throw Errors.notServable(); // U-link invalid unless exactly one file
    return this.fetchFile(record.files[0]!);
  }

  /** Manifest rail: POST <url> {recipient,passcode?,embeddedLengthMax?}. Lists all files. */
  async resolveManifest(id: string, opts: ResolveOptions = {}): Promise<Manifest> {
    const record = await this.checkAndCount(id, opts);
    const cap = Math.min(opts.embeddedLengthMax ?? this.maxEmbedded, this.maxEmbedded);
    const files: ManifestFile[] = [];
    for (const f of record.files) {
      if (f.len <= cap) {
        const { jwe } = await this.fetchFile(f);
        files.push({ contentType: "application/jose", embedded: jwe });
      } else {
        const ticket = await this.signTicket(id, f.fileId);
        files.push({ contentType: "application/jose", location: `${this.baseUrl}/shl/${id}/f/${f.fileId}?t=${ticket}` });
      }
    }
    return { files };
  }

  /** Ticketed file rail (manifest `location`). Does NOT count — the manifest POST already did. */
  async resolveFileTicket(id: string, fileId: string, ticket: string): Promise<ResolveResult> {
    if (!(await this.verifyTicket(id, fileId, ticket))) throw Errors.notServable();
    const loaded = await this.loadRecord(id);
    if (!loaded || !this.isServable(loaded.record)) throw Errors.notServable();
    const f = loaded.record.files.find((x) => x.fileId === fileId);
    if (!f) throw Errors.notServable();
    return this.fetchFile(f);
  }

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
      if (await this.writeMeta(id, next, etag)) return next;
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

  private async fetchFile(f: FileEntry): Promise<ResolveResult> {
    const obj = await this.store.get(f.cipherKey);
    if (!obj) throw Errors.notServable();
    return { jwe: tdDecode(obj.bytes).trim(), contentType: "application/jose" };
  }

  // ---------- control plane (capability-token authed) ----------

  async get(id: string, token: string): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    return this.toView(record);
  }

  async revoke(id: string, token: string): Promise<ShareView> {
    const updated = await this.casUpdate(id, token, (r) => ({ ...r, status: "revoked" }));
    for (const f of updated.files) await this.store.delete(f.cipherKey).catch(() => {});
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

  /** Set, change, or clear (pass undefined) the passcode. */
  async setPasscode(id: string, token: string, passcode: string | undefined): Promise<ShareView> {
    const passcodeHash = passcode != null ? await hashPasscode(passcode) : undefined;
    return this.toView(await this.casUpdate(id, token, (r) => ({ ...r, passcodeHash })));
  }

  async accessLog(id: string, token: string) {
    const { record } = await this.requireOwner(id, token);
    return record.recipients;
  }

  async delete(id: string, token: string): Promise<void> {
    const { record } = await this.requireOwner(id, token);
    for (const f of record.files) await this.store.delete(f.cipherKey).catch(() => {});
    await this.store.delete(this.metaKeyFor(id)).catch(() => {});
  }

  // ---------- file operations (capability-token authed) ----------

  /** Add a file. Returns its server-minted fileId. */
  async addFile(id: string, token: string, ciphertext: Ciphertext): Promise<{ fileId: string; view: ShareView }> {
    const { record } = await this.requireOwner(id, token);
    const bytes = toBytes(ciphertext);
    const fileId = this.newFileId(record.files);
    const cipherKey = this.fileKeyFor(id, fileId);
    await this.store.put(cipherKey, bytes, { contentType: "application/jose", cacheControl: "no-store" }); // object first
    const updated = await this.casUpdate(id, token, (r) => ({ ...r, files: [...r.files, { fileId, cipherKey, len: bytes.length }] }));
    return { fileId, view: this.toView(updated) };
  }

  /** Replace one file's content (same fileId, same key/link). */
  async replaceFile(id: string, token: string, fileId: string, ciphertext: Ciphertext): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    const f = record.files.find((x) => x.fileId === fileId);
    if (!f) throw Errors.notFound();
    const bytes = toBytes(ciphertext);
    await this.store.put(f.cipherKey, bytes, { contentType: "application/jose", cacheControl: "no-store" });
    return this.toView(await this.casUpdate(id, token, (r) => ({
      ...r,
      files: r.files.map((x) => (x.fileId === fileId ? { ...x, len: bytes.length } : x)),
    })));
  }

  /** Delete one file from the share. */
  async deleteFile(id: string, token: string, fileId: string): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    const f = record.files.find((x) => x.fileId === fileId);
    if (!f) throw Errors.notFound();
    const updated = await this.casUpdate(id, token, (r) => ({ ...r, files: r.files.filter((x) => x.fileId !== fileId) }));
    await this.store.delete(f.cipherKey).catch(() => {}); // reclaim after removing the reference
    return this.toView(updated);
  }

  // ---------- internals ----------

  private async loadRecord(id: string): Promise<{ record: ShareRecord; etag: string } | null> {
    const obj = await this.store.get(this.metaKeyFor(id));
    if (!obj) return null;
    return { record: JSON.parse(tdDecode(obj.bytes)) as ShareRecord, etag: obj.etag };
  }

  /** Write the sidecar: CAS on capable backends, last-writer-wins otherwise. Returns false on CAS conflict. */
  private async writeMeta(id: string, record: ShareRecord, expectedEtag: string | null): Promise<boolean> {
    const body = teEncode(JSON.stringify(record));
    if (this.store.capabilities.conditionalWrite) {
      return (await this.store.conditionalPut(this.metaKeyFor(id), body, expectedEtag)) != null;
    }
    await this.store.put(this.metaKeyFor(id), body);
    return true;
  }

  private async requireOwner(id: string, token: string): Promise<{ record: ShareRecord; etag: string }> {
    const loaded = await this.loadRecord(id);
    if (!loaded) throw Errors.notFound();
    if (!(await this.tokenMatches(token, loaded.record))) throw Errors.notFound();
    return loaded;
  }
  private async tokenMatches(token: string, record: ShareRecord): Promise<boolean> {
    return token != null && timingSafeEqualHex(await sha256Hex(token), record.manageTokenHash);
  }

  /** CAS read-modify-write that re-verifies the capability token each attempt. */
  private async casUpdate(id: string, token: string, mutate: (r: ShareRecord) => ShareRecord): Promise<ShareRecord> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const loaded = await this.loadRecord(id);
      if (!loaded) throw Errors.notFound();
      if (!(await this.tokenMatches(token, loaded.record))) throw Errors.notFound();
      const next = mutate(loaded.record);
      if (next === loaded.record) return loaded.record; // no-op
      if (await this.writeMeta(id, next, loaded.etag)) return next;
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
      files: r.files.map((f) => ({ fileId: f.fileId, len: f.len })),
      directServable: this.isServable(r) && r.files.length === 1,
      exp: r.exp,
      maxUses: r.maxUses,
      audit: r.audit === true,
      useCount: r.useCount,
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

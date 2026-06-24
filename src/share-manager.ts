/**
 * share-manager.ts — the high-level surface app developers call. It turns "host
 * revocable, browser-fetchable SHLink files in a bucket" into method calls and
 * never exposes a raw bucket/key/presign operation.
 *
 * A share is a collection of files (0..N), each its own ciphertext object with a
 * declared (decrypted) content type, all under the link's one key. Management
 * (add/replace/delete files, settings, revoke) is uniform regardless of how a
 * recipient reads:
 *   - manifest rail (POST /shl/:id) serves any file count;
 *   - direct "U" rail (GET /shl/:id?recipient=) serves iff exactly one file AND
 *     no passcode (SHL: U SHALL NOT combine with P).
 *
 * Blind only: the client encrypts; the manager stores ciphertext +
 * sha256(manageToken) + opaque metadata, never the content key or plaintext.
 * Share ids are server-minted with 256 bits of entropy (SHL `url` requirement);
 * the constructor refuses a baseUrl that would push the shlink `url` over 128 chars.
 *
 * Use-counting and the passcode-failure budget are race-safe via the store's
 * conditionalPut (CAS) and require it (refused on non-CAS backends). Other
 * management writes fall back to last-writer-wins on non-CAS backends.
 */
import { hmacHex, randomId, randomToken, sha256Hex, timingSafeEqualHex } from "./crypto";
import type { ObjectStore } from "./object-store";
import { hashPasscode, verifyPasscode } from "./passcode";
import {
  ALLOWED_CONTENT_TYPES,
  type Ciphertext,
  type CreateInput,
  type CreateResult,
  DEFAULT_CONTENT_TYPE,
  type EffectiveStatus,
  Errors,
  type FileEntry,
  type FileInput,
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
  /** Max ciphertext size per file (DoS guard). Default 5 MiB. */
  maxFileBytes?: number;
  /** Consecutive incorrect-passcode budget before the link is disabled; reset on success. Default 5. */
  maxPasscodeFailures?: number;
  /** HMAC secret for location-rail tickets. Defaults to a per-process random (single-node only). */
  ticketSecret?: string;
}

export interface ManifestFile {
  contentType: string;
  embedded?: string;
  location?: string;
}
export interface Manifest {
  files: ManifestFile[];
}

const ID_BYTES = 32; // 256 bits of entropy for the share id (SHL `url` requirement)
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
  private maxFileBytes: number;
  private maxPasscodeFailures: number;
  private ticketSecret: string;

  constructor(cfg: ManagerConfig) {
    this.store = cfg.store;
    this.baseUrl = cfg.baseUrl.replace(/\/+$/, "");
    this.prefix = cfg.prefix ?? "shl/";
    this.maxRecipients = cfg.maxRecipientsLogged ?? 50;
    this.maxRetries = cfg.casMaxRetries ?? 8;
    this.maxEmbedded = cfg.maxEmbeddedBytes ?? 100_000;
    this.maxFileBytes = cfg.maxFileBytes ?? 5 * 1024 * 1024;
    this.maxPasscodeFailures = cfg.maxPasscodeFailures ?? 5;
    this.ticketSecret = cfg.ticketSecret ?? randomToken();

    // The shlink `url` (${baseUrl}/shl/${id}) SHALL NOT exceed 128 chars. A
    // 256-bit id is 43 base64url chars, so baseUrl must be <= 80 chars.
    const sampleLen = `${this.baseUrl}/shl/${"x".repeat(43)}`.length;
    if (sampleLen > 128) {
      throw new Error(`baseUrl too long: shlink url would be ${sampleLen} chars (>128). Use a shorter BASE_URL.`);
    }
  }

  get serviceBaseUrl(): string {
    return this.baseUrl;
  }
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
  private normFile(f: FileInput): { bytes: Uint8Array; contentType: string } {
    const isWrapped = typeof f !== "string" && !(f instanceof Uint8Array);
    const bytes = toBytes(isWrapped ? (f as any).ciphertext : (f as Ciphertext));
    const contentType = isWrapped ? ((f as any).contentType ?? DEFAULT_CONTENT_TYPE) : DEFAULT_CONTENT_TYPE;
    if (bytes.length > this.maxFileBytes) throw Errors.tooLarge(`file exceeds ${this.maxFileBytes} bytes`);
    if (!(ALLOWED_CONTENT_TYPES as readonly string[]).includes(contentType)) {
      throw Errors.badRequest(`contentType must be one of ${ALLOWED_CONTENT_TYPES.join(", ")}`);
    }
    return { bytes, contentType };
  }

  // ---------- create ----------

  async create(input: CreateInput): Promise<CreateResult> {
    const policy = input.policy ?? {};
    if (policy.maxUses != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("maxUses", "this backend lacks conditional writes for race-safe counting");
    }
    if (policy.passcode != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("passcode", "this backend lacks conditional writes for the lifetime attempt budget");
    }

    const norm: { bytes: Uint8Array; contentType: string }[] = [];
    if (input.ciphertext != null) norm.push(this.normFile(input.contentType ? { ciphertext: input.ciphertext, contentType: input.contentType } : input.ciphertext));
    for (const f of input.files ?? []) norm.push(this.normFile(f));
    if (norm.length === 0) throw Errors.badRequest("provide `ciphertext` or `files` (encrypt client-side; the service is blind)");

    const token = randomToken();
    const manageTokenHash = await sha256Hex(token);
    const passcodeHash = policy.passcode != null ? await hashPasscode(policy.passcode) : undefined;

    // 1) reserve the sidecar (atomic id allocation), with file entries referencing
    //    the to-be-written ciphertext objects.
    let id = "";
    let files: FileEntry[] = [];
    for (let attempt = 0; ; attempt++) {
      if (attempt >= this.maxRetries) throw Errors.conflict();
      id = randomId(ID_BYTES);
      files = [];
      for (const n of norm) {
        const fileId = this.newFileId(files);
        files.push({ fileId, cipherKey: this.fileKeyFor(id, fileId), len: n.bytes.length, contentType: n.contentType });
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
        passcodeFailures: 0,
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
        await this.store.put(files[i]!.cipherKey, norm[i]!.bytes, { contentType: "application/jose", cacheControl: "no-store" });
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

  /** Direct-file rail: GET <url>?recipient=. Single-file, non-passcoded shares only (SHL: no U+P). */
  async resolveDirect(id: string, opts: ResolveOptions = {}): Promise<ResolveResult> {
    const loaded = await this.loadRecord(id);
    if (!loaded || loaded.record.passcodeHash != null) throw Errors.notServable(); // U incompatible with passcode
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
        files.push({ contentType: f.contentType, embedded: jwe });
      } else {
        const ticket = await this.signTicket(id, f.fileId);
        files.push({ contentType: f.contentType, location: `${this.baseUrl}/shl/${id}/f/${f.fileId}?t=${ticket}` });
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

      // Servability (revoked/expired/exhausted/paused) is checked FIRST, so an
      // inactive share returns a uniform 404 and never leaks via a 401 or burns
      // the passcode budget.
      // isServable() now also covers a passcode-budget-disabled share, so an
      // exhausted link serves nothing — including via an outstanding ticket.
      if (!this.isServable(record)) throw Errors.notServable();
      let resetFailures = false;
      if (record.passcodeHash != null) {
        const ok = opts.passcode != null && (await verifyPasscode(opts.passcode, record.passcodeHash));
        if (!ok) throw Errors.passcodeRequired(await this.recordPasscodeFailure(id));
        resetFailures = record.passcodeFailures > 0; // a correct passcode resets the consecutive-failure budget
      }

      const counting = record.maxUses != null || record.audit === true;
      if (!counting && !resetFailures) return record; // read-only resolve

      const next: ShareRecord = {
        ...record,
        useCount: counting ? record.useCount + 1 : record.useCount,
        recipients: record.audit === true
          ? [...record.recipients, { at: nowSec(), recipient: opts.recipient ?? "Unknown" }].slice(-this.maxRecipients)
          : record.recipients,
        passcodeFailures: resetFailures ? 0 : record.passcodeFailures,
      };
      if (await this.writeMeta(id, next, etag)) return next;
      // lost the CAS race — reload and retry
    }
    throw Errors.conflict();
  }

  /** CAS-increment the lifetime failure counter (passcode shares are CAS-only). Returns remaining attempts. */
  private async recordPasscodeFailure(id: string): Promise<number> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const loaded = await this.loadRecord(id);
      if (!loaded) return 0;
      const next: ShareRecord = { ...loaded.record, passcodeFailures: loaded.record.passcodeFailures + 1 };
      if (await this.writeMeta(id, next, loaded.etag)) return Math.max(0, this.maxPasscodeFailures - next.passcodeFailures);
    }
    return 0;
  }

  private isServable(r: ShareRecord): boolean {
    if (r.status !== "active") return false;
    if (r.exp != null && nowSec() >= r.exp) return false;
    if (r.maxUses != null && r.useCount >= r.maxUses) return false;
    if (r.passcodeHash != null && r.passcodeFailures >= this.maxPasscodeFailures) return false; // brute-force budget exhausted
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

  /** Set, change, or clear (pass undefined) the passcode. Resets the failure budget. */
  async setPasscode(id: string, token: string, passcode: string | undefined): Promise<ShareView> {
    if (passcode != null && !this.store.capabilities.conditionalWrite) {
      throw Errors.unsupportedControl("passcode", "this backend lacks conditional writes for the lifetime attempt budget");
    }
    const passcodeHash = passcode != null ? await hashPasscode(passcode) : undefined;
    return this.toView(await this.casUpdate(id, token, (r) => ({ ...r, passcodeHash, passcodeFailures: 0 })));
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

  async addFile(id: string, token: string, ciphertext: Ciphertext, contentType?: string): Promise<{ fileId: string; view: ShareView }> {
    const { record } = await this.requireOwner(id, token);
    const { bytes, contentType: ct } = this.normFile(contentType ? { ciphertext, contentType } : ciphertext);
    const fileId = this.newFileId(record.files);
    const cipherKey = this.fileKeyFor(id, fileId);
    await this.store.put(cipherKey, bytes, { contentType: "application/jose", cacheControl: "no-store" }); // object first
    const updated = await this.casUpdate(id, token, (r) => ({ ...r, files: [...r.files, { fileId, cipherKey, len: bytes.length, contentType: ct }] }));
    return { fileId, view: this.toView(updated) };
  }

  async replaceFile(id: string, token: string, fileId: string, ciphertext: Ciphertext, contentType?: string): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    const f = record.files.find((x) => x.fileId === fileId);
    if (!f) throw Errors.notFound();
    const { bytes } = this.normFile(contentType ? { ciphertext, contentType } : ciphertext);
    await this.store.put(f.cipherKey, bytes, { contentType: "application/jose", cacheControl: "no-store" });
    return this.toView(await this.casUpdate(id, token, (r) => ({
      ...r,
      files: r.files.map((x) => (x.fileId === fileId ? { ...x, len: bytes.length, contentType: contentType ?? x.contentType } : x)),
    })));
  }

  async deleteFile(id: string, token: string, fileId: string): Promise<ShareView> {
    const { record } = await this.requireOwner(id, token);
    const f = record.files.find((x) => x.fileId === fileId);
    if (!f) throw Errors.notFound();
    const updated = await this.casUpdate(id, token, (r) => ({ ...r, files: r.files.filter((x) => x.fileId !== fileId) }));
    await this.store.delete(f.cipherKey).catch(() => {});
    return this.toView(updated);
  }

  // ---------- internals ----------

  private async loadRecord(id: string): Promise<{ record: ShareRecord; etag: string } | null> {
    const obj = await this.store.get(this.metaKeyFor(id));
    if (!obj) return null;
    return { record: JSON.parse(tdDecode(obj.bytes)) as ShareRecord, etag: obj.etag };
  }

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

  private async casUpdate(id: string, token: string, mutate: (r: ShareRecord) => ShareRecord): Promise<ShareRecord> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const loaded = await this.loadRecord(id);
      if (!loaded) throw Errors.notFound();
      if (!(await this.tokenMatches(token, loaded.record))) throw Errors.notFound();
      const next = mutate(loaded.record);
      if (next === loaded.record) return loaded.record;
      if (await this.writeMeta(id, next, loaded.etag)) return next;
    }
    throw Errors.conflict();
  }

  private effectiveStatus(r: ShareRecord): EffectiveStatus {
    if (r.status !== "active") return r.status;
    if (r.exp != null && nowSec() >= r.exp) return "expired";
    if (r.maxUses != null && r.useCount >= r.maxUses) return "exhausted";
    if (r.passcodeHash != null && r.passcodeFailures >= this.maxPasscodeFailures) return "disabled";
    return "active";
  }
  private toView(r: ShareRecord): ShareView {
    return {
      id: r.id,
      status: this.effectiveStatus(r),
      files: r.files.map((f) => ({ fileId: f.fileId, len: f.len, contentType: f.contentType })),
      // U rail needs exactly one file AND no passcode (SHL: no U+P).
      directServable: this.isServable(r) && r.files.length === 1 && r.passcodeHash == null,
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

/**
 * object-store.ts — the minimal port the service needs, plus an in-memory
 * adapter for dev/tests. Real adapters (S3-compatible, etc.) live in ./stores.
 *
 * Six verbs. App developers never call these directly — the ShareManager does.
 *
 * `conditionalPut` is the compare-and-swap primitive that makes race-safe
 * use-counting (and collision-safe id reservation) possible on a plain bucket:
 *   - expectedEtag === null  -> create-only-if-absent (If-None-Match: *)
 *   - expectedEtag === "..." -> replace-only-if-unchanged (If-Match: etag)
 * Returns null on precondition failure (the caller retries the read-modify-write).
 *
 * Backends that lack conditional writes (Backblaze B2; Wasabi unverified; GCS via
 * the S3/XML path) MUST set capabilities.conditionalWrite = false; the manager
 * then refuses use-limited shares on them (honesty rule) rather than miscounting.
 */

export interface PutOptions {
  contentType?: string;
  cacheControl?: string;
}
export interface GetResult {
  bytes: Uint8Array;
  etag: string;
}
export interface PutResult {
  etag: string;
}
export interface StoreCapabilities {
  conditionalWrite: boolean;
  presign: boolean;
  lifecycle: boolean;
}

export interface ObjectStore {
  readonly capabilities: StoreCapabilities;
  put(key: string, bytes: Uint8Array, opts?: PutOptions): Promise<PutResult>;
  get(key: string): Promise<GetResult | null>;
  head(key: string): Promise<{ etag: string; size: number } | null>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
  /** CAS write. See file header. Returns null on precondition failure. */
  conditionalPut(key: string, bytes: Uint8Array, expectedEtag: string | null, opts?: PutOptions): Promise<PutResult | null>;
  /** Short-lived signed GET — optional, generic; not used by the default flows. */
  presignGet?(key: string, ttlSeconds: number): Promise<string>;
}

/** In-memory store: full semantics incl. CAS. For tests and `STORE=memory` dev runs. */
export class MemoryObjectStore implements ObjectStore {
  readonly capabilities: StoreCapabilities = { conditionalWrite: true, presign: false, lifecycle: false };
  private m = new Map<string, { bytes: Uint8Array; etag: string }>();
  private seq = 0;
  private nextEtag(): string {
    return `"${++this.seq}"`;
  }
  async put(key: string, bytes: Uint8Array): Promise<PutResult> {
    const etag = this.nextEtag();
    this.m.set(key, { bytes, etag });
    return { etag };
  }
  async get(key: string): Promise<GetResult | null> {
    const e = this.m.get(key);
    return e ? { bytes: e.bytes, etag: e.etag } : null;
  }
  async head(key: string): Promise<{ etag: string; size: number } | null> {
    const e = this.m.get(key);
    return e ? { etag: e.etag, size: e.bytes.length } : null;
  }
  async delete(key: string): Promise<void> {
    this.m.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.m.keys()].filter((k) => k.startsWith(prefix));
  }
  async conditionalPut(key: string, bytes: Uint8Array, expectedEtag: string | null): Promise<PutResult | null> {
    const cur = this.m.get(key);
    if (expectedEtag === null) {
      if (cur) return null; // create-if-absent failed
    } else if (!cur || cur.etag !== expectedEtag) {
      return null; // replace-if-unchanged failed
    }
    const etag = this.nextEtag();
    this.m.set(key, { bytes, etag });
    return { etag };
  }
}

/**
 * stores/gcs.ts — an ObjectStore over Google Cloud Storage using its NATIVE API
 * (not the S3/XML interop endpoint). GCS has strong compare-and-swap via
 * generation preconditions, which the S3 path does NOT expose — so use-limits
 * work here through this adapter.
 *
 * Loaded only when STORE=gcs (dynamic import in index.ts). To use:
 *   bun add @google-cloud/storage
 *
 * CAS mapping: each object version has a numeric `generation`. We return it as
 * the port's opaque `etag`. conditionalPut sets `ifGenerationMatch`:
 *   - create-if-absent  -> ifGenerationMatch: 0  (succeeds only if absent)
 *   - replace-if-same   -> ifGenerationMatch: <generation>
 * A precondition failure surfaces as HTTP 412 -> we return null.
 */
import { Storage } from "@google-cloud/storage";
import type { GetResult, ObjectStore, PutOptions, PutResult, StoreCapabilities } from "../object-store";

export interface GcsStoreConfig {
  bucket: string;
  projectId?: string;
  /** Path to a service-account JSON key (or rely on ADC if omitted). */
  keyFilename?: string;
  /** Inline credentials, as an alternative to keyFilename. */
  credentials?: Record<string, unknown>;
  /** Override the API endpoint (e.g. a fake-gcs-server emulator). */
  apiEndpoint?: string;
}

export class GcsObjectStore implements ObjectStore {
  readonly capabilities: StoreCapabilities = { conditionalWrite: true, presign: false, lifecycle: true };
  private bucket;

  constructor(cfg: GcsStoreConfig) {
    const storage = new Storage({
      projectId: cfg.projectId,
      keyFilename: cfg.keyFilename,
      credentials: cfg.credentials as any,
      apiEndpoint: cfg.apiEndpoint,
    });
    this.bucket = storage.bucket(cfg.bucket);
  }

  private file(key: string, generation?: string) {
    return generation != null ? this.bucket.file(key, { generation: Number(generation) }) : this.bucket.file(key);
  }
  private saveOpts(opts: PutOptions, ifGenerationMatch?: number) {
    return {
      resumable: false,
      contentType: opts.contentType,
      ...(opts.cacheControl ? { metadata: { cacheControl: opts.cacheControl } } : {}),
      ...(ifGenerationMatch != null ? { preconditionOpts: { ifGenerationMatch } } : {}),
    };
  }

  async put(key: string, bytes: Uint8Array, opts: PutOptions = {}): Promise<PutResult> {
    const f = this.file(key);
    await f.save(bytes, this.saveOpts(opts));
    const [md] = await f.getMetadata();
    return { etag: String(md.generation) };
  }

  async get(key: string): Promise<GetResult | null> {
    try {
      const [md] = await this.file(key).getMetadata();
      const gen = String(md.generation);
      // pin the download to this exact generation so bytes + etag are consistent
      const [buf] = await this.file(key, gen).download();
      return { bytes: new Uint8Array(buf), etag: gen };
    } catch (e: any) {
      if (e?.code === 404) return null;
      throw e;
    }
  }

  async head(key: string): Promise<{ etag: string; size: number } | null> {
    try {
      const [md] = await this.file(key).getMetadata();
      return { etag: String(md.generation), size: Number(md.size ?? 0) };
    } catch (e: any) {
      if (e?.code === 404) return null;
      throw e;
    }
  }

  async delete(key: string): Promise<void> {
    await this.file(key).delete({ ignoreNotFound: true });
  }

  async list(prefix: string): Promise<string[]> {
    const [files] = await this.bucket.getFiles({ prefix });
    return files.map((f) => f.name);
  }

  async conditionalPut(key: string, bytes: Uint8Array, expectedEtag: string | null, opts: PutOptions = {}): Promise<PutResult | null> {
    const ifGenerationMatch = expectedEtag === null ? 0 : Number(expectedEtag);
    try {
      const f = this.file(key);
      await f.save(bytes, this.saveOpts(opts, ifGenerationMatch));
      const [md] = await f.getMetadata();
      return { etag: String(md.generation) };
    } catch (e: any) {
      if (e?.code === 412) return null; // generation precondition failed -> CAS lost
      throw e;
    }
  }
}

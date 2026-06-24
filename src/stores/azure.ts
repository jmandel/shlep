/**
 * stores/azure.ts — an ObjectStore over Azure Blob Storage. Azure is not
 * S3-compatible, so it needs its own adapter; it has long-standing optimistic
 * concurrency via ETag conditions, so use-limits work here.
 *
 * Loaded only when STORE=azure (dynamic import in index.ts). To use:
 *   bun add @azure/storage-blob
 *
 * CAS mapping: every blob write returns a new ETag. conditionalPut sets the
 * upload `conditions`:
 *   - create-if-absent  -> ifNoneMatch: "*"   (fails if the blob exists)
 *   - replace-if-same   -> ifMatch: <etag>
 * A precondition failure surfaces as HTTP 412 (or 409 on create races) -> null.
 */
import { BlobServiceClient, StorageSharedKeyCredential } from "@azure/storage-blob";
import type { GetResult, ObjectStore, PutOptions, PutResult, StoreCapabilities } from "../object-store";

export interface AzureStoreConfig {
  container: string;
  /** Either a full connection string… */
  connectionString?: string;
  /** …or an account URL (+ shared key for writes). */
  accountUrl?: string; // https://<account>.blob.core.windows.net
  accountName?: string;
  accountKey?: string;
}

async function streamToU8(stream: NodeJS.ReadableStream | undefined): Promise<Uint8Array> {
  if (!stream) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  for await (const c of stream as AsyncIterable<Uint8Array | string>) {
    chunks.push(typeof c === "string" ? new TextEncoder().encode(c) : new Uint8Array(c));
  }
  return new Uint8Array(await new Blob(chunks).arrayBuffer());
}

export class AzureObjectStore implements ObjectStore {
  readonly capabilities: StoreCapabilities = { conditionalWrite: true, presign: false, lifecycle: true };
  private container;

  constructor(cfg: AzureStoreConfig) {
    let svc: BlobServiceClient;
    if (cfg.connectionString) {
      svc = BlobServiceClient.fromConnectionString(cfg.connectionString);
    } else if (cfg.accountUrl && cfg.accountName && cfg.accountKey) {
      svc = new BlobServiceClient(cfg.accountUrl, new StorageSharedKeyCredential(cfg.accountName, cfg.accountKey));
    } else if (cfg.accountUrl) {
      svc = new BlobServiceClient(cfg.accountUrl);
    } else {
      throw new Error("Azure: provide connectionString or accountUrl (+ accountName/accountKey for writes)");
    }
    this.container = svc.getContainerClient(cfg.container);
  }

  private blob(key: string) {
    return this.container.getBlockBlobClient(key);
  }
  private headers(opts: PutOptions) {
    return { blobHTTPHeaders: { blobContentType: opts.contentType, blobCacheControl: opts.cacheControl } };
  }

  async put(key: string, bytes: Uint8Array, opts: PutOptions = {}): Promise<PutResult> {
    const r = await this.blob(key).upload(Buffer.from(bytes), bytes.length, this.headers(opts));
    return { etag: r.etag ?? "" };
  }

  async get(key: string): Promise<GetResult | null> {
    try {
      const dl = await this.blob(key).download();
      return { bytes: await streamToU8(dl.readableStreamBody), etag: dl.etag ?? "" };
    } catch (e: any) {
      if (e?.statusCode === 404) return null;
      throw e;
    }
  }

  async head(key: string): Promise<{ etag: string; size: number } | null> {
    try {
      const p = await this.blob(key).getProperties();
      return { etag: p.etag ?? "", size: p.contentLength ?? 0 };
    } catch (e: any) {
      if (e?.statusCode === 404) return null;
      throw e;
    }
  }

  async delete(key: string): Promise<void> {
    await this.blob(key).deleteIfExists();
  }

  async list(prefix: string): Promise<string[]> {
    const out: string[] = [];
    for await (const b of this.container.listBlobsFlat({ prefix })) out.push(b.name);
    return out;
  }

  async conditionalPut(key: string, bytes: Uint8Array, expectedEtag: string | null, opts: PutOptions = {}): Promise<PutResult | null> {
    const conditions = expectedEtag === null ? { ifNoneMatch: "*" } : { ifMatch: expectedEtag };
    try {
      const r = await this.blob(key).upload(Buffer.from(bytes), bytes.length, { ...this.headers(opts), conditions });
      return { etag: r.etag ?? "" };
    } catch (e: any) {
      if (e?.statusCode === 412 || e?.statusCode === 409) return null; // precondition failed -> CAS lost
      throw e;
    }
  }
}

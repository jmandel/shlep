/**
 * stores/s3.ts — an ObjectStore over any S3-compatible backend (AWS S3,
 * Cloudflare R2, MinIO, Backblaze B2, Wasabi, GCS via its XML/S3 endpoint).
 *
 * Loaded only when STORE=s3 (dynamic import in index.ts), so `bun test` against
 * the in-memory store needs no AWS SDK installed. To use it:
 *   bun add @aws-sdk/client-s3 @aws-sdk/s3-request-presigner
 *
 * CAS NOTE (honesty rule): conditional writes are NOT universal across
 * "S3-compatible" stores. AWS S3 (2024+), R2, and MinIO support If-None-Match /
 * If-Match on PutObject; Backblaze B2 does NOT; Wasabi is unverified; GCS's CAS
 * (ifGenerationMatch) is JSON-API only, NOT the S3/XML path. Set
 * `conditionalWrite: false` in config for backends without it — the manager will
 * then refuse use-limited shares rather than miscount.
 */
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import type { GetResult, ObjectStore, PutOptions, PutResult, StoreCapabilities } from "../object-store";

export interface S3StoreConfig {
  bucket: string;
  region?: string;
  endpoint?: string; // R2/MinIO/B2/etc.
  forcePathStyle?: boolean; // MinIO / some S3-compatibles
  accessKeyId?: string;
  secretAccessKey?: string;
  /** Set false for B2/Wasabi/GCS-via-S3 (no conditional writes). Default true. */
  conditionalWrite?: boolean;
}

const toBytes = async (body: any): Promise<Uint8Array> => {
  if (!body) return new Uint8Array(0);
  if (typeof body.transformToByteArray === "function") return new Uint8Array(await body.transformToByteArray());
  const chunks: Uint8Array[] = [];
  for await (const c of body as AsyncIterable<Uint8Array>) chunks.push(c);
  return new Uint8Array(await new Blob(chunks).arrayBuffer());
};

export class S3ObjectStore implements ObjectStore {
  readonly capabilities: StoreCapabilities;
  private s3: S3Client;
  private bucket: string;

  constructor(cfg: S3StoreConfig) {
    this.bucket = cfg.bucket;
    this.s3 = new S3Client({
      region: cfg.region ?? "us-east-1",
      endpoint: cfg.endpoint,
      forcePathStyle: cfg.forcePathStyle,
      credentials:
        cfg.accessKeyId && cfg.secretAccessKey
          ? { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey }
          : undefined,
    });
    this.capabilities = {
      conditionalWrite: cfg.conditionalWrite ?? true,
      presign: true,
      lifecycle: true,
    };
  }

  async put(key: string, bytes: Uint8Array, opts: PutOptions = {}): Promise<PutResult> {
    const out = await this.s3.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: bytes,
        ContentType: opts.contentType,
        CacheControl: opts.cacheControl,
      }),
    );
    return { etag: out.ETag ?? "" };
  }

  async get(key: string): Promise<GetResult | null> {
    try {
      const out = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
      return { bytes: await toBytes(out.Body), etag: out.ETag ?? "" };
    } catch (e: any) {
      if (e?.$metadata?.httpStatusCode === 404 || e?.name === "NoSuchKey") return null;
      throw e;
    }
  }

  async head(key: string): Promise<{ etag: string; size: number } | null> {
    try {
      const out = await this.s3.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return { etag: out.ETag ?? "", size: out.ContentLength ?? 0 };
    } catch (e: any) {
      if (e?.$metadata?.httpStatusCode === 404) return null;
      throw e;
    }
  }

  async delete(key: string): Promise<void> {
    await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }

  async list(prefix: string): Promise<string[]> {
    const keys: string[] = [];
    let token: string | undefined;
    do {
      const out = await this.s3.send(
        new ListObjectsV2Command({ Bucket: this.bucket, Prefix: prefix, ContinuationToken: token }),
      );
      for (const o of out.Contents ?? []) if (o.Key) keys.push(o.Key);
      token = out.IsTruncated ? out.NextContinuationToken : undefined;
    } while (token);
    return keys;
  }

  async conditionalPut(key: string, bytes: Uint8Array, expectedEtag: string | null, opts: PutOptions = {}): Promise<PutResult | null> {
    if (!this.capabilities.conditionalWrite) {
      throw new Error("conditionalPut called on a backend configured without conditional writes");
    }
    try {
      const out = await this.s3.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: key,
          Body: bytes,
          ContentType: opts.contentType,
          CacheControl: opts.cacheControl,
          // create-if-absent vs replace-if-unchanged
          IfNoneMatch: expectedEtag === null ? "*" : undefined,
          IfMatch: expectedEtag !== null ? expectedEtag : undefined,
        }),
      );
      return { etag: out.ETag ?? "" };
    } catch (e: any) {
      const code = e?.$metadata?.httpStatusCode;
      if (code === 412 || code === 409 || e?.name === "PreconditionFailed") return null; // CAS lost
      throw e;
    }
  }

  async presignGet(key: string, ttlSeconds: number): Promise<string> {
    return getSignedUrl(this.s3, new GetObjectCommand({ Bucket: this.bucket, Key: key }), { expiresIn: ttlSeconds });
  }
}

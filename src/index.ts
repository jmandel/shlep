/**
 * index.ts — entry point. Wires an ObjectStore + ShareManager + fetch handler
 * from env and serves it with Bun.serve.
 *
 *   STORE=memory (default) | s3 | gcs | azure
 *   BASE_URL=https://shl.example.com         (public base for the service)
 *   PORT=8788
 *   CREATE_TOKEN=...   (optional: require this bearer to POST /shares)
 *   ADMIN_TOKEN=...    (optional: enable GET /admin/shares)
 *   DEFAULT_MODE=mediated | direct
 *   TICKET_SECRET=...  (HMAC secret for location-rail tickets; set in prod/multi-node)
 *
 *   S3-compatible (STORE=s3 — AWS S3, Cloudflare R2, MinIO, Backblaze B2, Wasabi):
 *     S3_BUCKET, S3_REGION, S3_ENDPOINT, S3_FORCE_PATH_STYLE=1,
 *     S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY,
 *     S3_CONDITIONAL_WRITE=0   (set 0 for B2/Wasabi — disables maxUses)
 *
 *   Google Cloud Storage (STORE=gcs):
 *     GCS_BUCKET, GCP_PROJECT, GOOGLE_APPLICATION_CREDENTIALS (ADC if omitted)
 *
 *   Azure Blob (STORE=azure):
 *     AZURE_CONTAINER, and either AZURE_STORAGE_CONNECTION_STRING
 *     or AZURE_ACCOUNT_URL (+ AZURE_ACCOUNT_NAME / AZURE_ACCOUNT_KEY)
 *
 *   bun run src/index.ts
 */
import { MemoryObjectStore, type ObjectStore } from "./object-store";
import { createFetchHandler } from "./server";
import { ShareManager } from "./share-manager";

const env = (k: string, d?: string) => process.env[k] ?? d;

async function buildStore(): Promise<ObjectStore> {
  const store = env("STORE", "memory");
  if (store === "s3") {
    const { S3ObjectStore } = await import("./stores/s3");
    return new S3ObjectStore({
      bucket: env("S3_BUCKET")!,
      region: env("S3_REGION"),
      endpoint: env("S3_ENDPOINT"),
      forcePathStyle: env("S3_FORCE_PATH_STYLE") === "1",
      accessKeyId: env("S3_ACCESS_KEY_ID"),
      secretAccessKey: env("S3_SECRET_ACCESS_KEY"),
      conditionalWrite: env("S3_CONDITIONAL_WRITE", "1") !== "0",
    });
  }
  if (store === "gcs") {
    const { GcsObjectStore } = await import("./stores/gcs");
    return new GcsObjectStore({
      bucket: env("GCS_BUCKET")!,
      projectId: env("GCP_PROJECT"),
      keyFilename: env("GOOGLE_APPLICATION_CREDENTIALS"),
    });
  }
  if (store === "azure") {
    const { AzureObjectStore } = await import("./stores/azure");
    return new AzureObjectStore({
      container: env("AZURE_CONTAINER")!,
      connectionString: env("AZURE_STORAGE_CONNECTION_STRING"),
      accountUrl: env("AZURE_ACCOUNT_URL"),
      accountName: env("AZURE_ACCOUNT_NAME"),
      accountKey: env("AZURE_ACCOUNT_KEY"),
    });
  }
  return new MemoryObjectStore();
}

const baseUrl = env("BASE_URL", "http://localhost:8788")!;
const mgr = new ShareManager({
  store: await buildStore(),
  baseUrl,
  ticketSecret: env("TICKET_SECRET"),
});

const handler = createFetchHandler(mgr, {
  createToken: env("CREATE_TOKEN"),
  adminToken: env("ADMIN_TOKEN"),
});

const port = Number(env("PORT", "8788"));
Bun.serve({ port, fetch: handler });
console.log(`shlep listening on :${port}  (base ${baseUrl}, store ${env("STORE", "memory")})`);

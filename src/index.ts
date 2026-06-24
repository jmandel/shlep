/**
 * index.ts — entry point. Wires an ObjectStore + ShareManager + fetch handler
 * from env and serves it with Bun.serve.
 *
 *   STORE=memory (default) | s3
 *   BASE_URL=https://shl.example.com         (public base for mediated links)
 *   PORT=8788
 *   CREATE_TOKEN=...   (optional: require this bearer to POST /shares)
 *   ADMIN_TOKEN=...    (optional: enable GET /admin/shares)
 *   DEFAULT_MODE=mediated | direct
 *   TICKET_SECRET=...  (HMAC secret for location-rail tickets; set in prod/multi-node)
 *
 *   S3 backend (STORE=s3):
 *     S3_BUCKET, S3_REGION, S3_ENDPOINT, S3_FORCE_PATH_STYLE=1,
 *     S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_PUBLIC_BASE,
 *     S3_CONDITIONAL_WRITE=0   (set 0 for B2/Wasabi/GCS-via-S3)
 *
 *   bun run src/index.ts
 */
import { MemoryObjectStore, type ObjectStore } from "./object-store";
import { createFetchHandler } from "./server";
import { ShareManager } from "./share-manager";

const env = (k: string, d?: string) => process.env[k] ?? d;

async function buildStore(): Promise<ObjectStore> {
  if (env("STORE", "memory") === "s3") {
    const { S3ObjectStore } = await import("./stores/s3");
    return new S3ObjectStore({
      bucket: env("S3_BUCKET")!,
      region: env("S3_REGION"),
      endpoint: env("S3_ENDPOINT"),
      forcePathStyle: env("S3_FORCE_PATH_STYLE") === "1",
      accessKeyId: env("S3_ACCESS_KEY_ID"),
      secretAccessKey: env("S3_SECRET_ACCESS_KEY"),
      publicBase: env("S3_PUBLIC_BASE"),
      conditionalWrite: env("S3_CONDITIONAL_WRITE", "1") !== "0",
    });
  }
  return new MemoryObjectStore();
}

const baseUrl = env("BASE_URL", "http://localhost:8788")!;
const mgr = new ShareManager({
  store: await buildStore(),
  baseUrl,
  defaultMode: (env("DEFAULT_MODE", "mediated") as "mediated" | "direct"),
  ticketSecret: env("TICKET_SECRET"),
});

const handler = createFetchHandler(mgr, {
  createToken: env("CREATE_TOKEN"),
  adminToken: env("ADMIN_TOKEN"),
});

const port = Number(env("PORT", "8788"));
Bun.serve({ port, fetch: handler });
console.log(`shlep listening on :${port}  (base ${baseUrl}, store ${env("STORE", "memory")})`);

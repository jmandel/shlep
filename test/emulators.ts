/**
 * emulators.ts — build each cloud adapter pointed at a local emulator, ensuring
 * its bucket/container exists. Gated by env so the default `bun test` run (no
 * emulators) stays green; `scripts/test-emulators.sh` sets these.
 *
 *   SHLEP_TEST_S3=1     -> MinIO        on http://127.0.0.1:9000
 *   SHLEP_TEST_AZURE=1  -> Azurite      on http://127.0.0.1:10000
 *   SHLEP_TEST_GCS=1    -> fake-gcs     on http://127.0.0.1:4443
 */
import { CreateBucketCommand, S3Client } from "@aws-sdk/client-s3";
import { BlobServiceClient } from "@azure/storage-blob";
import { Storage } from "@google-cloud/storage";
import { S3ObjectStore } from "../src/stores/s3";
import { AzureObjectStore } from "../src/stores/azure";
import { GcsObjectStore } from "../src/stores/gcs";

export const EMU = {
  s3: process.env.SHLEP_TEST_S3 === "1",
  azure: process.env.SHLEP_TEST_AZURE === "1",
  gcs: process.env.SHLEP_TEST_GCS === "1",
};

const BUCKET = "shlep-test";

const S3_CFG = {
  bucket: BUCKET,
  region: "us-east-1",
  endpoint: "http://127.0.0.1:9000",
  forcePathStyle: true,
  accessKeyId: "minioadmin",
  secretAccessKey: "minioadmin",
};

export async function s3Store(): Promise<S3ObjectStore> {
  const c = new S3Client({
    region: S3_CFG.region,
    endpoint: S3_CFG.endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId: S3_CFG.accessKeyId, secretAccessKey: S3_CFG.secretAccessKey },
  });
  try {
    await c.send(new CreateBucketCommand({ Bucket: BUCKET }));
  } catch (e: any) {
    if (!/BucketAlreadyOwnedByYou|BucketAlreadyExists/.test(e?.name ?? "")) throw e;
  }
  return new S3ObjectStore(S3_CFG);
}

// Azurite's well-known dev account.
const AZ_CONN =
  "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;" +
  "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;" +
  "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;";

export async function azureStore(): Promise<AzureObjectStore> {
  await BlobServiceClient.fromConnectionString(AZ_CONN).getContainerClient(BUCKET).createIfNotExists();
  return new AzureObjectStore({ container: BUCKET, connectionString: AZ_CONN });
}

const GCS_ENDPOINT = "http://127.0.0.1:4443";

export async function gcsStore(): Promise<GcsObjectStore> {
  // A custom apiEndpoint puts the client in anonymous custom-endpoint mode (no
  // ADC) and uses /storage/v1 paths. (Do NOT set STORAGE_EMULATOR_HOST — that
  // forces the old bare-path convention that fake-gcs-server doesn't serve.)
  const storage = new Storage({ apiEndpoint: GCS_ENDPOINT, projectId: "test" });
  try {
    await storage.createBucket(BUCKET);
  } catch (e: any) {
    if (e?.code !== 409) throw e; // already exists
  }
  return new GcsObjectStore({ bucket: BUCKET, projectId: "test", apiEndpoint: GCS_ENDPOINT });
}

import { MemoryObjectStore } from "../src/object-store";
import { objectStoreContract } from "./conformance";

// The in-memory store runs the full contract in CI.
objectStoreContract("memory", () => new MemoryObjectStore());

// To verify a cloud adapter, install its SDK and point the contract at a real
// bucket or an emulator, e.g.:
//
//   import { S3ObjectStore } from "../src/stores/s3";
//   objectStoreContract("minio", () => new S3ObjectStore({
//     bucket: "shlep-test", endpoint: "http://127.0.0.1:9000",
//     forcePathStyle: true, accessKeyId: "minioadmin", secretAccessKey: "minioadmin",
//   }));
//
// Same shape for GcsObjectStore (fake-gcs-server) and AzureObjectStore (Azurite).

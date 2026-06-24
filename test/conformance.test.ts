import { MemoryObjectStore } from "../src/object-store";
import { objectStoreContract } from "./conformance";
import { azureStore, EMU, gcsStore, s3Store } from "./emulators";

// The in-memory store runs the full contract in CI, always.
objectStoreContract("memory", () => new MemoryObjectStore());

// Cloud adapters run when their emulator is up (see scripts/test-emulators.sh):
// MinIO (S3 API), Azurite (Azure Blob), fake-gcs-server (GCS native API).
if (EMU.s3) objectStoreContract("s3 · minio", s3Store);
if (EMU.azure) objectStoreContract("azure · azurite", azureStore);
if (EMU.gcs) objectStoreContract("gcs · fake-gcs-server", gcsStore);

import { describe, expect, test } from "bun:test";
import { bodyToBytes } from "../src/bytes";
import { MemoryObjectStore } from "../src/object-store";
import { objectStoreContract } from "./conformance";
import { azureStore, EMU, gcsStore, s3Store } from "./emulators";

describe("byte bodies", () => {
  test("bodyToBytes handles standard chunks and streams", async () => {
    const bytes = await bodyToBytes(
      (async function* () {
        yield new TextEncoder().encode("ab");
        yield "cd";
        yield new Uint8Array([101]).buffer;
      })(),
    );
    expect(new TextDecoder().decode(bytes)).toBe("abcde");
  });
});

// The in-memory store runs the full contract in CI, always.
objectStoreContract("memory", () => new MemoryObjectStore());

// Cloud adapters run when their emulator is up (see scripts/test-emulators.sh):
// MinIO (S3 API), Azurite (Azure Blob), fake-gcs-server (GCS native API).
if (EMU.s3) objectStoreContract("s3 · minio", s3Store);
if (EMU.azure) objectStoreContract("azure · azurite", azureStore);
if (EMU.gcs) objectStoreContract("gcs · fake-gcs-server", gcsStore);

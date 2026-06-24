# shlep

> **SHL Encrypted Proxy** — *schlep your health data anywhere.*

Blind, revocable **SMART Health Links** backed by any cloud **object store** —
without writing raw bucket/key/presign/CORS code, and **without the host ever
seeing the content encryption key**.

- The client encrypts; the service stores only ciphertext + a hashed capability
  token + opaque metadata. The content key lives only in the link `#fragment`.
- Two modes, one service: **direct** (link points at the bucket object; revoke =
  delete) and **mediated** (link points at the service; it enforces expiry,
  use-limits, passcode, pause, revoke, and an access log).
- Runs on Bun (and any Web-standard runtime; the handler is a plain `fetch`).

Spec: [`docs/api-design.md`](./docs/api-design.md). Background exploration:
[`docs/background-prd.md`](./docs/background-prd.md).

## Quickstart

```bash
bun install            # dev types only; AWS SDK is optional (S3 backend)
bun test               # 13 tests, in-memory store, no cloud creds
bun run start          # STORE=memory on :8788
```

Real backend:

```bash
bun add @aws-sdk/client-s3 @aws-sdk/s3-request-presigner
STORE=s3 S3_BUCKET=my-bucket S3_REGION=auto \
  S3_ENDPOINT=https://<acct>.r2.cloudflarestorage.com \
  S3_ACCESS_KEY_ID=… S3_SECRET_ACCESS_KEY=… \
  S3_PUBLIC_BASE=https://files.example.com \
  BASE_URL=https://shl.example.com \
  bun run start
```

The bucket needs a permissive CORS rule so browser viewers can fetch the
ciphertext cross-origin (see `docs/api-design.md` §6/§7).

## The blind flow (client ↔ service)

```ts
import { encryptBundle, composeViewerLink, openSealed } from "./src/client";

// 1. CLIENT encrypts — the key is born here and never leaves.
const sealed = await encryptBundle(JSON.stringify(bundle));   // {jwe, key, keyB64}

// 2. Upload ONLY ciphertext. Server returns the file URL + the manage token (once).
const res = await fetch("https://shl.example.com/shares", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ mode: "mediated", ciphertext: sealed.jwe, policy: { maxUses: 5, label: "Cycle export" } }),
}).then((r) => r.json());                                     // {id, fileUrl, manageToken}

// 3. CLIENT composes the link with its own key — show as QR + copy/share.
const link = composeViewerLink("https://periodicity.fhir.me/", res.fileUrl, sealed.keyB64, { label: "Cycle export" });

// 4. Later: revoke (needs the manage token only — it can't decrypt anything).
await fetch(`https://shl.example.com/shares/${res.id}`, {
  method: "DELETE",
  headers: { authorization: `Bearer ${res.manageToken}` },
});
```

The receiver opens `link`, the viewer `fetch`es `fileUrl` (`?recipient=…`),
decrypts with the fragment key, and renders. The service saw only ciphertext.

## Layout

```
src/
  types.ts          shared types + ShlError
  crypto.ts         compact JWE (ported from the IG viewer) + hashing/HMAC helpers
  shlink.ts         shlink:/ encode/decode + viewer link
  object-store.ts   the ObjectStore port + MemoryObjectStore
  stores/s3.ts      S3-compatible adapter (AWS/R2/MinIO/B2/Wasabi/GCS-XML)
  share-manager.ts  the high-level API: create/resolve/revoke/… + CAS counting
  server.ts         framework-agnostic fetch handler (data + control plane)
  client.ts         CLIENT side of the blind boundary (encrypt + compose link)
  index.ts          env wiring + Bun.serve
test/               manager + http round-trip tests
docs/               api-design.md (authoritative) + background-prd.md
```

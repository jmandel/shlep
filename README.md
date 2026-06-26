# shlep

> **SHL Encrypted Proxy** — *schlep your health data anywhere.*

Blind, revocable **SMART Health Links** backed by any cloud **object store** —
without writing raw bucket/key/presign/CORS code, and **without the host ever
seeing the content encryption key**.

- The client encrypts; the service stores only ciphertext + a hashed capability
  token + opaque metadata. The content key lives only in the link `#fragment`.
- Every link points at the service, which enforces expiry, use-limits, passcode,
  pause, revoke, and an opt-in access log. A resolve reads the sidecar to enforce
  those; it only *writes* when the share opted into `maxUses` or `audit`, so
  unlimited links stay cheap.
- Runs on Bun (and any Web-standard runtime; the handler is a plain `fetch`).

Spec: [`docs/api-design.md`](./docs/api-design.md). Historical background:
[`docs/background-prd.md`](./docs/background-prd.md) is design exploration, not
current API behavior when it differs from the spec or code.

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
  BASE_URL=https://shl.example.com \
  bun run start
```

The service is in the read path, so the bucket can stay **private** — browsers
fetch the ciphertext from the service (`/shl/:id`), which sets CORS.

**Backends** (set `STORE=`): `s3` covers AWS S3, Cloudflare R2, MinIO, Backblaze
B2, and Wasabi; `gcs` is a native Google Cloud Storage adapter; `azure` is a
native Azure Blob adapter; `memory` is for dev. `maxUses` needs compare-and-swap,
which every major provider supports — AWS S3, R2, MinIO, GCS, and Azure all do.
Only Backblaze B2 and Wasabi lack it (a provider limitation): there you set
`S3_CONDITIONAL_WRITE=0`, `maxUses` is refused, and everything else still works.

The cloud adapters share one contract (`test/conformance.ts`). CI runs it against
the in-memory store and against MinIO, Azurite, and fake-gcs-server, so the S3,
Azure, and GCS adapters are certified on real wire behavior — CAS included. See
`docs/api-design.md` §6.

## Tests

```bash
bun test                 # unit: manager + server + contract vs in-memory store
bun run test:emulators   # certify the S3/Azure/GCS adapters against MinIO /
                         # Azurite / fake-gcs-server (needs Docker)
```

## Self-documentation

A running instance serves an agent-readable integration guide at **`GET /llms.txt`**
(and a pointer at `GET /`), tailored to that instance — its base URL, whether create
is open or token-gated, and whether the backend supports `maxUses`. Emit it as a
static file with `bun run scripts/gen-llms.ts > llms.txt`.

## The blind flow (client ↔ service)

```ts
import { encryptBundle, composeViewerLink, openSealed } from "./src/client";

// 1. CLIENT encrypts — the key is born here and never leaves.
const sealed = await encryptBundle(JSON.stringify(bundle));   // {jwe, key, keyB64}

// 2. Upload ONLY ciphertext. Server returns the file URL + the manage token (once).
const res = await fetch("https://shl.example.com/shares", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ ciphertext: sealed.jwe, policy: { maxUses: 5, audit: true } }),
}).then((r) => r.json());                                     // {id, fileUrl, manageToken}

// 3. CLIENT composes the link with its own key — show as QR + copy/share.
//    flag:"U" = the single-GET direct-file rail (valid here: one file, no passcode).
//    Omit `flag` for the manifest rail (any file count, required if passcoded/multi-file).
const link = composeViewerLink("https://cycle.fhir.me/view", res.fileUrl, sealed.keyB64, { flag: "U", label: "Cycle export" });

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
  stores/s3.ts      S3-compatible adapter (AWS S3 / R2 / MinIO / B2 / Wasabi)
  stores/gcs.ts     native Google Cloud Storage adapter
  stores/azure.ts   native Azure Blob adapter
  share-manager.ts  the high-level API: create/resolve/revoke/… + CAS counting
  server.ts         framework-agnostic fetch handler (data + control plane + /llms.txt)
  llms.ts           renders the instance-tailored /llms.txt integration guide
  passcode.ts       salted-PBKDF2 passcode hashing (WebCrypto)
  client.ts         CLIENT side of the blind boundary (encrypt + compose link)
  index.ts          env wiring + Bun.serve
test/               manager + http tests; conformance.ts (the ObjectStore contract);
                    emulators.ts (adapters wired to MinIO / Azurite / fake-gcs)
scripts/            build-site.ts, test-emulators.sh
docs/               api-design.md (authoritative) + background-prd.md
```

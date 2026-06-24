# API design — shlep (SHL Encrypted Proxy)

Authoritative spec for the implementation in `../src`. Supersedes the exploratory
[`background-prd.md`](./background-prd.md); where they differ, this document and the
code win. Every open question the PRD raised is closed in [§9](#9-closed-decisions).

## 1. What this is

A small library + HTTP service that hosts **SMART Health Links** in a commodity
**object store** and makes them **revocable** — without the app developer ever
writing a raw bucket/key/presign/CORS call, and **without the host ever seeing the
content encryption key**.

Every share's link points at the service (`${baseUrl}/shl/${id}`), and every read
is resolved through it. Because the service is always in the read path, revocation,
expiry, passcode, pause, and use-limits are all enforceable, and the bucket can
stay private.

The cost of being in the read path is bounded by what the share asks for:

| share has… | a resolve does | per-read storage ops |
|---|---|---|
| nothing (unlimited, unaudited) | read the sidecar, enforce revoke/expiry/passcode | **1 read** |
| `maxUses` and/or `audit` | the above + a CAS write to bump the counter / log the recipient | **1 read + 1 CAS write** |

So you only pay the write when you opted into counting or an access log.

## 2. The blind invariant (the only path)

There is exactly one content path: **the client encrypts; the service stores
opaque ciphertext.** There is no server-side-encryption mode — that knob is
deliberately absent to keep the state space (and the trust boundary) small.

- The **content key** is generated on the client, used to produce a compact JWE
  (`alg:"dir"`, `enc:"A256GCM"`), and placed only in the link **fragment**
  (`#shlink:/…`). It never reaches the service.
- The service stores: ciphertext bytes, a JSON **sidecar** of opaque metadata,
  and `sha256(manageToken)`. It can enforce link *settings* but can never read
  content.
- The **manage token** is minted by the service and returned **once** at create.
  It is a capability over settings (revoke/expiry/limits), independent of the
  content key, and **cannot decrypt anything**.

Two secrets, each born where it is needed: the content key on the client, the
manage token on the service. Neither crosses to the other party.

## 3. HTTP API

### Data plane (public, CORS `*`)

| Method · path | Body / query | Returns |
|---|---|---|
| `GET /shl/:id?recipient=` | — | `application/jose` (the JWE). Counts/logs iff the share opted in. |
| `POST /shl/:id` | `{recipient, passcode?, embeddedLengthMax?}` | manifest `{files:[{contentType, embedded \| location}]}`. Counts/logs iff opted in. |
| `GET /shl/:id/f/:fileId?t=` | HMAC ticket `t` | `application/jose`. **No** count (the manifest POST already accounted for it). |
| `OPTIONS *` | — | CORS preflight (204) |

`recipient` is always accepted (the SHL viewer appends it). It is consumed by the
service and **never forwarded to storage**; it is recorded in the access log only
when the share set `audit`. Any non-servable link (missing, revoked, expired,
exhausted, paused) returns a **uniform 404** so existence never leaks.

### Control plane (`Authorization: Bearer <manageToken>`)

| Method · path | Body | Effect |
|---|---|---|
| `POST /shares` | `{ciphertext, policy?}` | create → `{id, status, fileUrl, manageToken}` (201) |
| `GET /shares/:id` | — | current `ShareView` |
| `DELETE /shares/:id` | — | revoke |
| `POST /shares/:id/pause` · `/resume` | — | pause / resume |
| `POST /shares/:id/extend` | `{exp}` | change expiry |
| `POST /shares/:id/limits` | `{maxUses}` | change use-limit |
| `GET /shares/:id/log` | — | recipient access log (entries exist only if `audit`) |
| `GET /admin/shares` | `Bearer <adminToken>` | ops list (off unless configured) |

`policy` = `{ exp?, maxUses?, label?, passcode?, audit? }`.

`ciphertext` travels as a compact-JWE **string** (ASCII; JSON-safe). Wrong or
missing manage token on any `/shares/:id*` route → **404** (never 401/403), so an
attacker can't probe which ids exist. `POST /shares` is open by default; set
`createToken` to gate who may create.

## 4. Library surface

App code drives the `ShareManager`; it never touches the store directly.

```ts
class ShareManager {
  constructor(cfg: {
    store: ObjectStore;
    baseUrl: string;            // public base for the service endpoints
    prefix?: string;            // bucket key namespace, default "shl/"
    maxRecipientsLogged?: number;
    casMaxRetries?: number;
    maxEmbeddedBytes?: number;
    ticketSecret?: string;
  });

  // control plane
  create(input: { ciphertext: Uint8Array | string; policy? }): Promise<CreateResult>;
  get(id, token): Promise<ShareView>;
  revoke(id, token): Promise<ShareView>;
  pause(id, token): Promise<ShareView>;
  resume(id, token): Promise<ShareView>;
  extend(id, token, exp?): Promise<ShareView>;
  setLimits(id, token, maxUses?): Promise<ShareView>;
  accessLog(id, token): Promise<RecipientEntry[]>;
  delete(id, token): Promise<void>;
  list(): Promise<ShareView[]>;          // ops only; gate behind adminToken

  // data plane
  resolveDirect(id, opts): Promise<ResolveResult>;
  resolveManifest(id, opts): Promise<Manifest>;
  resolveFileTicket(id, fileId, ticket): Promise<ResolveResult>;
}
```

The **client** side (never imported by the service) is in `client.ts`:
`encryptBundle()`, `composeShlink()`, `composeViewerLink()`, `openSealed()`.

### The `ObjectStore` port

Six verbs. Adapters wrap a proven blob library; the service stays storage-agnostic.

```ts
interface ObjectStore {
  readonly capabilities: { conditionalWrite; presign; lifecycle };
  put(key, bytes, opts?): Promise<{etag}>;
  get(key): Promise<{bytes, etag} | null>;
  head(key): Promise<{etag, size} | null>;
  delete(key): Promise<void>;
  list(prefix): Promise<string[]>;
  conditionalPut(key, bytes, expectedEtag: string|null, opts?): Promise<{etag} | null>; // CAS
  presignGet?(key, ttl): Promise<string>; // optional, generic; unused by default flows
}
```

`conditionalPut` is the compare-and-swap primitive: `expectedEtag===null` means
create-if-absent (`If-None-Match: *`); a string means replace-if-unchanged
(`If-Match`); `null` return = precondition failed (caller retries). Shipped
adapters: `MemoryObjectStore` (dev/tests) and `S3ObjectStore` (any S3-compatible).

## 5. Lifecycle & state machine

Persisted `status ∈ {active, paused, revoked}`; **effective** status adds derived
terminals `expired` (now ≥ exp) and `exhausted` (useCount ≥ maxUses), computed at
read time — never written, so a clock change or limit edit can't strand state.

| from | event | to |
|---|---|---|
| active | `pause` | paused |
| paused | `resume` | active |
| active/paused | `revoke` | revoked (terminal) |
| active | now ≥ exp | *expired* (derived) |
| active | useCount ≥ maxUses | *exhausted* (derived) |
| any | `delete` | gone (both objects removed) |

Only `active` + not-expired + not-exhausted + passcode-OK is servable; everything
else is a data-plane 404.

### Durability invariants (two-object ordering)

- **create** **reserves the id by writing the sidecar create-if-absent first,**
  then writes the ciphertext. Reserving first makes id allocation atomic: the id
  is 128-bit random and **server-minted** (clients never choose it), and a
  collision — cosmically unlikely — is **retried with a fresh id**, never
  surfaced, and can never clobber an existing share's ciphertext (whose key is
  derived from the id; a "ciphertext-first" write *would* clobber it). A crash
  after the reservation but before the cipher write leaves an orphan sidecar
  (unreferenced; resolves to 404 because the cipher is missing) — sweepable,
  never corrupting. On non-CAS backends, the reservation falls back to head+put.
- **revoke** flips the sidecar to `revoked` **first**, then deletes the
  ciphertext. Enforcement reads the sidecar, so even if the delete lags, nothing
  is servable.

### Resolve: read always, write only when needed

`resolve*` first reads the sidecar and enforces servability (revoke/expiry/
passcode). If the share has **neither `maxUses` nor `audit`**, it returns there —
a pure read, no write. If it has either, it does read → check →
`conditionalPut(useCount+1, +recipient if audit)` in a bounded CAS retry loop; a
lost CAS reloads and retries; exhausting retries → 409. This keeps counting exact
under concurrent opens **on a plain bucket**, with no DB. On backends without
conditional writes the manager refuses use-limited shares at create (honesty rule)
rather than miscounting. For very hot counted links, swap a KV counter behind the
same `conditionalPut` seam (noted, not required).

## 6. Backend capability matrix

| Backend | CORS config | Conditional write (CAS) | Notes |
|---|---|---|---|
| AWS S3 | bucket CORS | ✓ (`If-None-Match` Aug 2024, `If-Match` Nov 2024) | reference target |
| Cloudflare R2 | bucket CORS | ✓ (`If-Match`/`If-None-Match`) | S3 API |
| MinIO | bucket CORS | ✓ | S3 API, `forcePathStyle` |
| Backblaze B2 | bucket CORS | ✗ | set `conditionalWrite:false` → no use-limits |
| Wasabi / OVH | bucket CORS | ✗ / unverified | treat as false until verified |
| GCS | CORS | ✓ native (`ifGenerationMatch`) — **not** via S3/XML | add a native adapter for CAS |
| Azure Blob | account CORS | ✓ native (ETag `If-Match`) | not S3; add a native adapter |

The CAS column is what gates **use-limits**: AWS S3, R2, and MinIO get it through
the shipped `S3ObjectStore`; GCS and Azure have strong native CAS but need a native
adapter (their S3/XML ETag preconditions are read-only). The honesty rule binds UI
to capability: `create` throws `unsupported_control` for `maxUses` on a non-CAS
backend rather than miscounting.

## 7. Security & privacy

- **Blind host:** ciphertext + hashed token + opaque metadata only; the key and
  plaintext never arrive. The optional `label` is the one metadata leak — omit it
  (it rides in the link) for blind-strict deployments.
- **Unguessable ids:** 128-bit random, base64url (keeps the shlink `url` short).
- **Enumeration resistance:** uniform 404 for non-servable links and for wrong
  capability tokens.
- **Capability tokens:** stored only as `sha256`, compared in constant time; sent
  as a bearer, never in a URL path.
- **Location tickets:** stateless HMAC over `id.fileId.exp`, 5-minute TTL. The
  `exp` is signed, so a client can't extend it; the bucket stays private (the
  service streams bytes; no presigned object URL in the link, avoiding the
  >128-char `url` problem). The ticket fetch re-checks the live record, so revoke
  still wins inside the 5 minutes. `ticketSecret` must be shared across nodes.
- **Recipient:** consumed at the service; never forwarded to storage. Recorded in
  the access log only when the share set `audit`. Treat decrypted content as
  untrusted on the receiver.

## 8. The `recipient` parameter (explicit)

The SHL viewer **always** appends `?recipient=<name>` to the GET, so the service
always accepts it. The service reads it, and:

- **serves the JWE** (it is never passed to the object store), and
- **records it in the access log only if the share set `audit`** — otherwise an
  unlimited, unaudited resolve is read-only and nothing about the recipient is
  persisted (less metadata on the host, better for blind-strict deployments).

Clients may always send it; it never affects storage and never errors.

## 9. Closed decisions

The PRD left these open; here is the resolution implemented in `../src`:

1. **`?recipient=` handling** — always accepted (the viewer appends it), consumed
   by the service, and never forwarded to storage. Recorded in the access log only
   when the share set `audit`.
2. **Control-plane auth** — per-share capability token (bearer), `sha256` at rest,
   404 on mismatch. No accounts/tenants required; optional `createToken` gates
   creation, optional `adminToken` gates the ops list.
3. **Create/revoke atomicity & id conflicts** — clients never pick the id (128-bit
   server-minted). Create **reserves the id via sidecar create-if-absent first**,
   retrying a fresh id on the ~impossible collision (never surfaced, never
   clobbers); then writes ciphertext (§5). Revoke: sidecar(revoked)→delete cipher.
4. **CAS as a counter substrate** — default; bounded-retry loop; refused on non-CAS
   backends; KV seam noted for hot links. **The CAS write happens only when the
   share opted into `maxUses` or `audit`** — otherwise a resolve is read-only.
5. **Mediated private-bucket file delivery** — `embedded` for small payloads;
   `location` via a stateless HMAC ticket served by the service for large ones
   (bucket stays private; no presigned URL in the link).
6. **`resolve` vs `resolveManifest`** — three explicit methods, one per rail
   (`resolveDirect` / `resolveManifest` / `resolveFileTicket`); no overloaded shape.
7. **`ShareManager` type** — a single `class`, not also an interface.
8. **`exp` ordering / byte-compat** — we make **no** byte-equality claim with the
   demo minter (which never emits `exp`); round-trip is order-independent.
9. **`embeddedLengthMax`** — honored from the POST body, clamped by a server cap
   (`maxEmbeddedBytes`).
10. **deflate default** — `false` everywhere (safer for unknown viewers), a
    deliberate divergence from `jwe.mjs`'s `true`, documented at the call site.
11. **Server-encrypt "convenience" path** — removed. Blind is the only path.

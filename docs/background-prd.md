# PRD — Object-Store-Backed SMART Health Link Adapter

> **Superseded.** This is the exploratory design that seeded the project. The
> authoritative spec is [`api-design.md`](./api-design.md), implemented in
> `../src`. Where they differ, the api-design doc and the code win — in
> particular the convenience/server-encrypt path described below was **removed**
> (blind is the only path), and tenant-API-key auth was replaced by a per-share
> capability token. Kept for the research and rationale it captured.

> Status: draft for review. Generated design proposal; not yet implemented.

## Executive summary

This PRD specifies a multi-language (TS/Python/Go) adapter that lets developers mint, host, resolve, and revoke SMART Health Links over commodity object stores without hand-writing bucket/key/presign/CORS code. It is built on a minimal seven-verb `ObjectStore` port (put/get/head/delete/list/presignGet/conditionalPut) and a high-level `ShareManager` exposing a single control- and data-plane surface across two hosting profiles: STATIC (a blind public object serving the direct-file `U` rail) and MANAGED (a shipped, framework-agnostic request handler that owns the manifest POST and enforces expiry, use-limits, passcode, pause, and audit via a CAS-protected JSON sidecar). Its central design discipline is the HONESTY RULE — surface a control only where the chosen backend and profile can actually enforce it — backed by well-researched, accurate findings that "S3-compatible" does not imply conditional-write support (B2 lacks it, Wasabi is unverified, GCS supports it only via its native JSON API, Azure via ETag If-Match). The wire-format sections are largely faithful to the existing pipeline (`gen-shl.ts`, `jwe.mjs`, `shl.mjs`): payload field order, the `U`-flag direct rail, `application/jose` body, `DEFAULT_RECIPIENT = "Example User"`, and the compact JWE dir/A256GCM envelope all match the source. The security section is strong (blind-host invariant, ≥256-bit ids, uniform 404s, SSRF-safety, versioning/WORM revocation caveats). The main weaknesses are an over-claimed byte-compatibility story around `exp` ordering and the manifest `embedded` newline contract, an under-specified type model (the doc declares `ShareManager` as both a `class` and an `interface`, and uses both `resolve`/`resolve_manifest` inconsistently across language examples), and several genuinely unresolved decisions (how STATIC `?recipient=` reaches a blind object, control-plane authentication, atomic two-object create/revoke ordering) that should be closed before implementation.

---

## Problem & motivation

App developers who want to share encrypted health data via SMART Health Links (SHLs) keep colliding with the same wall: **the link's `url` must be fetchable by a browser, cross-origin**. The SHL viewer runs in the recipient's browser and `fetch`es the ciphertext from wherever `url` points; if that host doesn't return permissive CORS, the share simply fails. This is the **Drive/CORS gap** — consumer Google Drive "share" links, Dropbox links, and most ad-hoc file hosts do not send the CORS headers a browser viewer needs, so they look like they should work and silently don't. The real options are object stores (AWS S3, GCS, Azure Blob, Cloudflare R2, B2, Wasabi, MinIO) with a CORS rule, or a mediated endpoint that owns CORS.

But "just use an object store" pushes a second problem onto every developer: **nobody should be writing raw bucket/key/presign/CORS-XML code to ship a share feature.** The operations are fiddly and cloud-specific — presigned-URL construction, per-bucket vs. account-level CORS, conditional-write headers that exist on some "S3-compatible" stores and not others. Worse, the SHL data model has sharp, non-obvious constraints (a ≤128-char `url` budget that presigned URLs blow; an AES-256 key that must stay in the fragment and never reach the host; a `U`-flag direct-file rail vs. a manifest rail) that a developer hand-rolling storage code will get wrong.

This adapter closes both gaps. It gives developers **high-level, SHL-aware abstractions** over any cloud object store — `create`, `host`, `present`, `manage`, `revoke` — so they create revocable, browser-fetchable, spec-correct SHLinks **without ever touching a raw bucket, key, presign call, or CORS document.** It wraps a proven multi-cloud blob library per language behind a minimal `ObjectStore` port, and ships an optional framework-agnostic request handler for the controls a blind object can't enforce.

## Goals

- **One SHL-correct API over any object store.** Mint, host, resolve, and revoke SHLinks that round-trip byte-for-byte with the existing pipeline (`gen-shl.ts`, `jwe.mjs`, `shl.mjs`) and conform to the SMART Health Links retrieval spec on both the direct-file (`U`) and manifest rails.
- **Never make the developer write raw storage ops.** The public surface is `ObjectStore` port verbs and SHL lifecycle helpers; per-cloud detail (CORS, presign, conditional-put) lives in thin adapters over a vendored blob library.
- **Every share is revocable and the app retains a handle.** `create` always returns an owner handle (object URL/key for STATIC; control token for MANAGED) sufficient to take the share down later.
- **Honest controls only.** Surface a control only where the chosen backend + profile can actually enforce it (the HONESTY RULE). Expiry, use-limit, opens-remaining, revoke, audit are exposed exactly when enforceable.
- **Present-helpers for the handoff.** Provide the viewer-prefixed link string and the data a client needs to render a QR plus a copy/share action (QR render stays client-side).
- **Race-safe state where claimed.** When a profile offers use-limits, mutate sidecar state through a `conditionalPut` (compare-and-swap) primitive with a defined retry-on-`412/409` loop, and refuse the control when the backend lacks CAS.
- **Cross-cloud, cross-language.** Ship the same conceptual port for TS/Node, Python, and Go, mapped onto a proven blob library per language.

## Non-goals

- **Not a key-management or identity service.** The AES-256 `key` is generated client-side and lives only in the link fragment; the adapter never escrows, transmits, or logs it.
- **Not a viewer.** QR rendering, link parsing in the recipient browser, and the decrypt/preview UI are the viewer's job (`shl.mjs`); the adapter only produces the strings/bytes those consume.
- **Not a hosted SaaS.** No managed control-plane service, dashboard, or account system; the MANAGED handler is code the developer deploys on their own runtime.
- **Not a general object-store SDK.** The `ObjectStore` port exposes only the seven verbs SHL hosting needs (`put`/`get`/`head`/`delete`/`list`/`presignGet`/`conditionalPut`), not the full surface of any cloud.
- **No new crypto.** We reuse the established compact-JWE `dir`/`A256GCM` format exactly; we do not invent envelopes, ciphers, or compression schemes.
- **Not a database.** Control-plane state defaults to a sidecar object in the same bucket or an optional external KV; we don't require or ship a DBMS.

## Personas

- **Solo app dev with only an S3 bucket.** Has cloud storage and a static frontend, no backend. Wants to ship a "share my data" button this week. Picks the **STATIC profile**: `create` uploads the JWE, configures CORS once via `ensureCors()`, returns a short public-object `url` with `flag:"U"`, and a delete-handle for revoke. Accepts that "expiry" means object-lifecycle and that opens can't be counted.
- **Client-only mobile app.** No server the developer controls; the app holds storage credentials (or a scoped token) and talks to the bucket directly. Needs revocable, CORS-correct shares and an on-screen QR. Uses **STATIC** with the present-helpers; revoke = delete the object via the retained handle.
- **Clinic backend / regulated product.** Runs a serverless function or small server and must honestly offer **use-limits, opens-remaining, passcode, pause/resume, expiry enforcement, and an access log** for audit. Deploys the **MANAGED profile**: the shipped request handler owns the manifest `POST` and direct-file `GET ?recipient=`, keeps CAS-safe sidecar state in a conditional-write-capable backend (S3/R2/MinIO, or GCS/Azure via native SDK), and matches the KTC reference feature set.

## Glossary

- **SHL (SMART Health Link).** A shareable `<viewer>/#shlink:/<base64url(min-JSON)>` string whose payload (`url`, `key`, `flag`, `label`, `exp`, `v`) points a browser viewer at encrypted content. The decryption `key` lives in the `#` fragment and never reaches a server.
- **JWE.** The compact-serialized encrypted file the host stores: `alg:"dir"`, `enc:"A256GCM"`, fresh 12-byte IV, `cty` header (default `application/fhir+json`), optional `zip:"DEF"`. Five dot-separated base64url segments; the host only ever holds this ciphertext.
- **Direct-file rail (`U` flag).** Receiver does `GET <url>?recipient=<org>`; the response body *is* the JWE (`application/jose`). Servable by a raw object — the STATIC-compatible rail.
- **Manifest rail (no `U`).** Receiver `POST`s `{recipient, passcode?, embeddedLengthMax?}` to `url` and gets `{files:[{contentType, embedded|location}]}`. Requires the mediated MANAGED handler.
- **Profile.** The hosting tier chosen per share: **STATIC** (object store only) or **MANAGED** (object store + provided request handler). The choice is driven by which controls the product must honestly offer.
- **Control plane.** The owner-facing operations on a share's state: create, set expiry/maxUses, pause/resume, revoke, re-arm, read status/audit. In MANAGED, authorized by a control token.
- **Data plane.** The receiver-facing retrieval path: the direct-file `GET` or the manifest `POST` that returns the JWE. Where counting, use-limit, and per-recipient audit hooks live.
- **Recipient.** The single per-open input the host receives (`?recipient=` or the POST body `recipient`, default `"Example User"`). The hook for counting, use-limit enforcement, and audit-logging.
- **`ObjectStore` port.** The minimal abstraction the adapter is built on: `put`, `get`, `head`, `delete`, `list`, `presignGet`, and `conditionalPut` (compare-and-swap). Implemented by thin per-cloud adapters over a vendored blob library.
- **`conditionalPut` / CAS.** A race-safe write gated on `If-None-Match:"*"` (create-only) or `If-Match:<etag>` (update), used to mutate sidecar state without overshooting `maxUses`. Unevenly supported across "S3-compatible" stores — the gate for offering use-limits.

## Profiles at a glance

| Dimension | STATIC (object store only) | MANAGED (object store + request handler) |
|---|---|---|
| **Compute needed** | None — raw object served directly | A serverless function / edge worker / small server runs the shipped handler |
| **Retrieval rail** | Direct-file `GET ?recipient=` → `application/jose` (`flag:"U"`) | Manifest `POST {recipient,…}` → `{files:[{embedded\|location}]}` (and may also serve `U`) |
| **CORS** | Required; configured once per bucket via `ensureCors()` (account-level on Azure) | Handler owns CORS on its own endpoint; bucket stays private |
| **Expiry (`exp`)** | Advisory only; degrades to object-lifecycle / presigned-TTL — not enforced per request | Enforced server-side on every open; `404`/stale on expiry; extendable |
| **Use-limit / opens-remaining** | Not available — a blind object cannot count opens (do not surface) | Enforced; atomic increment via `conditionalPut` CAS, retry on `412/409`; `opensRemaining` exposed |
| **Passcode (`P`)** | Not available (needs mediated POST) | Enforced with lifetime wrong-attempt budget; `401 {remainingAttempts}` |
| **Pause / resume** | Not available | Supported (temporary disable without losing state) |
| **Revoke** | Yes — delete/overwrite the object via the retained handle (the only take-down a blind host supports) | Yes — terminal deactivation + ciphertext purge |
| **Re-arm** | No (revoke is one-way: re-create instead) | Yes — extend expiry / reset limit / clear failure |
| **Audit (access log)** | Not available — `recipient` is ignored, opens are invisible (do not surface) | Per-recipient, timestamped access log |
| **`url` length** | Short **public-object** URL (within ≤128 budget); **never** a presigned URL | Short **mediated** URL `https://host/m/<id>`; long presigned/SAS strings only ever inside the manifest `location`, never in `url` |
| **Backend constraint** | Any CORS-capable store (incl. B2, Wasabi) | Use-limits need CAS: S3/R2/MinIO via one S3 path; GCS/Azure via native SDK; backends without CAS fall back to KV counters or drop the control |
| **When to choose** | You have only a bucket and a static/client-only app, and revoke-by-delete + lifecycle expiry are honestly enough | You must offer any of: open-counting, use-limits, passcode, pause, server-enforced expiry, or an audit log |

Files referenced for wire-contract alignment: `/home/jmandel/periodicity/scripts/gen-shl.ts`, `/home/jmandel/periodicity/viewer-src/jwe.mjs`, `/home/jmandel/periodicity/viewer-src/shl.mjs`, `/home/jmandel/periodicity/skill/references/smart-health-links.md`.

---

## Architecture

## Research: object stores
Key capability findings (verified during research):

- **B2: does NOT support `If-None-Match` conditional writes** (rclone has a "Skip If-None-Match" quirk for it) — kills the assumption that "S3-compatible" implies conditional-write support.
- **Wasabi: inconclusive/likely unsupported** — no documentation confirms it; must be treated as unverified.
- **MinIO: supports both `If-None-Match` and `If-Match`** (full RFC 7232) since the 2024/2025 conditional-write feature.
- **R2: supports `If-Match`/`If-None-Match` on PutObject** (confirmed in compat docs).
- **GCS S3/XML path: ETag preconditions only work for reads; the native generation-precondition CAS is JSON-API only** — so atomic counters via the S3 path are NOT reliable; use native SDK with `if_generation_match`. Also boto3 needs checksum env-var workarounds against GCS.
- **Azure: not S3-compatible; CORS + lifecycle are account/service-level (not per-bucket), conditional via ETag `If-Match`.**
- **Presigned URLs far exceed 128 chars** (hundreds to ~1500+ with session tokens) — confirms they blow the shlink `url` budget.

## Object-store landscape

### What the SHL adapter actually needs from a store

The adapter's `ObjectStore` port must express six verbs — `put`, `get`, `head`, `delete`, `list`, `presignGet` — plus one race-safe primitive, `conditionalPut` (compare-and-swap), used only by the MANAGED profile to mutate the sidecar state object (`useCount`, `status`, `exp`). Three properties decide whether a given backend can host SHLinks at all:

1. **Cross-origin GET** (browser fetch of ciphertext) → backend must serve configurable **CORS**.
2. **Short stable URL** (`url` field SHOULD be ≤128 chars) → favors **public-object** or **path-style virtual-host** URLs; **disfavors presigned URLs**, which are far too long.
3. **Atomic CAS** (use-limit counting) → backend must support a **conditional write** (`If-None-Match`/`If-Match`, generation precondition, or ETag `If-Match`). This is the feature most unevenly implemented across "S3-compatible" stores.

A store that only satisfies (1) and (2) can host the **STATIC** profile. Only a store that also satisfies (3) — or is fronted by the MANAGED handler keeping state in a CAS-capable backend — can honestly offer use-limits.

### Recommended abstraction per language

Do not hand-roll per-cloud code. Wrap one proven blob library and expose the `ObjectStore` port over it. The port's `conditionalPut` is the part the libraries cover unevenly, so it dictates the choice.

| Language | Primary pick | Why | `conditionalPut` story |
|---|---|---|---|
| **TS/Node** | `@aws-sdk/client-s3` (S3 path) against any S3-compatible endpoint | Native `IfNoneMatch`/`IfMatch` params on `PutObjectCommand`; widest endpoint reach (S3, R2, MinIO, B2, Wasabi, GCS-XML) | First-class. Pass `IfNoneMatch: "*"` / `IfMatch: etag`; catch `412`. |
| TS/Node | `unstorage` S3 driver (built on `aws4fetch`) | Tiny, fetch-based, multi-driver mounting; good for the STATIC profile | **No conditional-write or presign surface** — STATIC only. Drop to raw SDK for MANAGED. |
| TS/Node | `flystorage` (S3/GCS/Azure adapters) | Clean filesystem-style API incl. temporary URLs across S3/GCS/Azure | No portable CAS verb; use for STATIC or where Azure is required. |
| **Python** | `boto3` S3 client against any S3-compatible endpoint | `put_object(IfNoneMatch="*" / IfMatch=etag)`; `generate_presigned_url` | First-class on real S3/R2/MinIO. **GCS needs `AWS_REQUEST_CHECKSUM_CALCULATION=when_required` + `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`.** |
| Python | `fsspec`/`s3fs`, `smart_open` | Streaming/file-like ergonomics; `s3fs` has a `sign()` for presign | Conditional support is thin/awkward; for CAS, reach the underlying `botocore` client. Treat as STATIC-grade. |
| Python | `apache-libcloud` | Broadest provider list incl. native Azure/GCS drivers | No uniform CAS primitive; fallback only. |
| **Go** | `gocloud.dev/blob` (`s3blob`, `gcsblob`, `azureblob`) | Portable `ReadAll`/`WriteAll`/`Delete`/`Exists`/`Attributes`/`List`/`SignedURL`; `WriterOptions.IfNotExist` is portable | `IfNotExist` covers create-if-absent CAS; **but no portable `If-Match`-on-ETag** for read-modify-write counters — drop to the `As()` escape hatch (native S3/GCS handle) for full CAS. |
| **Cross-language** | Apache **OpenDAL** | One core, many services; capability flags (`write_with_if_not_exists`, `write_with_if_match`, `presign`) are introspectable at runtime | Capability-gated CAS — query the `Capability` struct and refuse MANAGED if the flag is false. |

Opinion: for the MANAGED profile, standardize on the **raw S3 SDK per language** (`@aws-sdk/client-s3`, `boto3`, AWS SDK for Go v2) pointed at an S3-compatible endpoint, because conditional `PutObject` is a first-class parameter there and portable across S3/R2/MinIO. Use `gocloud.dev`/`flystorage`/`unstorage`/OpenDAL where you want one API across S3+GCS+Azure and can accept the STATIC profile or the capability-gated CAS path.

### Exact operations exposed

| Port verb | S3 SDK (TS/Py/Go) | `gocloud.dev/blob` | OpenDAL | unstorage | flystorage |
|---|---|---|---|---|---|
| put | `PutObject` | `WriteAll`/`NewWriter` | `write` | `setItemRaw` | `write` |
| get | `GetObject` | `ReadAll`/`NewReader` | `read` | `getItemRaw` | `read` |
| head | `HeadObject` | `Attributes`/`Exists` | `stat` | `getMeta`/`hasItem` | `fileExists`/`stat` |
| delete | `DeleteObject` | `Delete` | `delete` | `removeItem` | `delete` |
| list | `ListObjectsV2` | `List`/`ListPage` | `list` | `getKeys` | `list` |
| presignGet | `getSignedUrl(GetObjectCommand)` / `generate_presigned_url` | `SignedURL{Method:GET}` | `presign_read` | — | temporary URL |
| **conditionalPut** | `PutObject{IfNoneMatch:"*"\|IfMatch:etag}` | `WriterOptions{IfNotExist:true}` (create-only) | `write_with(if_not_exists\|if_match)` | — | — |

Notes: `gocloud.dev` `SignedURL` supports `GET`/`PUT`/`DELETE` with `Expiry` (default 1h). S3 conditional writes evaluate at write time: `200` on success, **`412 Precondition Failed`** on conflict, `409 Conflict`/`404` under concurrent delete — the handler must retry the read-modify-write loop on `412`/`409`.

### S3-API compatibility matrix

| Provider | S3 API native? | CORS config | Conditional write (CAS) | Object-expiry lifecycle | SHL verdict |
|---|---|---|---|---|---|
| **AWS S3** | Yes (reference) | Yes, per-bucket | **Yes** — `If-None-Match:*` + `If-Match:etag` on `PutObject`/`CopyObject`/`CompleteMPU` (GA since Aug/Nov 2024) | Yes, per-bucket prefix rules + `Expiration` | MANAGED ✓ |
| **Cloudflare R2** | Yes (S3-compat endpoint, region `auto`) | Yes (`PutBucketCors`) | **Yes** — `If-Match`/`If-None-Match`/`If-(Un)Modified-Since` on `PutObject` | Yes (`PutBucketLifecycleConfiguration`) | MANAGED ✓ |
| **MinIO** | Yes | Yes | **Yes** — full RFC 7232 (`If-None-Match` *and* `If-Match`) | Yes | MANAGED ✓ (self-host) |
| **Google Cloud Storage** | Partial via **XML/S3 interop** (HMAC keys, `storage.googleapis.com`) | Yes (native + XML) | **Native JSON API only**: `ifGenerationMatch=0` (create) / `=N` (CAS). **The S3/XML path supports ETag preconditions on reads only — not write CAS.** | Yes (Age/expiration, native) | MANAGED via **native SDK**; STATIC via S3 path |
| **Backblaze B2** | Yes (S3-compat API since 2018) | Yes (`PutBucketCors`, also native) | **No** — `If-None-Match` not implemented (rclone ships a "skip If-None-Match" quirk) | Yes (lifecycle rules) | **STATIC only** |
| **Wasabi** | Yes | Yes | **Unverified — assume no** (not documented) | Yes | STATIC only (until proven) |
| **Azure Blob** | **No** (no native S3 API) | Yes, but **service/account-level**, not per-container | ETag **`If-Match`** optimistic concurrency + leases (native REST), not the S3 header model | Yes, but **account-level policy**, day-granularity, not per-object TTL | Needs native SDK adapter; MANAGED ✓ via Azure ETag |

Opinion: pick **AWS S3, R2, or MinIO** when use-limits matter — they give CAS through one S3 code path. **GCS and Azure** require their native SDK for honest CAS. **B2 and Wasabi** are STATIC-grade for counting; you can still host revocable, expiring links there, just don't surface a use-limit control.

### Gotchas the design must encode

#### Presigned URLs blow the `url` budget
A SigV4 presigned GET carries `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature` in the query string — typically **hundreds of characters**, and **~1500+** when a session/security token (`X-Amz-Security-Token`) is present, routinely exceeding the 2048-char URL ceiling and always blowing the SHL ≤128-char guideline. **Never put a presigned URL in the shlink `url` field.** Use a **short public-object URL** for STATIC, or a **short MANAGED endpoint URL** (`https://host/m/<id>`) that returns the JWE or a freshly minted presigned `location` *inside* the manifest response (where length is irrelevant).

#### CORS must be configured, per provider, and it's not uniform
Public/cross-origin GET requires an explicit CORS rule on every provider. **S3, R2, B2, Wasabi, MinIO** take a **per-bucket** CORS config (`PutBucketCors`). **GCS** supports CORS natively and via XML. **Azure is the exception: CORS is set at the storage-account/Blob-service level**, not per container — a different mental model the Azure adapter must own. The adapter should ship a `ensureCors()` helper per backend so devs never touch raw CORS XML/JSON.

#### GCS: XML/S3 path vs JSON API split
GCS speaks S3 only through its **XML API + HMAC keys** (swap endpoint to `storage.googleapis.com`, use HMAC access-id/secret as AWS key/secret). That path is fine for `put`/`get`/`list`/`presign`, but **compare-and-swap counters do not work through it** — ETag preconditions apply to reads only, and the generation-based CAS (`ifGenerationMatch`) lives on the **JSON API**. Also, recent AWS SDK default checksums break GCS over the S3 path unless you set `AWS_REQUEST_CHECKSUM_CALCULATION=when_required` and `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`. **Decision: use a native GCS adapter (`gcsblob`/google-cloud-storage) for the MANAGED state object; the S3 path is STATIC-grade on GCS.**

#### Azure is the odd one out
No native S3 API at all — it needs a dedicated adapter (`azureblob`, flystorage Azure, or libcloud). Its concurrency model is **ETag `If-Match`** (optimistic) or **leases** (pessimistic), not S3's `If-None-Match:*`. Time-limited links are **SAS URLs** (also long — same rule: never in the `url` field). Lifecycle is an **account-level policy** in days, so per-object expiry must be emulated by the MANAGED handler (or by prefix-scoped rules), not assumed as native per-object TTL.

#### "S3-compatible" ≠ "conditional-write-compatible"
The sharpest trap: B2 and (almost certainly) Wasabi advertise S3 compatibility yet **omit `If-None-Match`**, so a naive CAS loop silently overwrites — corrupting `useCount`. The `ObjectStore` port must **probe/declare a `supportsConditionalPut` capability** (OpenDAL exposes this directly; for raw SDKs, detect by a one-time canary `PutObject IfNoneMatch:"*"` or maintain a static backend table). When false, the adapter must **refuse to offer use-limits** (HONESTY RULE) and fall back to either an external KV for counters or STATIC-only controls (revoke-by-delete + lifecycle expiry).

### Sources

- [AWS — Conditional writes (`If-None-Match`/`If-Match`, 412/409 behavior)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [AWS — S3 now supports conditional writes (2024 launch)](https://aws.amazon.com/about-aws/whats-new/2024/08/amazon-s3-conditional-writes/)
- [Simon Willison — S3 conditional writes expanded (Nov 2024)](https://simonwillison.net/2024/Nov/26/s3-conditional-writes/)
- [Cloudflare R2 — S3 API compatibility (conditional headers, CORS, lifecycle)](https://developers.cloudflare.com/r2/api/s3/api/)
- [Cloudflare R2 — Presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/)
- [MinIO — Conditional write feature (`If-Match`/`If-None-Match`)](https://blog.min.io/leading-the-way-minios-conditional-write-feature-for-modern-data-workloads/)
- [Backblaze B2 — Enable CORS with the S3-Compatible API](https://www.backblaze.com/docs/cloud-storage-enable-cors-with-the-s3-compatible-api)
- [Wasabi — Compliance with the Wasabi S3 API](https://docs.wasabi.com/docs/compliance-with-the-wasabi-s3-api)
- [GCS — Conditional requests via ETag/generation/metageneration preconditions](https://docs.cloud.google.com/python/docs/reference/storage/latest/generation_metageneration)
- [GCS — Interoperability (XML API, HMAC keys, S3 tools)](https://docs.cloud.google.com/storage/docs/interoperability)
- [beginswithdata — AWS S3 tools with GCS need checksum env-var workarounds](https://www.beginswithdata.com/2025/05/14/aws-s3-tools-with-gcs/)
- [Azure — CORS support for Azure Storage (service-level config)](https://learn.microsoft.com/en-us/rest/api/storageservices/cross-origin-resource-sharing--cors--support-for-the-azure-storage-services)
- [Azure — Configure a lifecycle management policy](https://learn.microsoft.com/en-us/azure/storage/blobs/lifecycle-management-policy-configure)
- [gocloud.dev/blob — package reference (`SignedURL`, `WriterOptions.IfNotExist`)](https://pkg.go.dev/gocloud.dev/blob)
- [Apache OpenDAL Go bindings — capability flags (presign, if-match, if-not-exists)](https://pkg.go.dev/github.com/apache/opendal/bindings/go)
- [unstorage — S3 driver (aws4fetch-based)](https://unstorage.unjs.io/drivers/s3)
- [Flystorage — overview (S3/GCS/Azure adapters, temporary URLs)](https://flystorage.dev/)
- [boto3 — `generate_presigned_url`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/generate_presigned_url.html)
- [s3fs — API (filesystem ops, sign)](https://s3fs.readthedocs.io/en/stable/api.html)
- [AWS SDK Java — presigned URL length with session tokens](https://github.com/aws/aws-sdk-java-v2/discussions/4013)

## Research: our SHL pipeline
## How our SHL pipeline works today

The adapter must be byte-compatible with the implementation in `scripts/gen-shl.ts` (minting), `viewer-src/jwe.mjs` (crypto), and `viewer-src/shl.mjs` (receiver). Everything below is the concrete wire contract those files establish; any "create" / "host" / "resolve" API the adapter ships must round-trip with these exact shapes.

### The shareable link string

The full link is a viewer URL plus a fragment, assembled in `gen-shl.ts` as:

```
<viewer>/#shlink:/<base64url(minified JSON)>
```

Two helpers build it. `shlinkPayload(fileUrl)` produces the bare URI `"shlink:/" + b64uFromBytes(enc.encode(JSON.stringify({ url, key, flag, label, v })))`, and `share(viewer, file)` wraps it as `` `${viewer}#${shlinkPayload(file)}` ``. Note the `#` (not `/#`) in `share`; the trailing slash comes from the caller passing `` `${VIEWER_BASE}/` ``, e.g. `https://periodicity.fhir.me/#shlink:/eyJ…`. The viewer prefix is configurable via `VIEWER_BASE` (default `https://periodicity.fhir.me`), normalized by stripping trailing slashes.

The `#` fragment never reaches a server, so `key` never lands in host logs — the privacy boundary the whole design protects.

### The `shlink:/` payload JSON

Minted object (exact field set used today, in this order):

```json
{ "url": fileUrl, "key": keyB64, "flag": "U", "label": LABEL, "v": 1 }
```

The receiver (`parseShlink` in `shl.mjs`) decodes back to `{ url, key, flag?, label?, exp?, v? }`. Field contract the adapter must honor:

| field | shape | notes from code |
|---|---|---|
| `url` | string ≤128 chars | where the ciphertext lives; may be **relative** — `fetchJwe` resolves it via `new URL(payload.url, baseUrl)`, so one committed link works on `localhost:5525/viewer/` and when published. |
| `key` | base64url, 43 chars (32 bytes) | the AES-256 key; `importKey` hard-fails if `keyBytes.length !== 32`. |
| `flag` | optional string | `"U"` = direct-file. Receiver tests `(payload.flag || "").includes("U")`, so it is a substring check, not equality. |
| `label` | optional string ≤80 | passed through to `resolveShl` result as `payload.label || null`. |
| `exp` | optional epoch seconds | decoded but **not enforced anywhere** in this codebase (advisory only — directly motivates the honesty rule). |
| `v` | optional int | minted as `1`. |

`shlinkFromPayload(payload)` in `shl.mjs` re-serializes any payload object the same way (`"shlink:/" + b64uFromBytes(te.encode(JSON.stringify(payload)))`), so the adapter's "mint" and "re-mint after edit" paths both reduce to JSON-stringify → b64url with no canonicalization beyond `JSON.stringify`'s own key order.

### The JWE wire format (`jwe.mjs`)

Compact JWE, five dot-separated base64url segments, second segment always empty (`alg:"dir"` has no encrypted key):

```
protectedHeaderB64 . "" . ivB64 . ciphertextB64 . tagB64
```

- **Header**: `{ alg: "dir", enc: "A256GCM", ...(deflate ? { zip: "DEF" } : {}), cty: contentType }` where `contentType` defaults to `application/fhir+json`.
- **IV**: 12 random bytes (`getRandomValues(new Uint8Array(12))`); a caller MAY pin it via `opts.iv` for byte-reproducible demo builds (gen-shl pins `ivB64 = "wrcwWOZXCZuO6fMQ"`).
- **AAD**: the protected-header base64url string is fed as `additionalData` to AES-GCM on both encrypt and decrypt — the adapter must not alter header bytes after computing them.
- **Tag**: 128-bit, split off the last 16 bytes of the WebCrypto `encrypt` output (`ct = ctAndTag.slice(0, -16)`, `tag = last 16`).
- **Compression**: `opts.deflate` **defaults to `true`** here (`opts.deflate !== false`) using `CompressionStream("deflate-raw")`, setting `zip:"DEF"`. This conflicts with the project's stated "default uncompressed for unknown viewers" guidance and the `jose`-dropped-`zip` caveat — so the adapter should expose `deflate` as an explicit per-share option and default it to **false** for unknown viewers, while remaining able to read `zip:"DEF"` (decrypt inflates when `header.zip === "DEF"`).

Signatures the adapter wraps:

```js
encryptCompact(plaintext: string, keyBytes: Uint8Array(32), opts?: { deflate?, contentType?, iv? }) → Promise<string>  // compact JWE
decryptCompact(jwe: string, keyBytes: Uint8Array(32)) → Promise<string>  // UTF-8 plaintext
b64uFromBytes(Uint8Array) → string ; bytesFromB64u(string) → Uint8Array   // padding stripped, URL-safe
```

These run unchanged in browser and Bun (WebCrypto + `CompressionStream` only) — the adapter's core crypto port must stay equally runtime-agnostic.

### Retrieval — the contract a managed host must satisfy

`fetchJwe(payload, baseUrl, recipient = "Example User")` in `shl.mjs` defines exactly what the data-plane endpoint receives and must return:

- **Direct-file** (`flag` includes `"U"`): `GET <url>?recipient=<name>`; body is the JWE as text (`.trim()`ed). `recipient` is always set, defaulting to `DEFAULT_RECIPIENT = "Example User"` via `normalizedRecipient` (trim, fall back to default). Spec content type is `application/jose`, but the receiver reads the body as text and does not check it.
- **Manifest** (no `"U"`): `POST <url>` with `content-type: application/json` and body `{ recipient }`. Response is `{ files: [...] }`; the receiver uses `files[0]` only. Each file is either `{ embedded: <jwe string> }` or `{ location: <url> }` (resolved against `baseUrl`, then GET). It throws on `manifest.files` empty.

So a MANAGED-profile handler the adapter ships must implement, per share id: `GET ?recipient=…` → `application/jose` body for direct-file, or `POST {recipient}` → `{files:[{contentType, embedded|location}]}` for manifest. `recipient` is the only per-open input it gets, and it is exactly the hook for counting, use-limit, and per-recipient audit.

`resolveShl(payload, baseUrl, recipient)` ties it together: `fetchJwe` → `bytesFromB64u(payload.key)` → `decryptCompact` → `JSON.parse`, returning `{ bundle, label }`. The adapter's "resolve/preview" helper must produce this same shape.

### Static-profile facts the adapter inherits

The shipped demo is the STATIC profile: `example.jwe` is a plain file on GitHub Pages with `flag:"U"`, fetched cross-origin by the browser viewer. Two consequences baked into `gen-shl.ts` comments that the adapter must respect:

- **CORS is mandatory.** The `.url` host must send permissive CORS or the browser viewer's cross-origin `fetch` fails. This is why the demo's `url` points at the CORS-durable `periodicity.fhir.me` even though the link is published in the spec on `hl7.org` (which does not send CORS).
- **The fixed demo key/IV is a STATIC-only affordance.** `keyB64 = "-iXXJ2n57QEfYcKZPqjzvde4Y_XaBdqjzmRUvRhwVcI"` and the pinned IV make `example.jwe` byte-stable across builds. The code comment is explicit: "NEVER reuse a fixed key/IV for real patient data — gen a fresh random key+IV." The adapter's create path must generate 32 fresh random bytes per share by default and only allow pinning for reproducible fixtures.
- A static object cannot read `recipient`, count opens, or enforce `exp`/use-limits — exactly the honesty-rule boundary in `smart-health-links.md`. Revoke for this tier = delete/overwrite the object (the only real take-down a blind host supports), which is why the adapter MUST retain the object handle/URL per share.

### Relevant files

- `/home/jmandel/periodicity/scripts/gen-shl.ts` — minting: payload shape, `flag:"U"`, fixed demo key/IV, `share()`/`shlinkPayload()`, CORS rationale.
- `/home/jmandel/periodicity/viewer-src/jwe.mjs` — compact JWE `dir`/A256GCM, IV, `zip:"DEF"`, `encryptCompact`/`decryptCompact`/b64url helpers.
- `/home/jmandel/periodicity/viewer-src/shl.mjs` — receiver: `parseShlink`/`shlinkFromPayload`/`fetchJwe`/`resolveShl`, direct-file vs manifest, `recipient` handling (`DEFAULT_RECIPIENT = "Example User"`).
- `/home/jmandel/periodicity/skill/references/smart-health-links.md` — present/manage UX checklist, honesty rule, host-decision table, DEFLATE caveat.

## Research: prior art

## Spec & prior-art alignment

### SHL retrieval protocol (what the adapter MUST conform to)

The adapter's hosted artifacts and request handler must satisfy the SMART Health Links retrieval contract on both rails. A receiver decodes `<viewer>/#shlink:/<base64url(min-JSON)>` into the payload below and dispatches on `flag`.

| Payload field | Constraint the adapter enforces | Notes |
|---|---|---|
| `url` | manifest/file endpoint, ≤128 chars, ≥256 bits entropy in the path | our short-URL budget; presigned URLs typically violate this, public-object/mediated URLs satisfy it |
| `key` | 43-char base64url of 32 random bytes | the AES-256 key; lives only in the fragment, never sent to host |
| `flag` | subset of `L`,`P`,`U`, alphabetical, `U`+`P` mutually exclusive | drives retrieval mode + control surface |
| `label` | ≤80 chars | client-side; in KTC it is client-*encrypted* so the host can't read it |
| `exp` | epoch seconds, advisory | host SHOULD also enforce server-side (see honesty rule) |
| `v` | int, default 1 | |

Flag semantics the adapter must honor:
- `U` — direct-file. Receiver issues `GET <url>?recipient=<org>`; response is `content-type: application/jose`, body IS the JWE compact serialization. No POST, no manifest. This is the STATIC-profile-compatible rail and what KTC's `GET /shl/{id}?recipient=` serves.
- `P` — passcode required. Receiver includes `passcode` in the manifest POST body. Host MUST enforce a *lifetime* count of incorrect passcodes (not per-request), processing competing attempts serially to block brute force; a wrong passcode returns `401` with `{remainingAttempts}`. `P` cannot combine with `U` (passcode enforcement needs the mediated POST). This is MANAGED-only.
- `L` — long-term / evolving content. Receiver may re-poll the manifest; host returns `Retry-After` and `429` when polled too fast. Implies the share is not single-use.

Manifest rail (no `U` flag): receiver POSTs `application/json` to `url` with body:
- `recipient` (required string), `passcode` (conditional on `P`), `embeddedLengthMax` (optional int cap on inline payload size).

Host responds `application/json` `{ files: [ ... ] }`, each entry having `contentType` (one of `application/smart-health-card`, `application/smart-api-access`, `application/fhir+json`) plus exactly one of:
- `embedded` — the JWE compact string inline (honoring `embeddedLengthMax`), or
- `location` — a short-lived URL (spec: ≤1 hour, may be single-use) the receiver then GETs for the JWE.

Stale/expired SHL on the manifest POST returns `404`.

JWE requirements for every stored ciphertext (both rails identical): compact serialization, `alg:"dir"`, `enc:"A256GCM"`, fresh 12-byte IV per encryption, protected-header `cty` set to the file's content type (`application/fhir+json` by default), optional `zip:"DEF"`. The host only ever stores this ciphertext; it never holds `key`.

Mapping to our two profiles:

| Rail | Flags | Profile | Why |
|---|---|---|---|
| Direct-file GET → `application/jose` | `U` (`L` ok) | STATIC or MANAGED | servable by a raw public object; counting/passcode impossible without mediation |
| Manifest POST → `files[].embedded` | none/`L`/`P` | MANAGED | POST + state needed; `embedded` avoids a second hop and any second-URL CORS |
| Manifest POST → `files[].location` | none/`L`/`P` | MANAGED | host mints a short-lived presigned/ticketed GET; enables counting at the POST and keeps the object private |

Design consequence: STATIC can only honestly offer the `U` rail (or a `location` that is just a public/presigned object) — it cannot do `P`, cannot count, and `exp` degrades to object-lifecycle/presigned-TTL. Anything richer requires the MANAGED handler to own the manifest POST.

### KTC companion-server (`jmandel/kill-the-clipboard-skill`) — reference feature set

KTC is the concrete prior art our MANAGED profile should match or exceed. Its privacy model: the server stores **only** ciphertext, a `sha256(auth)` hashed control token (sent in the `Authorization` header, never in a URL path), client-*encrypted* labels (opaque to server), link settings (expiry, max-use, pause/active, passcode), and an access log. All crypto keys derive client-side from an owner secret `M`; the management page is a capability URL `/m#M` where `M` stays in the fragment. The server can never read the records it hosts.

Endpoints observed in the repo:

Data plane (receiver-facing):
- `GET /shl/{id}?recipient=` → JWE (the `U`-flag direct rail).
- `POST /shl/{id}` → manifest; handles `recipient`, `passcode`, `embeddedLengthMax`; enforces lifetime passcode budget.
- `GET /shl/{id}/f/{fileId}?t=` → ticketed file fetch; `t` is a short-lived HMAC ticket — this is how `location` URLs are minted without a long presigned URL or a DB lookup of secrets.

Control plane (bearer token = the hashed control token):
- `POST /api/links` — create SHL (auth, flags, expiry).
- `GET /api/manage` — full ManageState: live status derived server-side, file metadata, complete access log.
- `PATCH /api/manage` — update settings: expiry, max-uses, active/paused, passcode, label. Re-arm is expressed here (extend expiry / reset the failed condition).
- `GET /api/manage/events` — SSE stream of mutations so an open management UI re-fetches state.
- `POST /api/manage/files` — upload JWE ciphertext (≤25 MB).
- `PUT /api/manage/files/{fileId}` — replace ciphertext (new IV).
- `DELETE /api/manage/files/{fileId}` — delete a file (blocked if it's the last file of an active `U` link).
- `DELETE /api/manage` — revoke: immediate ciphertext purge + terminal deactivation.

Two notable correctness mechanisms our adapter must replicate: **transaction-safe use-count decrement** (serialized so concurrent manifest POSTs can't overshoot `maxUses` — exactly the compare-and-swap / conditional-put problem in our ObjectStore port), and **short-lived HMAC-ticketed `location` URLs** (sign `{id,fileId,exp}` with a server secret instead of presigning, keeping URLs short and stateless).

### Control-plane operation checklist (a complete SHL manager)

The adapter's MANAGED API should cover all of these; STATIC honestly supports only the starred-as-degraded subset.

- [ ] Create link → returns shareable URL (`<viewer>/#shlink:/…`) + a retained owner handle/control token.
- [ ] Upload ciphertext (first file) — host stores JWE only.
- [ ] Replace ciphertext (re-encrypt with fresh IV) — supports `L` evolving content.
- [ ] Delete an individual file (guard last-file-of-active-`U`).
- [ ] Set/extend `exp` — server-side enforced, not just the advisory payload field.
- [ ] Set `maxUses` (use-limit) and expose `opensRemaining`.
- [ ] Atomic open-count increment with use-limit enforcement (race-safe via conditional-put / CAS; documented fallback when backend lacks it).
- [ ] Pause / resume (temporary disable without losing state).
- [ ] Revoke (terminal deactivation + ciphertext purge) — the MUST-be-revocable requirement.
- [ ] Re-arm (reset expiry / clear failure / restore after limit hit).
- [ ] Set/rotate/clear passcode (`P`) with lifetime wrong-attempt budget + `401 {remainingAttempts}` lockout.
- [ ] Rename / update (client-encrypted) label.
- [ ] Read status / ManageState (live status, file metadata, settings).
- [ ] Read access log (per-recipient, timestamped) — the audit requirement.
- [ ] Mint short-lived `location` (HMAC ticket or presigned) for the manifest rail.
- [ ] Serve direct-file `GET ?recipient=` → `application/jose` (the `U` rail).
- [ ] Serve manifest `POST {recipient, passcode?, embeddedLengthMax?}` → `files[].embedded|location` with `404` on stale.
- [ ] Honor `L`: `Retry-After` / `429` on over-polling.
- [ ] (Optional, matches KTC) change-notification stream (SSE) for live management UIs.

Honesty mapping: STATIC may surface only revoke-by-delete and lifecycle/presigned-TTL `exp`; it MUST NOT surface use-limit, opens-remaining, passcode, pause, or access log, because a raw object cannot enforce or record them. Every other row above requires the MANAGED handler.

Sources:
- [SMART Health Links spec — docs.smarthealthit.org](https://docs.smarthealthit.org/smart-health-links/spec)
- [jmandel/kill-the-clipboard-skill](https://github.com/jmandel/kill-the-clipboard-skill)

---

I have the exact wire contract. Note the actual minting order is `{ url, key, flag, label, v }` (no `exp` in the demo, but the receiver accepts `exp`). Now writing the design section.

## The abstraction

This section defines the canonical types every other section and example references. The shapes are language-neutral but expressed as copy-pasteable TypeScript. Two layers: the low-level `ObjectStore` **port** (what backend adapters implement) and the high-level `ShareManager` (what app developers call). The `ShareManager` never exposes buckets, keys, presigns, or CORS to its callers.

### Shared primitives

```ts
/** base64url, no padding — matches viewer-src/jwe.mjs b64uFromBytes/bytesFromB64u. */
export type B64u = string;

/** epoch SECONDS (SHL `exp` semantics), not millis. */
export type EpochSeconds = number;

/** A 32-byte AES-256 key as base64url (43 chars). */
export type KeyB64 = B64u;

export type Profile = "static" | "managed";

/** SHL retrieval flags. "U" = direct-file; "P" = passcode; "L" = long-term. */
export type ShlFlag = string; // substring-tested, e.g. "U", "LU", "LP"
```

### 1. The `ObjectStore` port

The port is the *only* thing a backend adapter must implement. Six data verbs, one CAS primitive, and a static capability descriptor. Bytes in/out are `Uint8Array`; the port never knows what a JWE or a sidecar is.

```ts
export interface PutOptions {
  contentType?: string;       // e.g. "application/jose", "application/json"
  cacheControl?: string;      // adapter may set "no-store" for state objects
  /** lifecycle hint; honored only if capabilities.supportsLifecycle. */
  expiresAt?: EpochSeconds;
}

export interface ObjectInfo {
  key: string;
  size: number;
  etag: string;               // opaque; used as the CAS token for conditionalPut
  contentType?: string;
  lastModified?: Date;
}

export interface GetResult {
  bytes: Uint8Array;
  info: ObjectInfo;
}

/** Outcome of a compare-and-swap put. Never throws on a lost race. */
export type ConditionalPutResult =
  | { ok: true; info: ObjectInfo }      // write applied
  | { ok: false; reason: "precondition-failed" } // 412 — caller retries RMW loop
  | { ok: false; reason: "conflict" };  // 409/404 — concurrent delete, caller retries

/** The precondition for a conditional put. */
export type PutCondition =
  | { kind: "if-absent" }               // create-only: S3 IfNoneMatch:"*", GCS ifGenerationMatch=0, gocloud IfNotExist
  | { kind: "if-match"; etag: string }; // RMW: S3 IfMatch:etag, GCS ifGenerationMatch=N, Azure If-Match

export interface ObjectStoreCapabilities {
  /** if-match RMW CAS works (S3 2024+/R2/MinIO/Azure/GCS-native). False on B2/Wasabi/GCS-via-S3. */
  supportsConditionalWrite: boolean;
  /** if-absent create-only works (often true even where if-match is false). */
  supportsConditionalCreate: boolean;
  /** per-object or prefix lifecycle expiry is configurable. */
  supportsLifecycle: boolean;
  /** programmatic CORS config available (ensureCors will no-op if false). */
  supportsCors: boolean;
  /** presignGet is available and produces a working URL. */
  supportsPresign: boolean;
}

export interface ObjectStore {
  readonly capabilities: ObjectStoreCapabilities;

  put(key: string, bytes: Uint8Array, opts?: PutOptions): Promise<ObjectInfo>;
  get(key: string): Promise<GetResult>;            // throws if absent
  head(key: string): Promise<ObjectInfo | null>;   // null if absent
  delete(key: string): Promise<void>;              // idempotent
  list(prefix: string): Promise<ObjectInfo[]>;

  /** Long, query-signed GET — NEVER placed in a shlink `url`; used only for manifest `location`. */
  presignGet(key: string, ttlSeconds: number): Promise<string>;

  /** Atomic compare-and-swap. The managed profile's only mutation primitive for state. */
  conditionalPut(
    key: string, bytes: Uint8Array, cond: PutCondition, opts?: PutOptions,
  ): Promise<ConditionalPutResult>;

  /** Idempotent CORS install for the bucket/account; no-op when !supportsCors. */
  ensureCors?(allowedOrigins: string[]): Promise<void>;

  /** Public, stable, short URL for a key — used to build STATIC shlink `url`s. */
  publicUrl(key: string): string;
}
```

**Mapping onto the libraries from Research A.** Each backend adapter wraps one proven lib and fills `capabilities` from the static matrix (no runtime probing required; an optional one-time `if-absent` canary may upgrade an `unknown` to `true`).

| Port member | `@aws-sdk/client-s3` (TS) / `boto3` (Py) / AWS SDK Go v2 | `gocloud.dev/blob` | OpenDAL | `unstorage` / `flystorage` |
|---|---|---|---|---|
| `put` | `PutObjectCommand` | `WriteAll` | `write` | `setItemRaw` / `write` |
| `get` | `GetObjectCommand` | `ReadAll` | `read` | `getItemRaw` / `read` |
| `head` | `HeadObjectCommand` | `Attributes` | `stat` | `getMeta` / `stat` |
| `delete` | `DeleteObjectCommand` | `Delete` | `delete` | `removeItem` / `delete` |
| `list` | `ListObjectsV2Command` | `List` | `list` | `getKeys` / `list` |
| `presignGet` | `getSignedUrl` / `generate_presigned_url` | `SignedURL{GET}` | `presign_read` | — / temporary URL |
| `conditionalPut` `if-absent` | `PutObject{IfNoneMatch:"*"}` | `WriterOptions{IfNotExist:true}` | `write_with(if_not_exists)` | — |
| `conditionalPut` `if-match` | `PutObject{IfMatch:etag}` (GCS: native `ifGenerationMatch`) | `As()` escape → native handle | `write_with(if_match)` | — |
| `capabilities` | static table / canary | `As()` + table | `Capability` struct | declared `false` for CAS |

`conditionalPut` returning `{ok:false}` (rather than throwing) is deliberate: the managed handler's read-modify-write loop branches on it. `unstorage`/`flystorage` adapters set `supportsConditionalWrite:false`, forcing those backends to STATIC (or an external-KV counter fallback).

### 2. The `ShareManager`

This is the developer-facing object. One construction, one operation set covering the full control-plane checklist plus the data-plane `resolve`. STATIC and MANAGED share the same surface; calling a control the active profile cannot honestly enforce throws `UnsupportedControlError` rather than silently no-op'ing (the HONESTY RULE, enforced at the type-adjacent runtime layer).

#### Construction

```ts
export interface ShareManagerConfig {
  store: ObjectStore;              // a backend adapter instance
  profile: Profile;               // "static" | "managed"

  /** key prefix inside the bucket, e.g. "shl/". Ciphertext + sidecar live here. */
  prefix?: string;                // default "shl/"

  /** Viewer URL the shareable link is built against, e.g. "https://periodicity.fhir.me". */
  viewerBase: string;             // trailing slashes stripped (matches gen-shl normalizeBase)

  /**
   * MANAGED only: public origin of the request handler, e.g. "https://host".
   * The shlink `url` becomes `${endpointBase}/m/<id>` (≤128 chars).
   */
  endpointBase?: string;

  /**
   * STATIC only: how to form the ciphertext object's public URL.
   * Defaults to store.publicUrl(key). Override for a CDN/custom domain.
   */
  staticUrl?: (objectKey: string) => string;

  /** default for new shares; false for unknown viewers per the DEFLATE caveat. */
  deflateDefault?: boolean;       // default false
}

export class ShareManager {
  constructor(config: ShareManagerConfig);
}
```

#### Create input, policy, and the returned handle

```ts
export interface CreateShareInput {
  /** UTF-8 plaintext to encrypt — typically a FHIR Bundle JSON string. */
  content: string;
  contentType?: string;           // JWE `cty`; default "application/fhir+json"
  label?: string;                 // ≤80 chars; truncated/validated
  deflate?: boolean;              // overrides config.deflateDefault

  /** Control policy. Fields requiring MANAGED throw under STATIC. */
  policy?: SharePolicy;

  /** Test/fixture only: pin key+IV for byte-reproducible artifacts. */
  fixed?: { keyB64: KeyB64; ivB64: B64u };
}

export interface SharePolicy {
  exp?: EpochSeconds;             // STATIC: maps to lifecycle/presign TTL; MANAGED: enforced
  maxUses?: number;               // MANAGED only
  passcode?: string;              // MANAGED only → sets flag "P"
  longTerm?: boolean;             // sets flag "L"
}

export interface ShareHandle {
  id: string;                     // opaque, ≥256-bit entropy in its encoding
  link: string;                   // `${viewerBase}/#shlink:/<b64u(json)>` — the shareable string
  shlinkUri: string;              // `shlink:/<b64u(json)>` (bare)
  payload: ShlinkPayload;         // the decoded object (see §4)
  keyB64: KeyB64;                 // returned ONCE so the caller can re-share; not stored server-readable
  profile: Profile;
  meta: LinkMeta;                 // see §3
}
```

#### Full operation set

```ts
export interface ShareManager {
  // ---- control plane ----
  create(input: CreateShareInput): Promise<ShareHandle>;
  get(id: string): Promise<LinkMeta>;                       // status + settings (no key)
  list(filter?: ListFilter): Promise<LinkMeta[]>;

  revoke(id: string): Promise<void>;        // terminal: purge ciphertext + mark "revoked"
  delete(id: string): Promise<void>;        // hard delete: ciphertext + sidecar gone

  pause(id: string): Promise<LinkMeta>;     // MANAGED — status "paused"
  resume(id: string): Promise<LinkMeta>;    // MANAGED — back to "active"
  extend(id: string, newExp: EpochSeconds): Promise<LinkMeta>;        // re-arm expiry
  setLimits(id: string, limits: { maxUses?: number }): Promise<LinkMeta>; // MANAGED
  setPasscode(id: string, passcode: string | null): Promise<LinkMeta>;    // MANAGED
  setLabel(id: string, label: string): Promise<LinkMeta>;

  accessLog(id: string): Promise<AccessLogEntry[]>;         // MANAGED — audit

  // ---- data plane (what the request handler calls; also directly callable) ----
  resolve(id: string, recipient?: string, opts?: ResolveOptions): Promise<ResolveResult>;

  // ---- presentation helpers (pure, no I/O) ----
  shlink(id_or_payload: string | ShlinkPayload): string;   // → shlink:/… string
  shareLink(id_or_payload: string | ShlinkPayload): string; // → viewer-prefixed link
  qrPayload(id_or_payload: string | ShlinkPayload): string; // → string to feed a QR renderer
}

export interface ListFilter {
  status?: LinkStatus | LinkStatus[];
  before?: EpochSeconds;          // createdAt cutoff
  labelContains?: string;
}

export interface ResolveOptions {
  passcode?: string;
  embeddedLengthMax?: number;     // manifest cap; large payloads return `location` instead
}

export interface ResolveResult {
  /** the parsed decrypted content (FHIR Bundle by default) — matches resolveShl. */
  bundle: unknown;
  label: string | null;
  /** raw JWE if the caller wants to re-emit it (e.g. manifest `embedded`). */
  jwe: string;
}

export interface AccessLogEntry {
  at: EpochSeconds;
  recipient: string;
  outcome: "ok" | "denied-expired" | "denied-limit" | "denied-passcode" | "denied-revoked";
}
```

`resolve` is the canonical name for the data-plane read; `accessLog` and the `*-denied` outcomes only ever populate under MANAGED. Under STATIC, `pause/resume/setLimits/setPasscode/accessLog` throw `UnsupportedControlError`, and `extend` is honored only if `store.capabilities.supportsLifecycle` (else it too throws).

### 3. Persisted `LinkMeta` schema (the sidecar)

One JSON object per share, stored at `<prefix><id>.json` in the *same bucket* as the ciphertext (pure object-store, no DB). MANAGED mutates it via `conditionalPut{if-match:etag}`; STATIC writes it once at create (informational; the only enforcement STATIC has is delete + lifecycle). `key` (the AES key) is **never** stored here — only the caller holds it, in the fragment.

```ts
export type LinkStatus =
  | "active" | "paused" | "expired" | "exhausted" | "revoked";

export interface LinkMeta {
  id: string;
  v: 1;
  profile: Profile;
  status: LinkStatus;             // MANAGED: live, mutated under CAS. STATIC: best-effort.
  createdAt: EpochSeconds;

  flag: ShlFlag;                  // "" | "U" | "L" | "P" combos, alphabetical
  label: string | null;          // ≤80 chars (server-opaque/encrypted if you choose KTC model)

  exp: EpochSeconds | null;       // advisory in payload; MANAGED enforces this value
  maxUses: number | null;         // MANAGED
  useCount: number;               // MANAGED — incremented under CAS on each resolve
  passcodeHash: string | null;    // MANAGED — sha256; never the plaintext
  wrongPasscodeCount: number;     // MANAGED — lifetime budget
  maxWrongPasscode: number | null;

  /** object key of the ciphertext JWE in the same bucket. The retained revoke handle. */
  ciphertextKey: string;

  /** STATIC: the public URL placed in the shlink payload (retained for revoke = delete). */
  staticUrl?: string;

  recipientLog: AccessLogEntry[]; // MANAGED — bounded/rotated; the audit trail

  /** opaque CAS token of THIS sidecar's last write; managers compare against store etag. */
  rev?: string;
}
```

Status is **derived-then-persisted**: a `live(meta, now)` pure function collapses `exp`/`maxUses`/`status` into the effective `LinkStatus` (`expired` when `exp<now`, `exhausted` when `useCount>=maxUses`, else stored `status`). The CAS write persists the transition so `get`/`list` are cheap.

**Race-safe counter (the hard part).** Each MANAGED `resolve` runs a read-modify-write loop:

```ts
for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
  const { bytes, info } = await store.get(metaKey);
  const meta = JSON.parse(text(bytes)) as LinkMeta;
  const eff = live(meta, now());
  if (eff !== "active") return deny(eff);
  if (meta.maxUses != null && meta.useCount >= meta.maxUses) return deny("exhausted");
  meta.useCount += 1;
  meta.recipientLog.push({ at: now(), recipient, outcome: "ok" });
  const r = await store.conditionalPut(metaKey, json(meta),
                                       { kind: "if-match", etag: info.etag },
                                       { cacheControl: "no-store" });
  if (r.ok) break;                 // committed
  // r.reason === "precondition-failed" | "conflict" → retry
}
```

When `store.capabilities.supportsConditionalWrite` is `false` (B2, Wasabi, GCS-via-S3), the manager refuses `maxUses`/`passcode` at `create` time, or routes state to a configured external KV with native CAS — it never runs this loop against a backend that would silently overwrite.

### 4. The `shlink:/` payload — byte-compatible with the pipeline

The payload the manager emits must round-trip through `parseShlink`/`shlinkFromPayload` in `viewer-src/shl.mjs`. The receiver decodes `{ url, key, flag?, label?, exp?, v? }`; the minter in `scripts/gen-shl.ts` emits keys in the order `url, key, flag, label, v`. The manager matches that order exactly (`JSON.stringify` key order is insertion order, and there is no canonicalization beyond it).

```ts
export interface ShlinkPayload {
  url: string;     // ≤128 chars (see below); MAY be relative (resolved via new URL(url, baseUrl))
  key: KeyB64;     // 43-char base64url of 32 fresh random bytes (per share, unless `fixed`)
  flag?: ShlFlag;  // omit when "" ; "U" for direct-file STATIC
  label?: string;  // ≤80
  exp?: EpochSeconds; // advisory; emit only when policy.exp set
  v?: 1;
}

/** Emit identically to gen-shl.ts: insertion order url,key,flag,label,exp?,v. */
function emitPayload(p: ShlinkPayload): string {
  const ordered: ShlinkPayload = { url: p.url, key: p.key };
  if (p.flag) ordered.flag = p.flag;
  if (p.label) ordered.label = p.label;
  if (p.exp != null) ordered.exp = p.exp;
  ordered.v = p.v ?? 1;
  // shlinkFromPayload equivalent: "shlink:/" + b64u(utf8(JSON.stringify(ordered)))
  return "shlink:/" + b64uFromBytes(new TextEncoder().encode(JSON.stringify(ordered)));
}
```

The shareable link is `` `${viewerBase}/#${shlinkUri}` `` — note `viewerBase` carries the trailing slash before `#` (matching `share(\`${VIEWER_BASE}/\`, …)` → `https://periodicity.fhir.me/#shlink:/…`).

**How `url` is formed per profile (the ≤128-char budget):**

| Profile | `url` value | Length | Why it fits |
|---|---|---|---|
| STATIC | `store.publicUrl(ciphertextKey)` (or `config.staticUrl(key)`) — a short public-object URL, e.g. `https://periodicity.fhir.me/example.jwe` | tens of chars | public-object/path-style URLs are short; **never** a presigned URL |
| MANAGED | `${endpointBase}/m/<id>` — a short mediated endpoint, e.g. `https://host/m/3f9c…` | ~30–60 chars | the handler returns the JWE/manifest; any long presigned URL hides inside the manifest `location`, where length is irrelevant |

The manager validates `url.length <= 128` at create and throws `UrlTooLongError` if a misconfigured `staticUrl`/`endpointBase` would overflow — presigned URLs are structurally rejected from this field.

### 5. The two data-plane modes — exactly what `resolve` does

`resolve(id, recipient)` is dispatch-equivalent to `fetchJwe` + `decryptCompact` + `JSON.parse` in `shl.mjs`, but runs server-side inside the manager (the request handler is a thin HTTP shell over it). `recipient` defaults to `"Example User"` (`DEFAULT_RECIPIENT`), normalized by trim-then-fallback.

**Direct-file mode (`flag` includes `"U"` — STATIC, or MANAGED single-file).**
The receiver issues `GET <url>?recipient=<name>` and reads the body as text (`application/jose`, but content-type is not checked). 

- *STATIC:* `url` is the public object; the store serves the JWE directly with no compute. `resolve` is purely client-side here: `store.get(ciphertextKey)` → `decryptCompact(jwe, bytesFromB64u(key))` → `JSON.parse`. No counting, no `recipient` capture, `exp` is only lifecycle.
- *MANAGED:* the handler's `GET /m/<id>?recipient=` runs the CAS counter loop (§3), then returns the JWE body as `application/jose`. If `live(meta) !== "active"`, it returns the SHL error status (stale → `404`).

**Manifest mode (no `"U"` — MANAGED only).**
The receiver POSTs `application/json` `{ recipient, passcode?, embeddedLengthMax? }` to `url`; the handler returns `{ files: [ { contentType, embedded | location } ] }`, and the receiver uses `files[0]` only.

- The handler runs the same CAS counter + passcode-budget check. On wrong passcode → `401 { remainingAttempts }`; on stale → `404`.
- It then chooses **`embedded`** (the JWE compact string inline, when within `embeddedLengthMax`) or **`location`** (a short-lived URL the receiver GETs). `location` is minted as either an HMAC ticket (`${endpointBase}/m/<id>/f/<fileId>?t=<sig>`, KTC-style, short and stateless) or `store.presignGet(ciphertextKey, ttl)` — both legal because URL length inside the manifest body is unconstrained.

In all modes the decrypted result is `{ bundle, label, jwe }` (`ResolveResult`), where `bundle = JSON.parse(decryptCompact(jwe, key))` and `label = payload.label || null` — the exact shape `resolveShl` returns, so the manager's preview path and the browser viewer agree byte-for-byte.

---

## Link lifecycle & policy

A share is a small state machine whose persisted state lives in the `LinkMeta` sidecar (`<prefix><id>.json`) alongside the ciphertext. STATIC shares have a *degenerate* machine — only `active`, `revoked`, and `deleted` are real, because a blind object cannot observe opens or enforce time/limits at read. MANAGED shares run the full machine, with every read-driven transition committed under a conditional write so concurrent opens cannot corrupt the counter. Throughout, the AES `key` never enters this layer — it lives only in the caller's fragment — so no state transition here can leak it.

### States

| State | Meaning | Profile | Ciphertext present? |
|---|---|---|---|
| `active` | Resolvable; counting/passcode/expiry (MANAGED) all pass | both | yes |
| `paused` | Temporarily disabled by owner; state retained, re-armable | MANAGED | yes |
| `expired` | `exp < now`; derived, then persisted on next touch | MANAGED (STATIC: lifecycle-only, see below) | yes (until lifecycle GC) |
| `exhausted` | `useCount >= maxUses`; derived, then persisted | MANAGED | yes |
| `revoked` | Terminal owner take-down: ciphertext purged, sidecar tombstoned | both | no |
| `deleted` | Hard delete: sidecar + ciphertext both gone; no record remains | both | no |

`expired` and `exhausted` are **derived-then-persisted**: a pure `live(meta, now)` collapses `exp`, `maxUses`/`useCount`, and the stored `status` into the *effective* status. `resolve` evaluates `live()` on the freshly-read meta (so a lapsed `exp` denies even if never previously persisted); `get`/`list` return `live()` over the last-persisted snapshot (cheap, may lag until the next `resolve` writes the transition back). `revoked` and `deleted` are terminal and never derived — only an explicit operation reaches them.

STATIC distinction: a STATIC share has no mediated read, so `paused`/`expired`/`exhausted` are *unobservable at resolve time*. Its sidecar is written once at `create` as informational metadata; its only real enforcement is `delete`/`revoke` (object take-down) and, where `store.capabilities.supportsLifecycle`, an object-lifecycle/`expiresAt` hint that eventually GCs the object. So for STATIC, `expired` is an eventual storage-side fact, not a denial the manager can issue.

### State-transition table

| From | To | Trigger / operation | Guard | Notes |
|---|---|---|---|---|
| — | `active` | `create` | profile-legal policy; `url.length<=128` | writes ciphertext then sidecar `if-absent` |
| `active` | `active` | `resolve` (MANAGED) | `live=="active"` and (`maxUses==null` or `useCount<maxUses`) | CAS `useCount+=1`, append `ok` log entry |
| `active` | `exhausted` | `resolve` reaching the last use (MANAGED) | the increment makes `useCount==maxUses` | committed in the *same* CAS as the final allowed open |
| `active` | `expired` | `resolve`/`get` when `exp<now` (MANAGED) | — | derived; persisted on next `resolve` CAS |
| `active` | `paused` | `pause` (MANAGED) | — | reversible; `useCount`/log preserved |
| `paused` | `active` | `resume` (MANAGED) | not terminal | |
| `expired` | `active` | `extend(newExp>now)` (MANAGED) | not terminal | re-arm; clears the `expired` derivation |
| `exhausted` | `active` | `setLimits({maxUses>useCount})` (MANAGED) | not terminal | re-arm; or set `maxUses=null` for unlimited |
| `paused`/`expired`/`exhausted` | same | `resolve` | — | denied with the effective reason; no counter change |
| `active`/`paused`/`expired`/`exhausted` | `revoked` | `revoke` | not already `deleted` | delete ciphertext, set `status="revoked"` (CAS) |
| any non-`deleted` | `deleted` | `delete` | — | delete ciphertext + sidecar; idempotent |
| `revoked` | `revoked` | `resolve`/`extend`/`pause`/… | — | terminal: control ops are no-ops or `409`; `resolve`→`404` |

Automatic transitions (`active→expired`, `active→exhausted`) have no operation of their own: they are realized lazily the next time `live()` is evaluated, and **persisted** by whichever `resolve` first observes them (or left as a pure derivation if no further `resolve` ever occurs — `get`/`list` still report them correctly).

### Policy model

Policy is supplied at `create` (`SharePolicy`) and amended later via `extend`/`setLimits`/`setPasscode`/`setLabel`. Each field maps to a payload flag and/or a sidecar field, and each MANAGED-only field is rejected at `create` under STATIC (HONESTY RULE — never surface a control the host can't enforce):

| Policy field | Flag effect | Sidecar field | STATIC behavior | MANAGED behavior |
|---|---|---|---|---|
| `exp` | emits payload `exp` (advisory) | `exp` | maps to lifecycle/`expiresAt` hint *only if* `supportsLifecycle`, else `UnsupportedControlError` | server-enforced denial at `resolve` |
| `maxUses` | — | `maxUses`, `useCount` | `UnsupportedControlError` | CAS-enforced; exposes `opensRemaining = maxUses-useCount` |
| `passcode` (`P`) | adds `"P"` (mutually exclusive with `"U"`) | `passcodeHash`, `wrongPasscodeCount`, `maxWrongPasscode` | `UnsupportedControlError` | lifetime wrong-attempt budget; `401 {remainingAttempts}` |
| `longTerm` (`L`) | adds `"L"` | (informational) | allowed (advisory); receiver may re-poll | `Retry-After`/`429` on over-poll |
| `label` | emits payload `label` (≤80) | `label` | allowed | allowed (may be client-encrypted per KTC model) |

Flag composition: flags are assembled, deduped, and **sorted alphabetically** (`"LU"`, `"LP"`), and `"U"`+`"P"` is rejected (passcode requires the mediated manifest POST, which the direct-file rail cannot run). STATIC implies the `"U"` rail; choosing `passcode` or `maxUses` therefore can't coexist with STATIC and fails fast at `create`.

Single-use vs long-term: single-use is just `maxUses:1` (MANAGED). `longTerm:true` sets `"L"`, signaling the receiver the content may evolve and is re-pollable; it does **not** by itself bound or unbound `maxUses` — combine `L` with a `maxUses` only if you intend a re-pollable-but-capped share.

### Per-operation semantics

`create(input)` — generates 32 fresh random key bytes and a fresh 12-byte IV (unless `input.fixed` pins them for fixtures), encrypts via `encryptCompact` (`deflate` defaults to `config.deflateDefault`, i.e. `false` for unknown viewers), `put`s the ciphertext at `ciphertextKey`, validates the assembled `url` (`<=128` chars, presigned URLs structurally rejected → `UrlTooLongError`), then writes the sidecar with `conditionalPut{if-absent}`. An `if-absent` conflict means an `id` collision (≥256-bit entropy makes this a hard error, surfaced as `conflict`, never a silent overwrite). Returns the `ShareHandle` including `keyB64` **once**. Idempotency: not idempotent — each call is a new `id`. On any post-ciphertext failure the manager deletes the orphan ciphertext (best-effort) so a failed create leaves no readable object.

`resolve(id, recipient?, opts?)` — the data-plane read; `recipient` normalized by trim-then-`"Example User"` fallback (matching `normalizedRecipient`). STATIC: pure client-side `store.get(ciphertextKey)` → `decryptCompact` → `JSON.parse`; no counter, no log, no denial (the object either exists or 404s). MANAGED: runs the race-safe RMW loop below, then returns the JWE (direct-file `application/jose`) or chooses `embedded`/`location` (manifest). Edge cases:
- *Resolve after expiry:* `live()=="expired"` → deny `denied-expired`; manifest rail returns `404` (SHL stale semantics), log appends a denied entry, no counter change.
- *Resolve when paused:* `live()=="paused"` → deny; `404` on manifest, `404`/`410`-class on direct.
- *Resolve when revoked/deleted:* ciphertext absent → `404`; if sidecar present (`revoked`) the denial is recorded, if absent (`deleted`) nothing is recorded.
- *Wrong passcode (`P`):* increment `wrongPasscodeCount` under CAS; if it reaches `maxWrongPasscode`, lock and return `401 {remainingAttempts:0}`, else `401 {remainingAttempts}`. Attempts are serialized through the same CAS loop so competing wrong guesses can't exceed the lifetime budget.
- *Race on the last allowed use:* see below — exactly one concurrent resolver commits the `useCount==maxUses` transition; the loser retries, re-reads `exhausted`, and is denied `denied-limit`.

`revoke(id)` — terminal take-down satisfying the MUST-be-revocable requirement: `delete` the ciphertext object (the retained `ciphertextKey`/`staticUrl` handle is exactly why this is possible), then CAS the sidecar to `status="revoked"`. Idempotent: revoking an already-`revoked` share is a no-op success; revoking a `deleted` share is a no-op (nothing to do). After revoke, `resolve` 404s because the ciphertext is gone *and* `live()` is terminal.

`delete(id)` — hard delete of both ciphertext and sidecar; no `revoked` tombstone remains. Idempotent (delete-of-absent is success). Use `revoke` when you want an auditable terminal record; `delete` when you want no trace.

`pause(id)` / `resume(id)` — MANAGED-only; CAS `status` between `paused`↔`active`, preserving `useCount` and `recipientLog`. Both throw `UnsupportedControlError` under STATIC. Idempotent toward their target state (pausing a paused share is a no-op success). Cannot move a terminal (`revoked`/`deleted`) share → `409`.

`extend(id, newExp)` — re-arm expiry. MANAGED: CAS `exp=newExp`; if the share was `expired` and `newExp>now`, this returns it to `active`. STATIC: honored only if `supportsLifecycle` (rewrites the lifecycle hint), else `UnsupportedControlError`. Idempotent for an unchanged `newExp`. Terminal shares reject.

`setLimits(id, {maxUses})` — MANAGED-only. CAS `maxUses`; setting `maxUses>useCount` re-arms an `exhausted` share to `active`, setting `maxUses=null` makes it unlimited. Lowering `maxUses` below the current `useCount` immediately drives the next `live()` to `exhausted` (allowed — it just denies further opens). Throws under STATIC.

`setPasscode(id, passcode|null)` — MANAGED-only. Hashes (`sha256`) and stores `passcodeHash`, resets `wrongPasscodeCount`; `null` clears the passcode and the `"P"` flag *for newly minted links* (note: already-shared links carry the flag in their immutable fragment, so clearing a passcode on a live `P` link means the receiver still sends a `passcode` the host now ignores — document this; prefer revoke+recreate to truly drop `P`). Throws under STATIC.

`setLabel(id, label)` — validates `<=80`, CAS the sidecar `label`. Note the *payload* `label` is frozen in the already-distributed fragment; `setLabel` updates only the owner-side/manifest-side record (and, under the KTC model, the client-encrypted stored label). Allowed in both profiles.

`accessLog(id)` — MANAGED-only audit read of `recipientLog` (bounded/rotated). Throws `UnsupportedControlError` under STATIC, because a blind object records nothing.

### Race-safe counting

The single correctness-critical transition is `active → active`/`exhausted` on `resolve`. Plain object stores have no compare-and-swap, so a naive read-increment-write races: two concurrent opens both read `useCount=4`, both write `5`, and `maxUses=5` is breached (over-counting) while one open is silently lost (under-recording). The fix is a conditional write keyed on the sidecar's `etag` (S3/R2/MinIO `If-Match`; GCS native `ifGenerationMatch=N`; Azure `If-Match`), wrapped in a bounded retry loop:

```ts
async function resolveManaged(metaKey: string, recipient: string, opts: ResolveOptions) {
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {       // e.g. MAX_RETRIES = 8
    const { bytes, info } = await store.get(metaKey);            // info.etag = CAS token
    const meta = JSON.parse(text(bytes)) as LinkMeta;
    const eff = live(meta, now());
    if (eff !== "active") return deny(eff, recipient);            // expired/paused/exhausted/revoked
    if (meta.passcodeHash && !checkPasscode(meta, opts.passcode))  // serialized via this same CAS
      return denyPasscode(meta, recipient);
    if (meta.maxUses != null && meta.useCount >= meta.maxUses)
      return deny("exhausted", recipient);

    meta.useCount += 1;                                           // may make useCount == maxUses
    meta.recipientLog.push({ at: now(), recipient, outcome: "ok" });
    if (meta.maxUses != null && meta.useCount >= meta.maxUses)
      meta.status = "exhausted";                                 // persist the terminal-for-opens transition

    const r = await store.conditionalPut(
      metaKey, json(meta), { kind: "if-match", etag: info.etag }, { cacheControl: "no-store" },
    );
    if (r.ok) return serveJwe(meta, opts);                       // committed — exactly one winner per use
    // r.reason === "precondition-failed" (412) | "conflict" (409/404) → re-read and retry
  }
  throw new TooMuchContentionError(metaKey);                     // surfaced as 503/Retry-After
}
```

On the *last allowed use*, exactly one concurrent resolver's `If-Match` matches the current `etag` and commits `useCount==maxUses`; every other resolver gets `precondition-failed`, re-reads the now-`exhausted` meta, and is cleanly denied `denied-limit`. No open is double-counted and none is lost. Wrong-passcode increments ride the same loop, giving the spec-required serial, lifetime-budgeted brute-force defense for free.

#### Fallback when the backend lacks conditional writes

`supportsConditionalWrite` is `false` on **B2** and (assume) **Wasabi**, and on **GCS reached through the S3/XML path** (its ETag preconditions are read-only; native `ifGenerationMatch` is JSON-API only). On such a store the manager must never run the loop above — it would silently overwrite and corrupt `useCount`. Three honest options, in preference order:

1. **Refuse the control (default).** At `create`, if `policy.maxUses`/`passcode` is requested and `!supportsConditionalWrite`, throw `UnsupportedControlError`. The share is downgraded to STATIC-grade controls: revoke-by-delete and (if `supportsLifecycle`) lifecycle expiry only. This is the HONESTY RULE applied literally — no use-limit, no opens-remaining, no passcode, no access log are surfaced because none can be enforced.
2. **Route state to an external KV with native CAS.** If the developer configures a KV side-channel (Redis `WATCH`/`MULTI`, DynamoDB conditional `UpdateItem`, etc.), the counter and log live there while ciphertext stays in the blob store. Capability becomes "CAS via KV"; the full MANAGED control surface is restored. This is the recommended path for B2/Wasabi/GCS-S3 deployments that genuinely need counting.
3. **Native-SDK escape for GCS.** For GCS specifically, prefer a native `gcsblob`/`google-cloud-storage` adapter whose `conditionalPut{if-match}` maps to `ifGenerationMatch=N`; this restores first-class CAS without an external KV. Treat the GCS-via-S3 path as STATIC-only.

What the manager must **not** do: approximate-count by eventually-consistent overwrite, or pretend `maxUses` is enforced when it isn't. "Approximate counting" is acceptable *only* as an explicitly-labeled, best-effort audit signal (e.g. append-only per-open log objects under a unique key per open, tallied lazily) and **never** as a use-*limit* gate — a limit the host cannot atomically enforce must not be offered as a control. Concretely: with the create-only primitive (`if-absent`, which many CAS-lacking stores still support — `supportsConditionalCreate`), the manager can write one immutable `…/opens/<uuid>.json` object per open and count them for the audit log, but it still cannot *cap* opens, so `maxUses` stays refused per option 1.

Files referenced for byte-compatibility: `/home/jmandel/periodicity/viewer-src/shl.mjs` (`resolveShl`/`fetchJwe`/`normalizedRecipient`, `DEFAULT_RECIPIENT = "Example User"`, manifest `files[0]` `embedded|location`, stale handling) and `/home/jmandel/periodicity/scripts/gen-shl.ts` (payload field order `url,key,flag,label,v`, fresh-key/IV rule, `<=128`-char `url` rationale).

---

---

## Security, privacy & deployment

### The blind-host invariant

The host stores **ciphertext only**. The AES-256 `key` lives exclusively in the `#shlink:/…` fragment, which never reaches the host (matching `scripts/gen-shl.ts`, where the key is concatenated into the fragment client-side and never sent to the `url` host). Three corollaries the adapter must guarantee:

- **Never persist `key`.** The `LinkMeta` sidecar (`<prefix><id>.json`) has no `key` field by construction. `ShareHandle.keyB64` is returned **once** from `create()` for the caller to embed in the link, then discarded by the manager — there is no read path that re-emits it. A backend adapter MUST NOT write `key` into object metadata, tags, or logs.
- **Never log `key`, fragments, or full links.** The data-plane handler only ever receives `url` (path + `?recipient=`) and POST bodies — the fragment is structurally absent. The adapter's request handler MUST scrub `Authorization` and any accidental `shlink:`-bearing query/header before emitting access logs.
- **Sidecar is host-readable; treat it as such.** Unlike `key`, `LinkMeta` (status, `exp`, `maxUses`, `useCount`, `recipientLog`) IS readable by the host operator. If the deployment requires the operator to be blind to even this control-plane state, adopt the KTC model: client-encrypt `label` and store only `passcodeHash` (sha256, never plaintext) — both already reflected in the §3 schema. The adapter ships `label` as plaintext by default but exposes a `labelCodec` hook to encrypt it under a key derived from the owner secret.

### Unguessable ids & enumeration resistance

The `url` path is the only thing standing between an attacker and the ciphertext (the key is still needed to *decrypt*, but the host should not serve ciphertext to crawlers). Requirements:

- **`id` carries ≥256 bits of entropy**, base64url-encoded (≈43 chars), generated from a CSPRNG (`crypto.getRandomValues(new Uint8Array(32))`). This is the `id` in `${endpointBase}/m/<id>` (MANAGED) and the object name component (STATIC). It satisfies the spec's "≥256-bit entropy in the path" guideline.
- **`list()` is an owner-only control-plane operation** — it reads the sidecar prefix via `store.list(prefix)`. The data plane never enumerates: `resolve(id)` does a direct keyed `get`/`head`, never a prefix scan, so a missing id is indistinguishable from a wrong guess.
- **Uniform negative responses.** STATIC: a wrong id is a bucket `404`. MANAGED: stale/missing/revoked all return `404` on the manifest POST (per spec) and on the direct `GET`, with no timing or body distinction between "never existed" and "revoked."
- **No incrementing or timestamp-derived ids** — they would let an attacker walk the namespace. The adapter rejects caller-supplied ids that are shorter than the entropy floor.

### Recipient handling & access-log privacy

`recipient` is the sole per-open input the host receives (`GET ?recipient=` or `POST {recipient}`), normalized exactly as `shl.mjs` does: `trim()` then fall back to `DEFAULT_RECIPIENT = "Example User"`. It is **attacker-controlled, free-text, and unauthenticated** — the SHL protocol does not verify it. Therefore:

- **Treat `recipient` as untrusted.** Cap length (e.g. 256 chars), strip control characters, and store it as an opaque string in `AccessLogEntry.recipient`. Never interpolate it into a shell, SQL, URL, or HTML sink. Never use it for authorization decisions — it is an audit *hint*, not an identity.
- **The access log is sensitive metadata.** It reveals who opened a health link and when. It is MANAGED-only, returned solely through the owner-authenticated `accessLog(id)`, and bounded/rotated in the sidecar so it cannot grow unboundedly or leak via a large public object. Under STATIC, `accessLog()` throws `UnsupportedControlError` — a blind public object physically cannot record opens, and surfacing an empty log would violate the honesty rule.
- **Outcomes, not payloads.** Log entries record `outcome` (`ok`, `denied-expired`, `denied-limit`, `denied-passcode`, `denied-revoked`) and never the decrypted content or the key.

### Presigned-URL TTL vs public-object trade-offs (and the `url`≤128 rule)

Presigned URLs are **structurally banned from the shlink `url` field**. A SigV4 presigned GET carries `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature` (and `X-Amz-Security-Token`, ~1500+ chars, when session credentials are used) — routinely hundreds to thousands of characters, always blowing the ≤128 budget. The manager enforces `url.length <= 128` at `create()` and throws `UrlTooLongError`; a presigned URL cannot pass.

| Where ciphertext lives | URL kind in `url` | TTL / expiry meaning | Trade-off |
|---|---|---|---|
| STATIC public object | short public-object URL (`store.publicUrl`/`config.staticUrl`) | none — "expiry" is object-lifecycle only | zero compute, CORS direct, but world-readable ciphertext until deleted; no counting |
| MANAGED mediated endpoint | `${endpointBase}/m/<id>` (~30–60 chars) | handler-enforced `exp`/`maxUses` | one hop of compute; object stays private |

Presigned/SAS URLs are legal **only inside the manifest body**, as `files[].location`, where length is unconstrained. There the manager prefers a **short-lived TTL** (spec: ≤1 hour, ideally single-use) via `store.presignGet(key, ttl)` or a stateless **HMAC ticket** (`${endpointBase}/m/<id>/f/<fileId>?t=<sig>`, KTC-style) that signs `{id,fileId,exp}` with a server secret — keeping the object private without a long presign and without a secret lookup.

### Revocation semantics per profile

Revocation MUST be real and MUST be possible for every share, which is why the manager retains a handle to each live share (`LinkMeta.ciphertextKey`, and `LinkMeta.staticUrl` for STATIC).

- **MANAGED — flip status, immediate.** `revoke(id)` CAS-writes `status:"revoked"` into the sidecar **and** deletes the ciphertext object. Because every `resolve` re-reads the sidecar under the CAS loop, the next open returns `404` synchronously — no cache window. `pause(id)` is the reversible variant (`status:"paused"`); `revoke` is terminal. This is the strong guarantee and the reason use-limits/passcode require MANAGED.
- **STATIC — delete the object.** The only take-down a blind host supports is `store.delete(ciphertextKey)` (plus overwriting with zero bytes if the backend's delete is eventually-consistent). `revoke()` and `delete()` both reduce to this; `pause/resume` throw `UnsupportedControlError`.
- **CDN / cache purge caveat.** If a CDN or `Cache-Control` fronts the public object, deletion does **not** immediately revoke — a cached copy keeps serving until TTL. The adapter sets `Cache-Control: no-store` on the MANAGED endpoint responses and on STATIC ciphertext where the backend honors it, and the STATIC `ensureCors`/publish helpers document that the operator MUST issue a CDN purge as part of revoke (the adapter exposes a `purgeHooks` callback for this).
- **Immutability / retained-copies warning.** Object versioning, bucket replication, backups, MFA-delete, or compliance/WORM locks can retain a copy after `delete`. The adapter MUST warn (and refuse to claim revocability) when it detects versioning/object-lock on the target bucket via `head`/bucket config — surfacing "this bucket retains deleted versions; revoke is not guaranteed terminal" rather than silently lying. Treat a versioned/locked bucket like git history: a delete is not an erase.

### Required CORS configuration per backend

The browser viewer fetches ciphertext **cross-origin** (the demo's `url` points at the CORS-durable `periodicity.fhir.me` precisely because `hl7.org` does not send CORS). Every backend hosting the `url` MUST serve permissive CORS, or the viewer's `fetch` fails. The adapter ships `ensureCors(allowedOrigins)` per backend (no-op when `!capabilities.supportsCors`). Direct-file (`U`) needs `GET`; manifest needs `POST`; both need the `content-type` request header allowed.

**AWS S3 / Cloudflare R2 / MinIO / B2 / Wasabi — per-bucket CORS** (`PutBucketCors`):

```json
[
  {
    "AllowedOrigins": ["https://periodicity.fhir.me"],
    "AllowedMethods": ["GET", "POST"],
    "AllowedHeaders": ["content-type"],
    "ExposeHeaders": ["ETag", "Content-Type"],
    "MaxAgeSeconds": 3600
  }
]
```

**Google Cloud Storage — per-bucket CORS** (native JSON; the XML/S3 path also honors it):

```json
[
  {
    "origin": ["https://periodicity.fhir.me"],
    "method": ["GET", "POST"],
    "responseHeader": ["content-type", "ETag"],
    "maxAgeSeconds": 3600
  }
]
```

**Azure Blob — account/service-level CORS** (the odd one out: set on the Blob *service*, not per container, via Set Blob Service Properties):

```xml
<Cors>
  <CorsRule>
    <AllowedOrigins>https://periodicity.fhir.me</AllowedOrigins>
    <AllowedMethods>GET,POST</AllowedMethods>
    <AllowedHeaders>content-type</AllowedHeaders>
    <ExposedHeaders>ETag,Content-Type</ExposedHeaders>
    <MaxAgeInSeconds>3600</MaxAgeInSeconds>
  </CorsRule>
</Cors>
```

The Azure adapter owns this account-scoped mental model so callers still only invoke `ensureCors([...])`. For STATIC direct-file, `["GET"]` suffices; the adapter requests `GET, POST` when the profile is MANAGED.

### What the data-plane handler MUST do

The MANAGED request handler is a thin HTTP shell over `resolve` (and the CAS loop in §3). It MUST:

- **Validate & normalize `recipient`** (trim → `DEFAULT_RECIPIENT`, length cap, strip control chars) before logging or branching.
- **Never echo `key`, sidecar internals, or the plaintext bundle** in any response or error. Errors are status-coded only: `404` stale/missing/revoked, `401 {remainingAttempts}` wrong passcode, `429` + `Retry-After` on `L` over-polling.
- **Set correct content types:** direct-file → `Content-Type: application/jose` with the JWE compact string as the body; manifest → `application/json` `{ files:[{contentType, embedded|location}] }`. (The receiver reads the body as text and does not check the type, but compliant types keep other receivers working.)
- **Run the CAS counter before serving** so a denied open never returns ciphertext, and honor `embeddedLengthMax` (oversized → `location` instead of `embedded`).
- **Rate-limit** per id and per source IP to blunt enumeration, passcode brute-force (in addition to the lifetime wrong-passcode budget), and counter-exhaustion griefing. Process competing passcode attempts **serially** so the lifetime budget can't be raced.
- **Be SSRF-safe.** `location`/`embedded` come from the adapter's own store, never from caller input; the handler MUST NOT fetch a caller-supplied URL. `recipient` and `passcode` are never used to construct an outbound request. Presign/ticket TTLs are server-chosen, not client-chosen.
- **Send `Cache-Control: no-store`** on all data-plane responses so a counted/limited open is never replayed from a cache.
- **No `Authorization` on the data plane.** The control token (KTC-style `sha256(auth)`) is required only for the owner control-plane endpoints and travels in the `Authorization` header, never in a URL path.

### Threat model

| Threat | Mitigation |
|---|---|
| Host reads patient data | Blind-host invariant: store ciphertext only; `key` lives in the fragment, never sent/stored/logged |
| Key leaks via server logs / referrer | `#` fragment never leaves the browser; handler scrubs `Authorization` and any `shlink:`-bearing field |
| Link-id enumeration / crawling | ≥256-bit CSPRNG id in path; uniform `404`; no list on the data plane; rate-limit |
| Replay past expiry / use-limit | MANAGED CAS counter + `live(meta,now)` re-checked every open; `no-store`; STATIC honestly omits these controls |
| Counter overshoot under concurrency | `conditionalPut{if-match:etag}` RMW loop; refuse `maxUses` when `!supportsConditionalWrite` (B2/Wasabi/GCS-via-S3) |
| Passcode brute-force | Lifetime wrong-attempt budget; serial processing; `401 {remainingAttempts}`; rate-limit |
| Revocation bypass via CDN/version cache | `no-store`; documented CDN purge hook; refuse to claim revocability on versioned/WORM buckets |
| Presigned URL leaks long-lived access | Banned from `url`; only short-TTL/single-use `location` inside manifest; prefer HMAC ticket |
| SSRF via handler | Handler fetches only its own store keys; never a caller-supplied URL; no `recipient`/`passcode` in outbound requests |
| Recipient field injection | Untrusted free-text: length-capped, control-char-stripped, opaque in log, never an auth or sink input |
| Tampered ciphertext / wrong key | AES-GCM auth tag + protected-header AAD (`jwe.mjs`): decrypt hard-fails; `importKey` rejects non-32-byte keys |
| Cross-origin fetch blocked (DoS-by-misconfig) | `ensureCors()` per backend; `UrlTooLongError`/capability guards fail loudly at `create`, not silently at open |

### Backend support / capability matrix

| Backend | API | CORS | Conditional write (CAS) | Lifecycle expiry | Presign | SHL verdict |
|---|---|---|---|---|---|---|
| **AWS S3** | native S3 | per-bucket | **Yes** (`If-None-Match:*` + `If-Match:etag`, GA 2024) | per-bucket prefix rules | yes (SigV4) | MANAGED ✓ |
| **Cloudflare R2** | S3-compat (region `auto`) | per-bucket (`PutBucketCors`) | **Yes** (`If-Match`/`If-None-Match`) | per-bucket | yes | MANAGED ✓ |
| **MinIO** | native S3 | per-bucket | **Yes** (full RFC 7232) | yes | yes | MANAGED ✓ (self-host) |
| **Google Cloud Storage** | native JSON + S3/XML interop | per-bucket | **Native JSON only** (`ifGenerationMatch`); **S3/XML path = reads only** | per-bucket (Age) | yes | MANAGED via native SDK; STATIC via S3 path |
| **Backblaze B2** | native + S3-compat | per-bucket (`PutBucketCors`) | **No** (`If-None-Match` not implemented) | yes (lifecycle rules) | yes | **STATIC only** (counters need external KV) |
| **Wasabi** | S3-compat | per-bucket | **Unverified — assume no** | yes | yes | STATIC only (until proven) |
| **Azure Blob** | native (no S3 API) | **account/service-level** | **Yes** via ETag `If-Match` (+ leases) | **account-level policy**, day-granularity | SAS (long) | MANAGED ✓ via native adapter; per-object `exp` emulated by handler |

Reading the matrix: pick **S3, R2, or MinIO** when use-limits/passcode matter — one S3 code path gives CAS. **GCS and Azure** need their native SDK adapter for honest CAS (and Azure for CORS/lifecycle, which it scopes to the account). **B2 and Wasabi** are STATIC-grade for counting: still revocable (delete) and expiring (lifecycle), but the manager refuses `maxUses`/`passcode` at `create()` unless an external CAS-capable KV is configured for state — never running the §3 loop against a backend that would silently overwrite `useCount`.

---

## Worked examples

The full sender + receiver path using the abstraction (never raw storage ops).

Verified against the actual source. The payload order is `url, key, flag, label, v` (no `exp` in the demo minter, but `parseShlink` accepts `exp`), the link form is `${VIEWER_BASE}/#shlink:/…`, and `DEFAULT_RECIPIENT = "Example User"`. Now writing the section.

### TypeScript / Node

Configure the manager once against any S3-compatible store (AWS/R2/MinIO/B2) from env, choosing the profile by which controls you must honestly offer.

```ts
// shl.ts — wiring. One S3 code path serves AWS, Cloudflare R2, MinIO, B2, Wasabi.
import { S3Client } from "@aws-sdk/client-s3";
import { S3ObjectStore } from "@your-org/shl-store-s3"; // ships the ObjectStore port over @aws-sdk/client-s3
import { ShareManager } from "@your-org/shl-manager";

const s3 = new S3Client({
  region: process.env.S3_REGION ?? "auto",        // R2 uses "auto"
  endpoint: process.env.S3_ENDPOINT,               // set for R2/MinIO/B2; omit for AWS
  forcePathStyle: process.env.S3_PATH_STYLE === "1", // MinIO/B2 want path-style
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID!,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY!,
  },
});

const store = new S3ObjectStore({
  client: s3,
  bucket: process.env.S3_BUCKET!,
  // publicUrl() builds the SHORT static `url`; point at your CDN/custom domain.
  publicBaseUrl: process.env.PUBLIC_BASE_URL,       // e.g. "https://periodicity.fhir.me"
});

// MANAGED: full controls (count, use-limit, pause/resume, audit). Requires CAS.
export const managed = new ShareManager({
  store,
  profile: "managed",
  prefix: "shl/",
  viewerBase: process.env.VIEWER_BASE ?? "https://periodicity.fhir.me",
  endpointBase: process.env.ENDPOINT_BASE!,         // e.g. "https://api.example.com"
  deflateDefault: false,                            // safe for unknown viewers
});

// One-time, idempotent: install CORS so the browser viewer can fetch cross-origin.
await store.ensureCors?.([process.env.VIEWER_BASE ?? "https://periodicity.fhir.me"]);
```

Create a managed share from a FHIR Bundle JSON string with an expiry, a use-limit, and a label, then hand the UI both the shareable link and the QR payload.

```ts
// create.ts
import { managed } from "./shl";

const fhirBundleJson = await readBundleSomehow(); // a UTF-8 FHIR Bundle JSON string

const handle = await managed.create({
  content: fhirBundleJson,
  contentType: "application/fhir+json",
  label: "Period-tracking export (Jun 2026)",       // ≤80 chars
  policy: {
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600, // epoch SECONDS, +7 days
    maxUses: 5,                                          // MANAGED-enforced opens-remaining
  },
});

// handle.keyB64 is returned ONCE and is already baked into handle.link's fragment.
console.log("id:        ", handle.id);
console.log("share this:", handle.link);              // https://periodicity.fhir.me/#shlink:/<b64u>
console.log("url length:", handle.payload.url.length, "(≤128)"); // e.g. https://api.example.com/m/<id>

// For the UI: a string to feed a QR renderer, plus the same link to copy/share.
const qrText = managed.qrPayload(handle.payload);     // === handle.link
```

List a user's shares with their live status and opens-remaining for a dashboard.

```ts
// list.ts
import { managed } from "./shl";

const rows = await managed.list({ status: ["active", "paused"] });
for (const m of rows) {
  const remaining = m.maxUses == null ? "∞" : m.maxUses - m.useCount;
  console.log(
    `${m.id.slice(0, 8)}…  ${m.status.padEnd(9)}  uses ${m.useCount}/${m.maxUses ?? "∞"} ` +
    `(left ${remaining})  exp ${m.exp ? new Date(m.exp * 1000).toISOString() : "—"}  ${m.label ?? ""}`,
  );
}
```

The MANAGED data-plane endpoint as an Express route: direct-file `GET` returns `application/jose`; manifest `POST` returns `{files:[…]}`; denied/stale opens map to spec-correct status codes — all via `resolve`, never raw storage.

```ts
// server.ts
import express from "express";
import { managed } from "./shl";

const app = express();
app.use(express.json({ limit: "64kb" }));

// One route serves both rails. `id` is the ≥256-bit path component from the shlink `url`.
app.all("/m/:id", async (req, res) => {
  const { id } = req.params;
  const recipient = req.method === "GET" ? req.query.recipient : req.body?.recipient;
  const passcode  = req.method === "GET" ? undefined          : req.body?.passcode;
  res.setHeader("Cache-Control", "no-store");   // never replay a counted open from cache

  try {
    if (req.method === "GET") {
      // direct-file (flag "U"): body IS the JWE. resolve() runs the CAS counter first.
      const { jwe } = await managed.resolve(id, String(recipient ?? ""));
      res.type("application/jose").send(jwe);
      return;
    }
    if (req.method === "POST") {
      // manifest: choose embedded vs short-lived location by size.
      const { jwe, label } = await managed.resolve(id, String(recipient ?? ""), {
        passcode: passcode ? String(passcode) : undefined,
        embeddedLengthMax: 50_000,
      });
      res.type("application/json").json({
        files: [{ contentType: "application/fhir+json", embedded: jwe }],
        ...(label ? { label } : {}),
      });
      return;
    }
    res.sendStatus(405);
  } catch (err: any) {
    // The manager never leaks key/sidecar/plaintext; map denials to SHL status codes.
    switch (err?.code) {
      case "denied-expired":
      case "denied-revoked":
      case "denied-limit":
      case "not-found":           return void res.sendStatus(404); // uniform: stale == missing
      case "denied-passcode":     return void res.status(401).json({ remainingAttempts: err.remainingAttempts ?? 0 });
      case "too-much-contention": return void res.set("Retry-After", "1").sendStatus(503);
      default:                    return void res.sendStatus(500);
    }
  }
});

app.listen(3000);
```

The same handler ports to a Cloudflare Worker almost verbatim — the only change is the request/response plumbing, since `resolve` is framework-agnostic.

```ts
// worker.ts (Cloudflare) — managed is built the same way, with endpoint/bucket from env bindings.
export default {
  async fetch(req: Request): Promise<Response> {
    const id = new URL(req.url).pathname.split("/").pop()!;
    const h = { "cache-control": "no-store" };
    try {
      if (req.method === "GET") {
        const recipient = new URL(req.url).searchParams.get("recipient") ?? "";
        const { jwe } = await managed.resolve(id, recipient);
        return new Response(jwe, { headers: { ...h, "content-type": "application/jose" } });
      }
      const { recipient, passcode } = await req.json<any>();
      const { jwe } = await managed.resolve(id, recipient ?? "", { passcode, embeddedLengthMax: 50_000 });
      return Response.json({ files: [{ contentType: "application/fhir+json", embedded: jwe }] }, { headers: h });
    } catch (err: any) {
      if (err?.code === "denied-passcode") return Response.json({ remainingAttempts: err.remainingAttempts ?? 0 }, { status: 401, headers: h });
      const stale = ["denied-expired", "denied-revoked", "denied-limit", "not-found"].includes(err?.code);
      return new Response(null, { status: stale ? 404 : 500, headers: h });
    }
  },
};
```

Owner control-plane operations — revoke (terminal, deletes ciphertext), pause/resume, and re-arm expiry — are one call each.

```ts
// controls.ts
import { managed } from "./shl";

await managed.pause(id);                                  // status → "paused"; next resolve 404s
await managed.resume(id);                                 // status → "active"
await managed.extend(id, Math.floor(Date.now() / 1000) + 30 * 24 * 3600); // re-arm exp; un-expires
await managed.setLimits(id, { maxUses: 10 });             // re-arm an exhausted share
await managed.revoke(id);                                 // TERMINAL: deletes ciphertext + status "revoked"
// managed.delete(id) leaves no tombstone; revoke when you want an auditable record.

const log = await managed.accessLog(id);                 // MANAGED-only audit trail
for (const e of log) console.log(e.at, e.recipient, e.outcome);
```

The STATIC profile differs only at construction and in which controls exist: the `url` is the public object itself (direct-file `"U"`), so there's no data-plane handler, and revoke is a delete.

```ts
// static.ts — same store, different profile. No endpointBase; no mediated route.
import { ShareManager } from "@your-org/shl-manager";
import { store } from "./shl"; // the same S3ObjectStore

const staticMgr = new ShareManager({
  store,
  profile: "static",
  viewerBase: "https://periodicity.fhir.me",
  // url comes from store.publicUrl(key); override for a CDN/custom domain:
  staticUrl: (key) => `https://periodicity.fhir.me/${key}`, // short, ≤128 chars
});

const h = await staticMgr.create({
  content: fhirBundleJson,
  label: "Public synthetic demo",
  policy: { exp: Math.floor(Date.now() / 1000) + 86_400 }, // honored ONLY if lifecycle-capable, else throws
  // policy.maxUses / passcode would throw UnsupportedControlError here — a blind object can't enforce them.
});
console.log(h.payload.flag); // "U" — receiver does GET <publicUrl>?recipient=… and gets the JWE directly

await staticMgr.revoke(h.id); // === store.delete(ciphertextKey); the retained handle is why this works.
// staticMgr.pause/resume/setLimits/accessLog all throw UnsupportedControlError (honesty rule).
```

A tiny browser snippet for the present step: render the QR, copy-to-clipboard, and invoke the native share sheet — all client-side, with the key never leaving the page.

```html
<!-- present.html — `link` is handle.link from create(); the #fragment key stays client-side. -->
<canvas id="qr"></canvas>
<button id="copy">Copy link</button>
<button id="share">Share…</button>
<script type="module">
  import QRCode from "https://esm.sh/qrcode";

  const link = location.hash ? location.href : "https://periodicity.fhir.me/#shlink:/…"; // injected by your app
  await QRCode.toCanvas(document.getElementById("qr"), link, { errorCorrectionLevel: "M", margin: 1 });

  document.getElementById("copy").onclick = async () => {
    await navigator.clipboard.writeText(link);
  };
  document.getElementById("share").onclick = async () => {
    if (navigator.share) await navigator.share({ title: "Health link", url: link });
    else await navigator.clipboard.writeText(link); // fallback where Web Share is unavailable
  };
</script>
```

The files confirm the contract. Now writing the Python example section.

### Python

The runnable example assumes a published package `shl_objstore` exposing the canonical types from §1–§4 (`ShareManager`, `S3ObjectStore`, the policy/handle dataclasses). Every snippet calls the high-level manager only — boto3 lives *behind* the `ObjectStore` port, never in app code.

Configure and instantiate the manager from environment, wiring an S3-compatible store (AWS S3 / R2 / MinIO / B2 / Wasabi — same code path) behind the `ObjectStore` port; this is the only place backend credentials appear.

```python
# config.py — build a ShareManager from env. No raw bucket/key/presign here.
import os
from functools import lru_cache

from shl_objstore import ShareManager, ShareManagerConfig
from shl_objstore.backends.s3 import S3ObjectStore  # thin adapter over boto3

@lru_cache
def get_manager(profile: str = os.environ.get("SHL_PROFILE", "managed")) -> ShareManager:
    # S3ObjectStore wraps boto3 and fills `capabilities` from the static matrix
    # (S3/R2/MinIO -> supportsConditionalWrite=True; B2/Wasabi -> False).
    store = S3ObjectStore(
        bucket=os.environ["SHL_BUCKET"],
        endpoint_url=os.environ.get("SHL_ENDPOINT_URL"),   # set for R2/MinIO/B2/Wasabi; omit for AWS
        region=os.environ.get("SHL_REGION", "auto"),
        access_key=os.environ["SHL_ACCESS_KEY"],
        secret_key=os.environ["SHL_SECRET_KEY"],
        # public base used by store.public_url(key) to build short STATIC urls / CDN domain
        public_base=os.environ.get("SHL_PUBLIC_BASE"),
    )
    # One-time, idempotent CORS install so the browser viewer can fetch cross-origin.
    # No-op when !store.capabilities.supports_cors. GET+POST for MANAGED; GET for STATIC.
    store.ensure_cors([os.environ.get("SHL_VIEWER_ORIGIN", "https://periodicity.fhir.me")])

    return ShareManager(ShareManagerConfig(
        store=store,
        profile=profile,                                   # "managed" | "static"
        prefix=os.environ.get("SHL_PREFIX", "shl/"),
        viewer_base=os.environ.get("SHL_VIEWER_BASE", "https://periodicity.fhir.me"),
        endpoint_base=os.environ.get("SHL_ENDPOINT_BASE"), # MANAGED: e.g. https://api.example.org
        deflate_default=False,                             # off for unknown viewers (DEFLATE caveat)
    ))
```

Create a share from a FHIR bundle JSON string with a real policy (`exp`, `maxUses`, `label`), then read back the shareable link and a QR-ready string; `keyB64` is returned once and lives only in the link fragment.

```python
# create_share.py
import time, qrcode  # qrcode renders the QR; the manager only supplies the payload string
from config import get_manager
from shl_objstore import CreateShareInput, SharePolicy

def create_demo_share(owner_id: str, bundle_json: str) -> dict:
    mgr = get_manager()  # managed profile
    handle = mgr.create(CreateShareInput(
        content=bundle_json,                     # UTF-8 FHIR Bundle string -> JWE (dir/A256GCM, cty application/fhir+json)
        content_type="application/fhir+json",
        label="Longitudinal period-tracking export",   # <=80 chars
        policy=SharePolicy(
            exp=int(time.time()) + 7 * 24 * 3600,       # 7-day server-enforced expiry (MANAGED)
            max_uses=5,                                  # opens-remaining gate (MANAGED, CAS-enforced)
            # passcode="1234",                           # would add "P" flag; mutually exclusive with "U"
        ),
        # owner_ref=owner_id,  # stored opaquely in sidecar so list(filter) can scope to this user
    ))

    # handle.link is the full shareable string: "<viewer>/#shlink:/<b64u(json)>".
    # handle.key_b64 is shown ONCE — it is in the fragment, never stored host-side.
    qr_png = f"/tmp/{handle.id}.png"
    qrcode.make(mgr.qr_payload(handle.payload)).save(qr_png)  # same bytes the viewer decodes

    return {
        "id": handle.id,
        "link": handle.link,            # paste / "share" action target
        "qr_png_path": qr_png,          # on-screen QR (HARD REQUIREMENT: QR + copy of same link)
        "key_b64": handle.key_b64,      # surface to the user once; do not persist server-side
        "opens_remaining": handle.meta.max_uses,
    }
```

List a user's shares with effective status (`live()`-derived) and opens-remaining, filtering out terminal ones — a pure control-plane read over the sidecar prefix.

```python
# list_shares.py
from config import get_manager
from shl_objstore import ListFilter

def list_active_shares() -> list[dict]:
    mgr = get_manager()
    metas = mgr.list(ListFilter(status=["active", "paused"]))  # owner-only; never enumerated on data plane
    return [
        {
            "id": m.id,
            "label": m.label,
            "status": m.status,                                # effective: active|paused|expired|exhausted|revoked
            "opens_remaining": (None if m.max_uses is None else m.max_uses - m.use_count),
            "expires_at": m.exp,
            "created_at": m.created_at,
        }
        for m in metas
    ]
```

The MANAGED data-plane endpoint is a thin FastAPI shell over `resolve`: it handles direct-file `GET` (`application/jose` body) and manifest `POST` (`{files:[…]}`), normalizes the attacker-controlled `recipient`, enforces state via the CAS counter, and maps denials to SHL status codes with `no-store`.

```python
# data_plane.py — mount the MANAGED handler. resolve() runs the §3 CAS loop internally.
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from config import get_manager
from shl_objstore import ResolveOptions, DEFAULT_RECIPIENT
from shl_objstore.errors import (
    DeniedExpired, DeniedLimit, DeniedRevoked, DeniedPaused,
    WrongPasscode, TooMuchContention,
)

app = FastAPI()
NO_STORE = {"cache-control": "no-store"}  # never replay a counted open from cache

# Direct-file (flag "U"): GET <url>?recipient=...  -> body IS the JWE (application/jose).
@app.get("/m/{share_id}")
async def resolve_direct(share_id: str, request: Request):
    mgr = get_manager()
    recipient = (request.query_params.get("recipient") or "").strip() or DEFAULT_RECIPIENT
    try:
        result = mgr.resolve(share_id, recipient)              # runs CAS counter + live() check
    except (DeniedExpired, DeniedLimit, DeniedRevoked, DeniedPaused):
        # uniform 404: stale/missing/revoked are indistinguishable (enumeration resistance)
        return Response(status_code=404, headers=NO_STORE)
    except TooMuchContention:
        return Response(status_code=503, headers={**NO_STORE, "retry-after": "1"})
    # result.jwe is the compact JWE string; key stays client-side, never echoed here.
    return PlainTextResponse(result.jwe, media_type="application/jose", headers=NO_STORE)

# Manifest mode (no "U"): POST {recipient, passcode?} -> {files:[{contentType, embedded|location}]}.
@app.post("/m/{share_id}")
async def resolve_manifest(share_id: str, request: Request):
    mgr = get_manager()
    body = await request.json()
    recipient = (str(body.get("recipient") or "")).strip() or DEFAULT_RECIPIENT
    opts = ResolveOptions(
        passcode=body.get("passcode"),
        embedded_length_max=body.get("embeddedLengthMax"),
    )
    try:
        manifest = mgr.resolve_manifest(share_id, recipient, opts)  # chooses embedded vs short-TTL location
    except WrongPasscode as e:
        return JSONResponse({"remainingAttempts": e.remaining_attempts},
                            status_code=401, headers=NO_STORE)
    except (DeniedExpired, DeniedLimit, DeniedRevoked, DeniedPaused):
        return Response(status_code=404, headers=NO_STORE)   # SHL stale semantics
    except TooMuchContention:
        return Response(status_code=503, headers={**NO_STORE, "retry-after": "1"})
    # manifest == {"files": [{"contentType": "application/fhir+json", "embedded": "<jwe>"}]}
    return JSONResponse(manifest, headers=NO_STORE)
```

Owner control-plane operations — revoke (terminal: delete ciphertext + tombstone), pause/resume, and extend (re-arm expiry) — each one CAS-mutates the sidecar and is idempotent toward its target state.

```python
# manage_shares.py
from config import get_manager

def revoke_share(share_id: str) -> None:
    # Terminal take-down: deletes the ciphertext (retained ciphertext_key handle) AND
    # marks status="revoked". Next resolve() -> 404. Idempotent.
    get_manager().revoke(share_id)

def pause_share(share_id: str):    # MANAGED only; reversible, preserves use_count + log
    return get_manager().pause(share_id)

def resume_share(share_id: str):
    return get_manager().resume(share_id)

def extend_share(share_id: str, new_exp_epoch_s: int):
    # Re-arms expiry; if the share was "expired" and new_exp>now it returns to "active".
    return get_manager().extend(share_id, new_exp_epoch_s)
```

The STATIC profile shares the same surface but builds a direct public-object link (`flag` includes `"U"`, short `publicUrl`), and `revoke` reduces to deleting the object — calling a MANAGED-only control raises `UnsupportedControlError`, enforcing the honesty rule.

```python
# static_profile.py
from config import get_manager
from shl_objstore import CreateShareInput, SharePolicy
from shl_objstore.errors import UnsupportedControlError

def create_static_share(bundle_json: str) -> dict:
    mgr = get_manager("static")  # store-only; no mediated endpoint
    handle = mgr.create(CreateShareInput(
        content=bundle_json,
        label="Public synthetic demo export",
        # exp is honored ONLY if store.capabilities.supports_lifecycle (maps to object lifecycle);
        # max_uses/passcode would raise UnsupportedControlError at create — never silently dropped.
        policy=SharePolicy(exp=None),
    ))
    # payload.url is a short public-object URL (e.g. https://periodicity.fhir.me/<id>.jwe),
    # flag includes "U" -> receiver does GET url?recipient=... and the body IS the JWE.
    assert "U" in (handle.payload.flag or "")

    try:
        mgr.access_log(handle.id)          # a blind object records nothing ->
    except UnsupportedControlError:
        pass                               # ... honest failure, not an empty log

    return {"id": handle.id, "link": handle.link, "key_b64": handle.key_b64}

def revoke_static_share(share_id: str) -> None:
    # STATIC revoke == delete the object (the only take-down a blind host supports).
    # If a CDN fronts the object, issue a purge too (purge_hooks) — deletion alone
    # leaves cached copies until TTL.
    get_manager("static").revoke(share_id)
```

### Go

This example targets the `ShareManager` Go binding (`shl.ShareManager`) backed by the `gocloud.dev/blob`-over-`ObjectStore` adapter from the matrix; app code never touches a `*blob.Bucket`, presign, or CORS call directly.

Configure and instantiate the manager from the environment — one `blobstore.Open` URL selects S3/GCS/Azure/R2, and the profile is chosen by which controls the product must honestly offer.

```go
// cmd/shldemo/manager.go
package main

import (
	"context"
	"fmt"
	"os"

	"example.com/shl"          // the ShareManager + ports
	"example.com/shl/blobstore" // gocloud.dev/blob adapter over the ObjectStore port
)

// newManager wires a gocloud.dev/blob bucket behind the ObjectStore port and
// returns a ShareManager. BLOB_URL is any gocloud bucket URL, e.g.
//   s3://my-bucket?region=us-east-1
//   gs://my-bucket
//   azblob://my-container
//   s3://my-bucket?endpoint=https://<acct>.r2.cloudflarestorage.com&region=auto  (R2)
func newManager(ctx context.Context, profile shl.Profile) (*shl.ShareManager, error) {
	store, err := blobstore.Open(ctx, os.Getenv("BLOB_URL")) // implements shl.ObjectStore
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// Install permissive CORS for the viewer origin (no-op if !supportsCors).
	// MANAGED requests GET+POST; STATIC direct-file only needs GET.
	if err := store.EnsureCors(ctx, []string{os.Getenv("VIEWER_BASE")}); err != nil {
		return nil, fmt.Errorf("ensure cors: %w", err)
	}
	return shl.NewShareManager(shl.ShareManagerConfig{
		Store:        store,
		Profile:      profile,                  // "managed" or "static"
		Prefix:       "shl/",                   // ciphertext + sidecar live here
		ViewerBase:   os.Getenv("VIEWER_BASE"), // e.g. https://periodicity.fhir.me
		EndpointBase: os.Getenv("ENDPOINT_BASE"), // MANAGED only, e.g. https://host
		// DeflateDefault defaults to false (unknown viewers); leave unset.
	})
}
```

Create a MANAGED share from a FHIR Bundle JSON string with an expiry, a use-limit, and a label, then obtain the viewer-prefixed link and a QR-ready payload string.

```go
// cmd/shldemo/create.go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"example.com/shl"
)

func createShare(ctx context.Context, mgr *shl.ShareManager) (*shl.ShareHandle, error) {
	bundleJSON, err := os.ReadFile("bundle.json") // a FHIR Bundle as a JSON string
	if err != nil {
		return nil, err
	}
	h, err := mgr.Create(ctx, shl.CreateShareInput{
		Content: string(bundleJSON),
		// ContentType defaults to "application/fhir+json".
		Label: "Periodicity — synthetic longitudinal export",
		Policy: &shl.SharePolicy{
			Exp:     shl.EpochSeconds(time.Now().Add(7 * 24 * time.Hour).Unix()),
			MaxUses: ptr(5), // MANAGED-only; STATIC would reject this at Create
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create: %w", err) // UnsupportedControlError if MaxUses under STATIC
	}
	fmt.Println("id:        ", h.ID)
	fmt.Println("share link:", h.Link)           // https://periodicity.fhir.me/#shlink:/<b64u>
	fmt.Println("qr payload:", mgr.QRPayload(h.Payload)) // feed to your QR renderer
	fmt.Println("key (once):", h.KeyB64)         // returned ONCE; embedded in the fragment, never stored
	return h, nil
}

func ptr[T any](v T) *T { return &v }
```

Render the QR client-side from `QRPayload` and present the same string as a copy/share action — here writing a PNG so the snippet is self-contained.

```go
// cmd/shldemo/qr.go
package main

import (
	"os"

	"github.com/skip2/go-qrcode"
	"example.com/shl"
)

func writeQR(mgr *shl.ShareManager, h *shl.ShareHandle, path string) error {
	payload := mgr.QRPayload(h.Payload) // same string the copy/share button uses
	return qrcode.WriteFile(payload, qrcode.Medium, 512, path)
}

var _ = os.Stdout // keep imports honest in trimmed example
```

List a user's shares with their live status, filtering to the ones still resolvable.

```go
// cmd/shldemo/list.go
package main

import (
	"context"
	"fmt"
	"time"

	"example.com/shl"
)

func listActive(ctx context.Context, mgr *shl.ShareManager) error {
	metas, err := mgr.List(ctx, &shl.ListFilter{
		Status: []shl.LinkStatus{shl.StatusActive, shl.StatusPaused},
	})
	if err != nil {
		return err
	}
	for _, m := range metas {
		remaining := "∞"
		if m.MaxUses != nil {
			remaining = fmt.Sprintf("%d", *m.MaxUses-m.UseCount)
		}
		exp := "none"
		if m.Exp != nil {
			exp = time.Unix(int64(*m.Exp), 0).Format(time.RFC3339)
		}
		// Status reflects live(meta, now): expired/exhausted collapse here too.
		fmt.Printf("%s  status=%-9s opens=%d remaining=%s exp=%s  %q\n",
			m.ID, m.Status, m.UseCount, remaining, exp, deref(m.Label))
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
```

Mount the MANAGED data-plane endpoint with `net/http`: it is a thin shell over `mgr.Resolve`, handling direct-file `GET` and manifest `POST`, mapping denials to spec status codes, and emitting `application/jose` for the JWE.

```go
// cmd/shldemo/handler.go
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"example.com/shl"
)

// managedHandler serves ${ENDPOINT_BASE}/m/<id> for both retrieval modes.
func managedHandler(mgr *shl.ShareManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/m/")
		w.Header().Set("Cache-Control", "no-store") // never replay a counted open

		var recipient, passcode string
		switch r.Method {
		case http.MethodGet: // direct-file (flag "U")
			recipient = r.URL.Query().Get("recipient")
		case http.MethodPost: // manifest
			var body struct {
				Recipient string `json:"recipient"`
				Passcode  string `json:"passcode"`
			}
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
			recipient, passcode = body.Recipient, body.Passcode
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}

		// Resolve runs the race-safe CAS counter loop and state checks (§3).
		res, err := mgr.Resolve(r.Context(), id, recipient, &shl.ResolveOptions{
			Passcode:          passcode,
			EmbeddedLengthMax: 64 * 1024, // larger payloads come back as location
		})
		if err != nil {
			writeResolveError(w, err) // uniform 404/401/429; never echoes internals
			return
		}

		if r.Method == http.MethodGet {
			// Direct-file: the body IS the JWE compact string.
			w.Header().Set("Content-Type", "application/jose")
			_, _ = w.Write([]byte(res.JWE))
			return
		}
		// Manifest: files[0] carries the JWE inline (embedded) or a short location.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"files": []map[string]any{{
				"contentType": "application/fhir+json",
				"embedded":    res.JWE, // adapter swaps to {"location": ...} if oversized
			}},
		})
	}
}

// writeResolveError maps denial reasons to SHL status codes with no body leakage.
func writeResolveError(w http.ResponseWriter, err error) {
	var denied *shl.DeniedError
	if errors.As(err, &denied) {
		switch denied.Outcome {
		case "denied-passcode":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized) // 401 {remainingAttempts}
			_ = json.NewEncoder(w).Encode(map[string]int{"remainingAttempts": denied.RemainingAttempts})
		default: // expired / exhausted / paused / revoked → stale
			http.Error(w, "", http.StatusNotFound) // 404, uniform negative
		}
		return
	}
	if errors.Is(err, shl.ErrTooMuchContention) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, "", http.StatusNotFound)
}
```

Run the control-plane operations — revoke, pause, resume, extend — each a single manager call; revoke deletes the ciphertext and tombstones the sidecar so the next open `404`s.

```go
// cmd/shldemo/control.go
package main

import (
	"context"
	"time"

	"example.com/shl"
)

func lifecycleOps(ctx context.Context, mgr *shl.ShareManager, id string) error {
	if _, err := mgr.Pause(ctx, id); err != nil { // status → "paused"; reversible
		return err
	}
	if _, err := mgr.Resume(ctx, id); err != nil { // status → "active"
		return err
	}
	// Re-arm expiry (also un-expires an already-expired share if newExp > now).
	newExp := shl.EpochSeconds(time.Now().Add(30 * 24 * time.Hour).Unix())
	if _, err := mgr.Extend(ctx, id, newExp); err != nil {
		return err
	}
	// Terminal take-down: deletes ciphertext + marks "revoked". Idempotent.
	return mgr.Revoke(ctx, id)
}
```

Show how the STATIC profile differs: no `MaxUses`/passcode (they would throw `UnsupportedControlError`), the `url` is the short public-object URL so the link is fetched directly with zero compute, and revoke reduces to deleting the object.

```go
// cmd/shldemo/static.go
package main

import (
	"context"
	"fmt"

	"example.com/shl"
)

func staticShare(ctx context.Context) error {
	mgr, err := newManager(ctx, shl.ProfileStatic)
	if err != nil {
		return err
	}
	h, err := mgr.Create(ctx, shl.CreateShareInput{
		Content: `{"resourceType":"Bundle","type":"collection"}`,
		Label:   "Direct-file share",
		// Policy.MaxUses/Passcode here would fail fast with UnsupportedControlError.
		// Policy.Exp is honored only if the bucket supports lifecycle, else it throws.
	})
	if err != nil {
		return err
	}
	// STATIC payload carries flag "U"; url is the public object (≤128 chars),
	// so the viewer GETs the JWE straight from the bucket — no endpoint hop.
	fmt.Println("static link:", h.Link)
	fmt.Println("direct url: ", h.Payload.URL) // e.g. https://periodicity.fhir.me/shl/<id>.jwe

	// Revoke == delete the object; pause/resume/accessLog are unavailable here.
	return mgr.Revoke(ctx, h.ID) // store.Delete(ciphertextKey) under the hood
}
```

Relevant byte-compatibility anchors verified against `/home/jmandel/periodicity/scripts/gen-shl.ts` (payload field order `url,key,flag,label,v`; link form `${VIEWER_BASE}/#shlink:/…`; STATIC direct-file `flag:"U"`) and `/home/jmandel/periodicity/viewer-src/shl.mjs` (`?recipient=` GET returns `application/jose` body; manifest POST returns `files[0].embedded|location`; `DEFAULT_RECIPIENT = "Example User"`).

---

## Open questions

- STATIC direct-file rail vs. a blind object: the receiver always issues GET <url>?recipient=<name> (shl.mjs unconditionally appends the query param), but a raw S3/GCS/R2 object returns 404/SignatureDoesNotMatch when an unexpected query string is present unless it is part of a presigned signature. The PRD asserts STATIC serves the JWE 'directly with no compute' yet never explains how a plain object tolerates the mandatory ?recipient= query. This needs an explicit answer (object stores ignore unknown query params on unsigned public-read GETs — is that true for every listed backend, including B2/Azure?).
- Control-plane authentication is essentially unspecified. The doc references a 'control token' / KTC-style sha256(auth) in the glossary and security section, but ShareManager.create() returns no control token, the Express/FastAPI/Go handler examples mount only the data plane, and none of the control-plane methods (revoke/pause/setLimits/accessLog) take or check any authorization argument. Who is authorized to call these over HTTP, and how is the token minted, stored, and verified?
- Two-object atomicity on create and revoke is hand-waved. create() does put(ciphertext) then conditionalPut{if-absent}(sidecar); revoke() does delete(ciphertext) then CAS(sidecar='revoked'). What is the correct ordering and crash-recovery story so a partial create leaves no resolvable-but-untracked object and a partial revoke never leaves servable ciphertext with a 'revoked' sidecar (or vice versa)? The doc mentions best-effort orphan cleanup but no invariant ordering rule.
- MANAGED ciphertext access by the handler: if the bucket is private (as the profile table requires), how does the handler read the ciphertext to return it inline as manifest `embedded`? Presumably via store.get with server credentials — but for the `location` rail on a private bucket the receiver must fetch it, requiring a presign or HMAC ticket. The HMAC-ticket endpoint (/m/<id>/f/<fileId>?t=) is described but never wired in any of the three language handler examples (they only ever return `embedded`).
- Sidecar read cost and the GET-per-resolve under load: every MANAGED resolve does a full store.get of the sidecar plus a conditional put, and the retry loop re-reads on every 412. Under a hot link this is an unbounded read-modify-write contention point with MAX_RETRIES=8 then a 503. Is object-store CAS actually an acceptable substrate for a counter that may see concurrent opens, or should MANAGED counting default to the external-KV path? The doc presents KV as a fallback but the contention ceiling suggests it may need to be the recommended default.
- embeddedLengthMax semantics: the handler examples hardcode 50_000 / 64*1024 as the cap rather than honoring the receiver-supplied embeddedLengthMax from the POST body. The spec field is a receiver request; the PRD says 'honor embeddedLengthMax' but the examples ignore the body value. Which wins, and what is the default when the receiver omits it?
- Passcode + revoke-by-recreate interaction: setPasscode(id,null) is documented as unable to truly drop the immutable `P` flag from already-distributed links, with 'prefer revoke+recreate.' But recreate mints a new url/key/link, breaking every copy already shared. Is there any supported path to clear a passcode on a live link, or is the honest answer simply 'no'?

## Known gaps / inconsistencies to resolve

- `exp` byte-order over-claim. The PRD's emitPayload() inserts `exp` between `label` and `v` and claims this matches 'gen-shl.ts insertion order url,key,flag,label,exp?,v.' But gen-shl.ts emits exactly { url, key, flag, label, v } with NO exp field — there is no established precedent for where exp goes, so the 'byte-compatible / matches the minter exactly' claim is unverifiable and overstated. Any receiver round-trips fine (parseShlink is order-independent JSON.parse), but the 'identical to gen-shl' framing is wrong: the demo never serializes exp.
- ShareManager is declared as both a `class` and an `interface`. Section 2 defines `export class ShareManager { constructor(config) }`, but the 'Full operation set' block immediately below declares `export interface ShareManager { ... }` with the same name. These cannot coexist as written; the type model is inconsistent.
- resolve() vs resolve_manifest() inconsistency across examples. The canonical API in §2/§5 defines a single `resolve(id, recipient?, opts?)` returning ResolveResult {bundle,label,jwe} and says the handler chooses embedded/location. But the Python FastAPI example calls a separate `mgr.resolve_manifest(...)` that returns a ready-made {files:[...]} manifest, while the TS and Go examples build the manifest by hand from resolve().jwe. The manifest-construction responsibility (manager vs. handler) is specified two different ways.
- Manifest `embedded` trailing-newline / trim contract. shl.mjs does `String(file.embedded).trim()` and `(await r.text()).trim()` on every JWE body, so it tolerates surrounding whitespace — but the PRD never states the host must emit the JWE without a trailing newline, and the direct-file STATIC path serves a raw stored object whose bytes are whatever was put(). Round-trip is safe because the receiver trims, but the PRD's 'byte-for-byte round-trip' claim is slightly stronger than the code guarantees (the receiver normalizes, it does not require byte-exactness).
- Profile table vs. spec on STATIC `exp`. The 'Profiles at a glance' table lists STATIC expiry as 'presigned-TTL' as one degradation path, but every other section structurally BANS presigned URLs from the `url` field and says STATIC `url` is a short public-object URL with no TTL. A public-object STATIC url therefore has no presigned-TTL expiry available at all; the table's 'presigned-TTL' option for STATIC contradicts the public-object-only rule used everywhere else.
- Capability flags vs. matrix for GCS-via-S3. The capabilities struct comment says supportsConditionalWrite is 'False on B2/Wasabi/GCS-via-S3,' and the fallback section repeats this. Correct — but the 'Exact operations exposed' / library matrix lists `@aws-sdk/client-s3 ... GCS-XML` under conditionalPut if-match as 'GCS: native ifGenerationMatch', implying the S3 SDK path does CAS on GCS, which the research section explicitly says is impossible (S3/XML ETag preconditions are read-only on GCS). The two tables disagree on whether the S3 code path can CAS against GCS.
- UnsupportedControlError typing claim. §2 says the honesty rule is 'enforced at the type-adjacent runtime layer' and STATIC calls 'throw UnsupportedControlError rather than silently no-op,' but the same surface is presented as a single shared TS interface with no STATIC/MANAGED type distinction — so the guarantee is purely runtime, not type-level. The phrase 'type-adjacent' papers over the fact that nothing in the type system prevents calling setLimits on a STATIC manager; this should be stated plainly as a runtime-only check.
- deflateDefault wording vs. JWE default. The PRD repeatedly says the adapter defaults deflate to false 'matching the project guidance,' while correctly noting encryptCompact defaults deflate to TRUE. This is an intentional override, not a match — but the create() prose in 'Per-operation semantics' says deflate 'defaults to config.deflateDefault, i.e. false for unknown viewers' without restating that this DIVERGES from the underlying jwe.mjs default, so a reader wiring encryptCompact directly (not through the manager) would silently get DEFLATE on. Worth an explicit warning.

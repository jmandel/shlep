/**
 * llms.ts — renders the `/llms.txt` an agent fetches from a running shlep
 * instance. It ties the general API documentation together with THIS instance's
 * live configuration (its base URL, whether creating shares is open or gated, and
 * whether the backend supports use-limits). Also usable from a script to emit a
 * static file (scripts/gen-llms.ts).
 */

const SOURCE_URL = "https://github.com/jmandel/shlep";
const SPEC_URL = "https://github.com/jmandel/shlep/blob/main/docs/api-design.md";
const RAW_SPEC_URL = "https://raw.githubusercontent.com/jmandel/shlep/main/docs/api-design.md";
const EXAMPLE_VIEWER = "https://viewer.example.org/";

export interface ServiceInfo {
  /** This instance's public base URL, e.g. https://shl.example.com */
  baseUrl: string;
  /** True if POST /shares requires an operator-issued bearer token (closed); false = open. */
  createRequiresToken: boolean;
  /** True if the backend supports compare-and-swap (so `maxUses` is available). */
  useLimitsSupported: boolean;
}

export function renderLlmsTxt(info: ServiceInfo): string {
  const b = info.baseUrl.replace(/\/+$/, "");
  const createAccess = info.createRequiresToken
    ? "**gated** — creating a share requires an operator-issued bearer token (`Authorization: Bearer <CREATE_TOKEN>`). The operator gives you this token out-of-band."
    : "**open** — anyone can create a share (no token required to `POST /shares`).";
  const createAuthHeader = info.createRequiresToken ? ` \\\n    -H "Authorization: Bearer $CREATE_TOKEN"` : "";
  const useLimits = info.useLimitsSupported
    ? "available (`policy.maxUses`) — this backend supports atomic counting."
    : "**unavailable** on this instance's backend (no conditional writes); `maxUses` is refused. Expiry, passcode, pause, and revoke still work.";

  return `# shlep — SMART Health Link service

> shlep hosts encrypted **SMART Health Links** (SHLinks) in a cloud object store and
> makes them revocable. It is a **blind host**: clients encrypt; this server only ever
> stores ciphertext and never sees your content key or plaintext. This file tells you
> how to integrate with **this specific instance**.

## This instance

- **Base URL:** ${b}
- **Create access:** ${createAccess}
- **Use-limits:** ${useLimits}
- **Source code:** ${SOURCE_URL}
- **Full design spec:** ${SPEC_URL} (raw: ${RAW_SPEC_URL})

## Mental model (read this first)

1. **You encrypt on the client.** Turn your FHIR Bundle (or any UTF-8) into a compact
   JWE: \`alg:"dir"\`, \`enc:"A256GCM"\`, \`cty:"application/fhir+json"\`.
   **Nonce/IV rule:** generate a **random 96-bit IV from a CSPRNG** for *every* encryption,
   with a hard limit of ~2³² messages per key, then rotate keys. shlep creates a
   **fresh 32-byte key per share** and still generates a fresh IV for every file
   encryption or update under that share key. (Optional \`zip:"DEF"\`, but prefer
   uncompressed for unknown viewers.) You can use our reference implementation
   directly or translate it: \`src/crypto.ts\` (compact JWE) and \`src/client.ts\` (encrypt +
   link helpers) at ${SOURCE_URL}.
2. **You upload only the ciphertext.** The key NEVER touches this server.
3. **The server returns a one-time \`manageToken\`** — your capability to revoke/manage the
   share. It governs settings only; it cannot decrypt anything. Store it; it is shown once.
4. **You build the link** with your key in the fragment:
   \`<viewer>/#shlink:/<base64url(JSON)>\` where JSON = \`{ "url": "<fileUrl>", "key": "<yourKeyB64url>", "flag": "U", "label": "optional", "exp": optionalEpochSeconds, "v": 1 }\`.
   The \`#fragment\` (with the key) never reaches any server. Any SHL-compatible viewer works
   (e.g. ${EXAMPLE_VIEWER}); the viewer is your choice, not this server's.
5. **A recipient opens the link.** Their viewer fetches the ciphertext from this server and
   decrypts it locally with the key from the fragment.

## What goes where

- **SHLink \`url\`:** the short receiver-facing endpoint, usually \`${b}/shl/<id>\`. It
  identifies the encrypted share but contains no key material.
- **SHLink \`key\`:** a 43-character base64url AES-256 key. It lives in the URL fragment
  after \`#shlink:/\`, so browsers do not send it to this server.
- **SHLink \`label\`:** optional display text for the viewer. It also lives only in the
  fragment; the server never receives or stores it.
- **\`manageToken\`:** the creator's capability token for revoke, pause/resume, file changes,
  expiry, limits, passcode, and logs. It is returned once by \`POST /shares\`; never put it
  in the recipient's SHLink.
- **\`recipient\`:** the viewer/recipient name sent on every resolve. It is required by SHL,
  consumed by this service, and logged only when \`audit: true\`.
- **\`passcode\`:** an optional access gate for the manifest rail. It is not a decryption key,
  is not placed in the SHLink, and is never compatible with the \`U\` direct-file rail.

Minimal SHLink fragment payload:

\`\`\`json
{
  "url": "${b}/shl/<id>",
  "key": "<43-char base64url AES-256 key>",
  "flag": "U",
  "label": "optional viewer text",
  "exp": 1735689600,
  "v": 1
}
\`\`\`

\`url\` and \`key\` are required. \`v\` should be \`1\`. \`label\`, \`exp\`, and \`flag\`
are optional. Valid flags are \`L\`, \`P\`, and \`U\`; shlep canonicalizes them in \`LPU\`
order and rejects unknown flags. \`U\` means direct GET. \`P\` means passcode-required
manifest POST. \`L\` marks long-term/evolving content for viewers that understand re-polling.
\`U\` and \`P\` are mutually exclusive.

## API

All ids are server-minted (256-bit random). Labels are **not** sent to the server — they
live only in the link fragment.

A share holds **one or more files**. Recipients read via the manifest (any count) or, when
the share has **exactly one file**, the single-GET shortcut (the SHL \`U\` flag). A \`U\` link
is your assertion of one file; if the share ever has 0 or 2+ files, only that GET shortcut
404s — the manifest still works.

For the common one-file, non-passcoded share, prefer the **\`U\` direct-file rail**: it is the
simplest receiver experience, returns the JWE directly, and works with clients that only
implement the direct SHL fetch. Use the manifest rail when you need multi-file shares,
passcode protection, explicit content types per file, or \`embeddedLengthMax\` handling with
short-lived \`location\` tickets.

### Data plane (public; CORS \`*\`)

\`\`\`
GET  ${b}/shl/:id?recipient=<name>     -> 200 application/jose   (single-file shares only)
POST ${b}/shl/:id                       -> 200 application/json   (a manifest of all files)
       body: { "recipient": "<name>", "passcode"?: "...", "embeddedLengthMax"?: 16384 }
       returns: { "files": [ { "contentType": "application/fhir+json", "embedded" | "location": ... } ] }
GET  ${b}/shl/:id/f/:fileId?t=<ticket>  -> 200 application/jose   (manifest "location" target)
\`\`\`

\`recipient\` is required by the SHL spec; this server consumes it (never forwards it to
storage) and logs it only if the share enabled \`audit\`. Any non-servable link — missing,
revoked, expired, exhausted, or paused — returns a **uniform 404** so existence never leaks.

Manifest response examples:

\`\`\`json
{ "files": [ { "contentType": "application/fhir+json", "embedded": "<COMPACT_JWE>" } ] }
\`\`\`

\`\`\`json
{ "files": [ { "contentType": "application/fhir+json", "location": "${b}/shl/<id>/f/<fileId>?t=<ticket>" } ] }
\`\`\`

\`embedded\` is the compact JWE inline. \`location\` is a short-lived URL minted by this
service for a specific file; receivers fetch it with GET and then decrypt the returned JWE
with the same fragment key. Do not construct or accept arbitrary caller-supplied locations.

### Control plane (\`Authorization: Bearer <manageToken>\`; wrong/missing token -> 404)

\`\`\`
POST   ${b}/shares                       create  -> { id, status, fileUrl, fileIds, manageToken }
GET    ${b}/shares/:id                   current state (ShareView, incl. files[])
DELETE ${b}/shares/:id                   revoke (stops serving + deletes ciphertext)
POST   ${b}/shares/:id/files             add a file     body: { "ciphertext": "<JWE>" } -> { fileId, view }
PUT    ${b}/shares/:id/files/:fileId     replace a file body: { "ciphertext": "<JWE>" }
DELETE ${b}/shares/:id/files/:fileId     delete a file
POST   ${b}/shares/:id/pause             pause
POST   ${b}/shares/:id/resume            resume
POST   ${b}/shares/:id/extend            body: { "exp": <epochSeconds> }
POST   ${b}/shares/:id/limits            body: { "maxUses": <n> }
POST   ${b}/shares/:id/passcode          set/change/clear  body: { "passcode": "..." | null }
GET    ${b}/shares/:id/log               recipient access log (entries exist only if audit)
\`\`\`

\`POST /shares\` body: \`{ "ciphertext": "<JWE>" }\` (one file) or \`{ "files": ["<JWE>", ...] }\`,
plus optional \`"policy"\`. \`policy = { exp?: epochSeconds, maxUses?: number, passcode?: string,
audit?: boolean }\`. Updates keep the same key/link (re-encrypt with a fresh IV). There is
**no list-all/admin endpoint** — the service is account-less and never enumerates shares.

Create request shapes:

\`\`\`json
{ "ciphertext": "<COMPACT_JWE>", "contentType": "application/fhir+json" }
\`\`\`

\`\`\`json
{
  "files": [
    { "ciphertext": "<FHIR_BUNDLE_JWE>", "contentType": "application/fhir+json" },
    { "ciphertext": "<SMART_CARD_JWE>", "contentType": "application/smart-health-card" }
  ],
  "policy": { "exp": 1735689600, "maxUses": 5, "passcode": "1234", "audit": true }
}
\`\`\`

The response includes \`fileUrl\` for the SHLink \`url\`, \`fileIds\` for later file
operations, and \`manageToken\` for control-plane calls. Save \`manageToken\` immediately;
the service stores only its hash.

## Quickstart

This instance's create access is ${info.createRequiresToken ? "gated (token required)" : "open"}.

\`\`\`bash
# 1) Encrypt client-side (pseudocode): JWE = A256GCM(dir, KEY, bundle); keep KEY yourself.

# 2) Create the share (upload ciphertext only):
curl -sS -X POST ${b}/shares${createAuthHeader} \\
    -H "content-type: application/json" \\
    -d '{ "ciphertext": "<COMPACT_JWE>", "policy": { "maxUses": 5${info.useLimitsSupported ? "" : " /* refused on this backend */"}, "audit": true } }'
# -> { "id": "...", "status": "active", "fileUrl": "${b}/shl/<id>", "manageToken": "<SAVE THIS>" }

# 3) Build the shareable link (your KEY goes in the fragment, base64url):
#    ${EXAMPLE_VIEWER}#shlink:/<base64url({"url":"${b}/shl/<id>","key":"<KEY_B64URL>","flag":"U","v":1})>

# 4) A recipient's viewer fetches + decrypts:
curl -sS "${b}/shl/<id>?recipient=Dr%20Smith"      # -> the JWE; decrypt locally with KEY

# 5) Revoke whenever you want (needs the manageToken; it cannot decrypt):
curl -sS -X DELETE ${b}/shares/<id> -H "Authorization: Bearer <manageToken>"
\`\`\`

## Guarantees & rules (SHL conformance)

- **Blind host:** stores ciphertext + \`sha256(manageToken)\` + minimal enforcement metadata
  (status, exp, maxUses/useCount, per-file length + contentType, salted-PBKDF2 passcode hash
  + failure count). Never the key, plaintext, or label.
- **\`recipient\` is required** on every resolve (GET query or manifest POST body).
- **File contentType** describes the *decrypted* payload — \`application/fhir+json\` (default),
  \`application/smart-health-card\`, or \`application/smart-api-access\`. Pass it per file at create
  (\`contentType\`) / add-file; it is echoed in the manifest, not \`application/jose\`.
- **U is incompatible with passcode.** A passcoded share is served by the **manifest only**;
  the GET (U) rail 404s for it. Don't mint a \`U\` link for a passcoded or multi-file share.
- **Passcode brute-force budget:** consecutive wrong passcodes count down (default 5, reset on a
  correct one — a documented product choice vs. the SHL spec's literal "lifetime count"); the 401
  body is \`{remainingAttempts}\`. Once spent, the link is **disabled** and serves nothing on any
  rail (including outstanding manifest tickets), returning a uniform 404.
- **One-time token:** \`manageToken\` is returned once at create and never again.
- **Unique nonce + entropy:** every encryption uses a fresh random IV with a fresh key per
  share; share ids carry 256 bits of entropy and the \`url\` stays ≤128 chars.
- **404 everything unservable:** revoked/expired/exhausted/paused/disabled links and wrong
  tokens all return 404 — do not treat 404 as "never existed."

## More

- Source, issues, and the reference client/server implementation: ${SOURCE_URL}
- Reference client crypto to adopt or translate: \`src/crypto.ts\` + \`src/client.ts\`
- Authoritative design & threat model: ${SPEC_URL}
`;
}

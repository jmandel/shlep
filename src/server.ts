/**
 * server.ts — a framework-agnostic `fetch` handler (Web Request -> Response) that
 * exposes the SHL data plane and the capability-token control plane. The handler,
 * the ShareManager, crypto/passcode, and the in-memory store use only Web-standard
 * APIs (WebCrypto, streams, fetch), so they run under Bun.serve, Deno, and
 * Cloudflare Workers as well as Node. (The bundled S3/GCS/Azure adapters target
 * Node/Bun; on Workers, use an R2 binding or a Workers-native store.)
 *
 *   DATA PLANE (public, CORS-enabled — browsers fetch these):
 *     GET  /shl/:id?recipient=        direct-file rail -> application/jose
 *     POST /shl/:id   {recipient,...}  manifest rail   -> application/json
 *     GET  /shl/:id/f/:fileId?t=       ticketed file   -> application/jose
 *
 *   CONTROL PLANE (Authorization: Bearer <manageToken>; wrong token -> 404):
 *     POST   /shares                      create -> {id,status,fileUrl,fileIds,manageToken}
 *     GET    /shares/:id                  state (ShareView, incl. files[])
 *     DELETE /shares/:id                  revoke
 *     POST   /shares/:id/files {ciphertext}        add a file -> {fileId,view}
 *     PUT    /shares/:id/files/:fileId {ciphertext} replace a file
 *     DELETE /shares/:id/files/:fileId             delete a file
 *     POST   /shares/:id/pause|resume
 *     POST   /shares/:id/extend   {exp}
 *     POST   /shares/:id/limits   {maxUses}
 *     POST   /shares/:id/passcode {passcode?}      set / change / clear
 *     GET    /shares/:id/log
 *
 *   SELF-DOC (public): GET / and GET /llms.txt — an integration guide tailored to
 *   this instance's config (open vs. token-gated create, CAS-capable backend).
 *
 * `recipient` from the data plane is consumed here (logged) and NEVER forwarded
 * to storage. The control plane is auth'd per-share by the capability token.
 */
import { renderLlmsTxt } from "./llms";
import type { ShareManager } from "./share-manager";
import { Errors, ShlError } from "./types";

export interface ServerOptions {
  /** If set, `POST /shares` requires this bearer token (otherwise create is open). */
  createToken?: string;
  /** Max request body bytes, buffered before parsing (DoS guard). Default 16 MiB. */
  maxBodyBytes?: number;
}

// Browser clients use both the data plane and the control plane (the README
// shows cross-origin fetch DELETE /shares/:id with a bearer), so CORS allows the
// control-plane methods/header too. The bearer is an explicit fetch header (not a
// cookie credential), so `*` origin is fine.
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
  "access-control-allow-headers": "content-type, authorization",
  "access-control-max-age": "86400",
};
const NOSTORE = { "cache-control": "no-store" };

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...CORS, ...extra } });

const jose = (jwe: string) =>
  new Response(jwe, { status: 200, headers: { "content-type": "application/jose", ...NOSTORE, ...CORS } });

const errResponse = (e: unknown, dataPlane = false) => {
  const h = dataPlane ? NOSTORE : {};
  if (e instanceof ShlError) return json({ error: e.code, message: e.message, ...(e.body ?? {}) }, e.httpStatus, h);
  return json({ error: "internal", message: "internal error" }, 500, h);
};

const bearer = (req: Request): string | null => {
  const m = (req.headers.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  return m?.[1] ?? null;
};

const isEpoch = (v: unknown) => typeof v === "number" && Number.isFinite(v);
const isCount = (v: unknown) => typeof v === "number" && Number.isInteger(v) && v >= 1;

/** Validate an untrusted policy object; returns an error message or null. */
function badPolicy(policy: any): string | null {
  if (policy == null) return null;
  if (typeof policy !== "object") return "policy must be an object";
  if (policy.exp !== undefined && !isEpoch(policy.exp)) return "policy.exp must be epoch seconds (number)";
  if (policy.maxUses !== undefined && !isCount(policy.maxUses)) return "policy.maxUses must be a positive integer";
  if (policy.passcode !== undefined && typeof policy.passcode !== "string") return "policy.passcode must be a string";
  if (policy.audit !== undefined && typeof policy.audit !== "boolean") return "policy.audit must be a boolean";
  return null;
}

export function createFetchHandler(mgr: ShareManager, opts: ServerOptions = {}) {
  const maxBody = opts.maxBodyBytes ?? 16 * 1024 * 1024;
  const readJson = (req: Request) => readJsonBounded(req, maxBody);
  return async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const seg = url.pathname.split("/").filter(Boolean); // e.g. ["shl","abc"]
    const method = req.method.toUpperCase();

    if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    // ---- self-documentation (public) ----
    if (method === "GET" && (seg.length === 0 || (seg.length === 1 && seg[0] === "llms.txt"))) {
      const info = {
        baseUrl: mgr.serviceBaseUrl,
        createRequiresToken: !!opts.createToken,
        useLimitsSupported: mgr.useLimitsSupported,
      };
      const body = seg.length === 0
        ? `shlep — SMART Health Link service\n\nIntegration guide for agents and clients: ${mgr.serviceBaseUrl}/llms.txt\nSource: https://github.com/jmandel/shlep\n`
        : renderLlmsTxt(info);
      return new Response(body, { headers: { "content-type": "text/plain; charset=utf-8", ...CORS } });
    }

    try {
      // ---- data plane ----
      if (seg[0] === "shl" && seg.length === 2) {
        const id = seg[1]!;
        if (method === "GET") {
          const recipient = url.searchParams.get("recipient");
          if (!recipient) return json({ error: "bad_request", message: "recipient query parameter is required" }, 400, NOSTORE);
          const r = await mgr.resolveDirect(id, { recipient });
          return jose(r.jwe);
        }
        if (method === "POST") {
          const body = await readJson(req);
          if (typeof body.recipient !== "string" || body.recipient.length === 0) {
            return json({ error: "bad_request", message: "recipient is required" }, 400, NOSTORE);
          }
          const manifest = await mgr.resolveManifest(id, {
            recipient: body.recipient,
            passcode: body.passcode,
            embeddedLengthMax: body.embeddedLengthMax,
          });
          return json(manifest, 200, NOSTORE);
        }
      }
      if (seg[0] === "shl" && seg.length === 4 && seg[2] === "f" && method === "GET") {
        const r = await mgr.resolveFileTicket(seg[1]!, seg[3]!, url.searchParams.get("t") ?? "");
        return jose(r.jwe);
      }

      // ---- control plane ----
      if (seg[0] === "shares") {
        if (seg.length === 1 && method === "POST") {
          if (opts.createToken && bearer(req) !== opts.createToken) return json({ error: "unauthorized" }, 401);
          const body = await readJson(req);
          const hasOne = typeof body.ciphertext === "string";
          const hasMany = Array.isArray(body.files) && body.files.length > 0 && body.files.every((f: unknown) => typeof f === "string" || (f && typeof (f as any).ciphertext === "string"));
          if (!hasOne && !hasMany) return json({ error: "bad_request", message: "ciphertext or files[] (compact JWE strings, optionally {ciphertext,contentType}) required" }, 400);
          const pErr = badPolicy(body.policy);
          if (pErr) return json({ error: "bad_request", message: pErr }, 400);
          const res = await mgr.create({ ciphertext: body.ciphertext, contentType: body.contentType, files: body.files, policy: body.policy });
          return json(res, 201);
        }
        const id = seg[1]!;
        const token = bearer(req) ?? "";
        if (seg.length === 2 && method === "GET") return json(await mgr.get(id, token));
        if (seg.length === 2 && method === "DELETE") return json(await mgr.revoke(id, token));

        // file operations
        if (seg.length === 3 && seg[2] === "files" && method === "POST") {
          const b = await readJson(req);
          if (typeof b.ciphertext !== "string") return json({ error: "bad_request", message: "ciphertext (compact JWE string) required" }, 400);
          return json(await mgr.addFile(id, token, b.ciphertext, b.contentType), 201);
        }
        if (seg.length === 4 && seg[2] === "files" && method === "PUT") {
          const b = await readJson(req);
          if (typeof b.ciphertext !== "string") return json({ error: "bad_request", message: "ciphertext (compact JWE string) required" }, 400);
          return json(await mgr.replaceFile(id, token, seg[3]!, b.ciphertext, b.contentType));
        }
        if (seg.length === 4 && seg[2] === "files" && method === "DELETE") {
          return json(await mgr.deleteFile(id, token, seg[3]!));
        }

        // settings
        if (seg.length === 3 && method === "POST") {
          if (seg[2] === "pause") return json(await mgr.pause(id, token));
          if (seg[2] === "resume") return json(await mgr.resume(id, token));
          if (seg[2] === "extend") {
            const exp = (await readJson(req)).exp;
            if (exp !== undefined && exp !== null && !isEpoch(exp)) return json({ error: "bad_request", message: "exp must be epoch seconds (number) or null" }, 400);
            return json(await mgr.extend(id, token, exp ?? undefined));
          }
          if (seg[2] === "limits") {
            const maxUses = (await readJson(req)).maxUses;
            if (maxUses !== undefined && maxUses !== null && !isCount(maxUses)) return json({ error: "bad_request", message: "maxUses must be a positive integer or null" }, 400);
            return json(await mgr.setLimits(id, token, maxUses ?? undefined));
          }
          if (seg[2] === "passcode") {
            const pc = (await readJson(req)).passcode;
            if (pc !== undefined && pc !== null && typeof pc !== "string") return json({ error: "bad_request", message: "passcode must be a string or null" }, 400);
            return json(await mgr.setPasscode(id, token, pc ?? undefined));
          }
        }
        if (seg.length === 3 && seg[2] === "log" && method === "GET") return json(await mgr.accessLog(id, token));
      }

      return json({ error: "not_found" }, 404);
    } catch (e) {
      return errResponse(e, seg[0] === "shl"); // data-plane errors are no-store
    }
  };
}

/** Read + parse a JSON body, capping bytes BEFORE buffering the whole thing (DoS guard). */
async function readJsonBounded(req: Request, maxBytes: number): Promise<any> {
  const cl = req.headers.get("content-length");
  if (cl && Number(cl) > maxBytes) throw Errors.tooLarge("request body too large");
  const reader = req.body?.getReader();
  if (!reader) return {};
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw Errors.tooLarge("request body too large");
    }
    chunks.push(value);
  }
  if (total === 0) return {};
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.length;
  }
  try {
    return JSON.parse(new TextDecoder().decode(buf));
  } catch {
    return {};
  }
}

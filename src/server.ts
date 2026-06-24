/**
 * server.ts — a framework-agnostic `fetch` handler (Web Request -> Response) that
 * exposes the SHL data plane and the capability-token control plane. Works under
 * Bun.serve, Cloudflare Workers, Deno, or any Web-standard runtime.
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
import { ShlError } from "./types";

export interface ServerOptions {
  /** If set, `POST /shares` requires this bearer token (otherwise create is open). */
  createToken?: string;
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400",
};

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...extra } });

const jose = (jwe: string) =>
  new Response(jwe, { status: 200, headers: { "content-type": "application/jose", "cache-control": "no-store", ...CORS } });

const errResponse = (e: unknown, cors = false) => {
  const h = cors ? CORS : {};
  if (e instanceof ShlError) return json({ error: e.code, message: e.message }, e.httpStatus, h);
  return json({ error: "internal", message: "internal error" }, 500, h);
};

const bearer = (req: Request): string | null => {
  const m = (req.headers.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
};

export function createFetchHandler(mgr: ShareManager, opts: ServerOptions = {}) {
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
        const id = seg[1];
        if (method === "GET") {
          const r = await mgr.resolveDirect(id, { recipient: url.searchParams.get("recipient") ?? undefined });
          return jose(r.jwe);
        }
        if (method === "POST") {
          const body = await readJson(req);
          const manifest = await mgr.resolveManifest(id, {
            recipient: body.recipient,
            passcode: body.passcode,
            embeddedLengthMax: body.embeddedLengthMax,
          });
          return json(manifest, 200, CORS);
        }
      }
      if (seg[0] === "shl" && seg.length === 4 && seg[2] === "f" && method === "GET") {
        const r = await mgr.resolveFileTicket(seg[1], seg[3], url.searchParams.get("t") ?? "");
        return jose(r.jwe);
      }

      // ---- control plane ----
      if (seg[0] === "shares") {
        if (seg.length === 1 && method === "POST") {
          if (opts.createToken && bearer(req) !== opts.createToken) return json({ error: "unauthorized" }, 401);
          const body = await readJson(req);
          const hasOne = typeof body.ciphertext === "string";
          const hasMany = Array.isArray(body.files) && body.files.length > 0;
          if (!hasOne && !hasMany) return json({ error: "bad_request", message: "ciphertext or files[] (compact JWE strings) required" }, 400);
          const res = await mgr.create({ ciphertext: body.ciphertext, files: body.files, policy: body.policy });
          return json(res, 201);
        }
        const id = seg[1];
        const token = bearer(req) ?? "";
        if (seg.length === 2 && method === "GET") return json(await mgr.get(id, token));
        if (seg.length === 2 && method === "DELETE") return json(await mgr.revoke(id, token));

        // file operations
        if (seg.length === 3 && seg[2] === "files" && method === "POST") {
          const ct = (await readJson(req)).ciphertext;
          if (typeof ct !== "string") return json({ error: "bad_request", message: "ciphertext (compact JWE string) required" }, 400);
          return json(await mgr.addFile(id, token, ct), 201);
        }
        if (seg.length === 4 && seg[2] === "files" && method === "PUT") {
          const ct = (await readJson(req)).ciphertext;
          if (typeof ct !== "string") return json({ error: "bad_request", message: "ciphertext (compact JWE string) required" }, 400);
          return json(await mgr.replaceFile(id, token, seg[3], ct));
        }
        if (seg.length === 4 && seg[2] === "files" && method === "DELETE") {
          return json(await mgr.deleteFile(id, token, seg[3]));
        }

        // settings
        if (seg.length === 3 && method === "POST") {
          if (seg[2] === "pause") return json(await mgr.pause(id, token));
          if (seg[2] === "resume") return json(await mgr.resume(id, token));
          if (seg[2] === "extend") return json(await mgr.extend(id, token, (await readJson(req)).exp));
          if (seg[2] === "limits") return json(await mgr.setLimits(id, token, (await readJson(req)).maxUses));
          if (seg[2] === "passcode") return json(await mgr.setPasscode(id, token, (await readJson(req)).passcode));
        }
        if (seg.length === 3 && seg[2] === "log" && method === "GET") return json(await mgr.accessLog(id, token));
      }

      return json({ error: "not_found" }, 404);
    } catch (e) {
      const cors = seg[0] === "shl"; // only the data plane needs CORS on errors
      return errResponse(e, cors);
    }
  };
}

async function readJson(req: Request): Promise<any> {
  try {
    return (await req.json()) ?? {};
  } catch {
    return {};
  }
}

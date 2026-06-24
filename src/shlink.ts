/**
 * shlink.ts — encode/decode the `shlink:/` payload and build viewer links.
 *
 * Field order mirrors the IG minter (scripts/gen-shl.ts): url, key, flag, label,
 * then v. We insert `exp` before `v` when present. NOTE: gen-shl.ts never emits
 * `exp`, so there is no established byte-precedent for its position — round-trip
 * is safe regardless because parsing is order-independent JSON.
 */
import { b64uFromBytes, bytesFromB64u } from "./crypto";
import type { ShlinkPayload } from "./types";

const enc = new TextEncoder();
const dec = new TextDecoder();

const FLAG_ORDER = ["L", "P", "U"] as const; // SHL-defined flags, canonical order

/** Validate + canonicalize SHL flags: subset of {L,P,U}, no dups, U and P exclusive, sorted. */
function normalizeFlag(flag: string): string {
  const set = new Set<string>();
  for (const c of flag) {
    if (!(FLAG_ORDER as readonly string[]).includes(c)) throw new Error(`invalid SHL flag "${c}" (allowed: L, P, U)`);
    set.add(c);
  }
  if (set.has("U") && set.has("P")) throw new Error("SHL flags U and P are mutually exclusive");
  return FLAG_ORDER.filter((c) => set.has(c)).join("");
}

export function encodeShlink(p: ShlinkPayload): string {
  if (p.label != null && p.label.length > 80) throw new Error("SHL label exceeds 80 characters");
  const obj: Record<string, unknown> = { url: p.url, key: p.key };
  if (p.flag) obj.flag = normalizeFlag(p.flag);
  if (p.label) obj.label = p.label;
  if (p.exp != null) obj.exp = p.exp;
  obj.v = p.v ?? 1;
  return "shlink:/" + b64uFromBytes(enc.encode(JSON.stringify(obj)));
}

/** Extract the shlink:/ URI from a bare link or a viewer-prefixed URL, then decode it. */
export function decodeShlink(input: string): ShlinkPayload {
  const i = input.indexOf("shlink:/");
  if (i < 0) throw new Error("no shlink:/ found");
  const b64 = input.slice(i + "shlink:/".length).trim();
  return JSON.parse(dec.decode(bytesFromB64u(b64))) as ShlinkPayload;
}

/** `${viewerPrefix}#shlink:/…` — the form that opens from any phone camera. */
export function viewerLink(viewerPrefix: string, shlink: string): string {
  return `${viewerPrefix.replace(/\/+$/, "")}/#${shlink}`;
}

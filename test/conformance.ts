/**
 * conformance.ts — the ObjectStore contract every adapter must satisfy. This is
 * the single source of truth for what the ShareManager relies on (especially CAS
 * semantics). Run it against any store:
 *
 *   objectStoreContract("memory", () => new MemoryObjectStore());
 *   objectStoreContract("s3",     () => new S3ObjectStore({ ... }));   // with live creds / an emulator
 *
 * The in-memory run executes in CI; the cloud adapters (S3/GCS/Azure) are written
 * to THIS contract and are meant to be run against a real bucket or an emulator
 * (MinIO / fake-gcs-server / Azurite) before trusting them in production.
 */
import { describe, expect, test } from "bun:test";
import type { ObjectStore } from "../src/object-store";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const rid = () => `t-${Math.floor(Math.random() * 1e9)}`;

export function objectStoreContract(name: string, makeStore: () => ObjectStore | Promise<ObjectStore>) {
  describe(`ObjectStore contract: ${name}`, () => {
    test("put / get / head / delete round-trip", async () => {
      const s = await makeStore();
      const k = `${rid()}/a.txt`;
      const p = await s.put(k, enc("hello"), { contentType: "text/plain" });
      expect(p.etag).toBeTruthy();
      const g = await s.get(k);
      expect(g).not.toBeNull();
      expect(dec(g!.bytes)).toBe("hello");
      expect(g!.etag).toBeTruthy();
      const h = await s.head(k);
      expect(h!.size).toBe(5);
      await s.delete(k);
      expect(await s.get(k)).toBeNull();
    });

    test("missing object -> null (get and head)", async () => {
      const s = await makeStore();
      expect(await s.get(`${rid()}/none`)).toBeNull();
      expect(await s.head(`${rid()}/none`)).toBeNull();
    });

    test("list by prefix", async () => {
      const s = await makeStore();
      const pfx = `${rid()}/`;
      await s.put(`${pfx}1`, enc("a"));
      await s.put(`${pfx}2`, enc("b"));
      await s.put(`${rid()}/x`, enc("c"));
      expect((await s.list(pfx)).sort()).toEqual([`${pfx}1`, `${pfx}2`]);
    });

    test("conditionalPut create-if-absent (expectedEtag === null)", async () => {
      const s = await makeStore();
      const k = `${rid()}/new`;
      expect(await s.conditionalPut(k, enc("x"), null)).not.toBeNull(); // created
      expect(await s.conditionalPut(k, enc("y"), null)).toBeNull(); // already exists
      expect(dec((await s.get(k))!.bytes)).toBe("x");
    });

    test("conditionalPut replace-if-unchanged (expectedEtag === current)", async () => {
      const s = await makeStore();
      const k = `${rid()}/v`;
      const created = await s.conditionalPut(k, enc("1"), null);
      const e1 = created!.etag;
      expect(await s.conditionalPut(k, enc("2"), e1)).not.toBeNull(); // matches -> replaced
      expect(await s.conditionalPut(k, enc("3"), e1)).toBeNull(); // stale etag -> refused
      expect(dec((await s.get(k))!.bytes)).toBe("2");
    });

    test("CAS serializes two writers holding the same base etag", async () => {
      const s = await makeStore();
      const k = `${rid()}/race`;
      await s.conditionalPut(k, enc("base"), null);
      const base = (await s.get(k))!.etag;
      const a = await s.conditionalPut(k, enc("A"), base);
      const b = await s.conditionalPut(k, enc("B"), base); // same (now stale) base
      expect([a, b].filter(Boolean).length).toBe(1); // exactly one wins
    });
  });
}

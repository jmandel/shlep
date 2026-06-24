import { describe, expect, test } from "bun:test";
import { encryptBundle, openSealed } from "../src/client";
import { MemoryObjectStore } from "../src/object-store";
import { createFetchHandler } from "../src/server";
import { ShareManager } from "../src/share-manager";

const BUNDLE = JSON.stringify({ resourceType: "Bundle", type: "collection" });

function handler() {
  const mgr = new ShareManager({ store: new MemoryObjectStore(), baseUrl: "http://t" });
  return createFetchHandler(mgr);
}

describe("http", () => {
  test("create -> direct-file GET -> decrypt; CORS present", async () => {
    const h = handler();
    const sealed = await encryptBundle(BUNDLE);

    const created = await h(
      new Request("http://t/shares", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ciphertext: sealed.jwe }),
      }),
    );
    expect(created.status).toBe(201);
    const { id, manageToken, fileUrl } = await created.json();
    expect(fileUrl).toBe(`http://t/shl/${id}`);

    const got = await h(new Request(`http://t/shl/${id}?recipient=Dr+Who`));
    expect(got.status).toBe(200);
    expect(got.headers.get("content-type")).toBe("application/jose");
    expect(got.headers.get("access-control-allow-origin")).toBe("*");
    expect(got.headers.get("cache-control")).toBe("no-store");
    expect(await openSealed(await got.text(), sealed.key)).toBe(BUNDLE);

    // recipient is required (SHL)
    expect((await h(new Request(`http://t/shl/${id}`))).status).toBe(400);

    // manifest rail -> no-store
    const man = await h(
      new Request(`http://t/shl/${id}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ recipient: "r" }),
      }),
    );
    expect(man.headers.get("cache-control")).toBe("no-store");
    const manifest = await man.json();
    expect(await openSealed(manifest.files[0].embedded, sealed.key)).toBe(BUNDLE);

    // revoke with manage token -> then 404
    const del = await h(new Request(`http://t/shares/${id}`, { method: "DELETE", headers: { authorization: `Bearer ${manageToken}` } }));
    expect(del.status).toBe(200);
    expect((await h(new Request(`http://t/shl/${id}?recipient=x`))).status).toBe(404);
  });

  test("oversized request body -> 413 (capped before buffering)", async () => {
    const mgr = new ShareManager({ store: new MemoryObjectStore(), baseUrl: "http://t" });
    const h = createFetchHandler(mgr, { maxBodyBytes: 64 });
    const r = await h(
      new Request("http://t/shares", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ciphertext: "x".repeat(500) }) }),
    );
    expect(r.status).toBe(413);
  });

  test("CORS preflight covers control-plane methods + Authorization", async () => {
    const h = handler();
    const pre = await h(new Request("http://t/shares/x", { method: "OPTIONS" }));
    expect(pre.status).toBe(204);
    expect(pre.headers.get("access-control-allow-methods")).toContain("DELETE");
    expect(pre.headers.get("access-control-allow-methods")).toContain("PUT");
    expect(pre.headers.get("access-control-allow-headers")).toContain("authorization");
  });

  test("GET /llms.txt reflects this instance (open vs gated create, base URL)", async () => {
    const open = createFetchHandler(new ShareManager({ store: new MemoryObjectStore(), baseUrl: "https://open.example" }));
    const r1 = await open(new Request("https://open.example/llms.txt"));
    expect(r1.status).toBe(200);
    expect(r1.headers.get("content-type")).toContain("text/plain");
    const t1 = await r1.text();
    expect(t1).toContain("https://open.example/shl/:id");
    expect(t1).toContain("**open**");
    expect(t1).toContain("https://github.com/jmandel/shlep");
    expect(t1).toContain("2³² messages per key"); // the nonce guidance

    const gated = createFetchHandler(new ShareManager({ store: new MemoryObjectStore(), baseUrl: "https://g.example" }), {
      createToken: "secret",
    });
    const t2 = await (await gated(new Request("https://g.example/llms.txt"))).text();
    expect(t2).toContain("gated");
    expect(t2).toContain("CREATE_TOKEN");
  });

  test("wrong manage token -> 404 (existence hidden)", async () => {
    const h = handler();
    const created = await h(
      new Request("http://t/shares", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ciphertext: (await encryptBundle(BUNDLE)).jwe }),
      }),
    );
    const { id } = await created.json();
    const del = await h(new Request(`http://t/shares/${id}`, { method: "DELETE", headers: { authorization: "Bearer nope" } }));
    expect(del.status).toBe(404);
  });
});

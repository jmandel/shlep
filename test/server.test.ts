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
        body: JSON.stringify({ ciphertext: sealed.jwe, policy: { label: "x" } }),
      }),
    );
    expect(created.status).toBe(201);
    const { id, manageToken, fileUrl } = await created.json();
    expect(fileUrl).toBe(`http://t/shl/${id}`);

    const got = await h(new Request(`http://t/shl/${id}?recipient=Dr+Who`));
    expect(got.status).toBe(200);
    expect(got.headers.get("content-type")).toBe("application/jose");
    expect(got.headers.get("access-control-allow-origin")).toBe("*");
    expect(await openSealed(await got.text(), sealed.key)).toBe(BUNDLE);

    // manifest rail
    const man = await h(
      new Request(`http://t/shl/${id}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ recipient: "r" }),
      }),
    );
    const manifest = await man.json();
    expect(await openSealed(manifest.files[0].embedded, sealed.key)).toBe(BUNDLE);

    // revoke with manage token -> then 404
    const del = await h(new Request(`http://t/shares/${id}`, { method: "DELETE", headers: { authorization: `Bearer ${manageToken}` } }));
    expect(del.status).toBe(200);
    expect((await h(new Request(`http://t/shl/${id}`))).status).toBe(404);
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

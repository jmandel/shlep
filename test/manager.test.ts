import { describe, expect, test } from "bun:test";
import { composeShlink, encryptBundle, openSealed } from "../src/client";
import { MemoryObjectStore } from "../src/object-store";
import { ShareManager } from "../src/share-manager";
import { decodeShlink } from "../src/shlink";
import { ShlError } from "../src/types";

const BUNDLE = JSON.stringify({ resourceType: "Bundle", type: "collection", id: "demo" });

function mk(overrides: Partial<ConstructorParameters<typeof ShareManager>[0]> = {}) {
  const store = new MemoryObjectStore();
  const mgr = new ShareManager({ store, baseUrl: "https://shl.example.com", ...overrides });
  return { store, mgr };
}

async function catchErr(p: Promise<unknown>): Promise<ShlError> {
  try {
    await p;
    throw new Error("expected rejection");
  } catch (e) {
    if (e instanceof ShlError) return e;
    throw e;
  }
}

describe("blind round-trip (mediated)", () => {
  test("the manager only ever sees ciphertext; receiver decrypts with the fragment key", async () => {
    const { mgr } = mk();
    const sealed = await encryptBundle(BUNDLE); // key born client-side
    const res = await mgr.create({ mode: "mediated", ciphertext: sealed.jwe, policy: { label: "demo" } });

    expect(res.mode).toBe("mediated");
    expect(res.fileUrl).toBe(`https://shl.example.com/shl/${res.id}`);
    expect(res.manageToken).toBeTruthy();

    const r = await mgr.resolveDirect(res.id, { recipient: "Dr. Smith" });
    expect(r.contentType).toBe("application/jose");
    const plain = await openSealed(r.jwe, sealed.key);
    expect(plain).toBe(BUNDLE);
  });

  test("shlink composes from fileUrl + client key and round-trips", async () => {
    const { mgr } = mk();
    const sealed = await encryptBundle(BUNDLE);
    const res = await mgr.create({ ciphertext: sealed.jwe });
    const shlink = composeShlink(res.fileUrl, sealed.keyB64, { label: "x" });
    const payload = decodeShlink(`https://viewer.example/#${shlink}`);
    expect(payload.url).toBe(res.fileUrl);
    expect(payload.key).toBe(sealed.keyB64);
    expect(payload.flag).toBe("U");
  });
});

describe("capability token", () => {
  test("wrong manage token is indistinguishable from missing (404)", async () => {
    const { mgr } = mk();
    const res = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe });
    const e = await catchErr(mgr.revoke(res.id, "wrong-token"));
    expect(e.httpStatus).toBe(404);
  });

  test("revoke stops resolution and deletes ciphertext", async () => {
    const { store, mgr } = mk();
    const res = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe });
    const view = await mgr.revoke(res.id, res.manageToken);
    expect(view.status).toBe("revoked");
    const e = await catchErr(mgr.resolveDirect(res.id, {}));
    expect(e.httpStatus).toBe(404);
    // ciphertext object gone
    expect(await store.get(`shl/c/${res.id}.jwe`)).toBeNull();
  });
});

describe("controls", () => {
  test("maxUses is enforced exactly (race-safe CAS)", async () => {
    const { mgr } = mk();
    const res = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe, policy: { maxUses: 2 } });
    await mgr.resolveDirect(res.id, {});
    await mgr.resolveDirect(res.id, {});
    const e = await catchErr(mgr.resolveDirect(res.id, {}));
    expect(e.httpStatus).toBe(404);
    const view = await mgr.get(res.id, res.manageToken);
    expect(view.status).toBe("exhausted");
    expect(view.useCount).toBe(2);
  });

  test("pause hides, resume restores", async () => {
    const { mgr } = mk();
    const res = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe });
    await mgr.pause(res.id, res.manageToken);
    expect((await catchErr(mgr.resolveDirect(res.id, {}))).httpStatus).toBe(404);
    await mgr.resume(res.id, res.manageToken);
    expect((await mgr.resolveDirect(res.id, {})).contentType).toBe("application/jose");
  });

  test("expired share is not servable", async () => {
    const { mgr } = mk();
    const past = Math.floor(Date.now() / 1000) - 10;
    const res = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe, policy: { exp: past } });
    expect((await catchErr(mgr.resolveDirect(res.id, {}))).httpStatus).toBe(404);
  });

  test("access log records recipients", async () => {
    const { mgr } = mk();
    const res = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe });
    await mgr.resolveDirect(res.id, { recipient: "Clinic A" });
    const log = await mgr.accessLog(res.id, res.manageToken);
    expect(log.at(-1)?.recipient).toBe("Clinic A");
  });

  test("passcode gates resolution", async () => {
    const { mgr } = mk();
    const res = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe, policy: { passcode: "1234" } });
    expect((await catchErr(mgr.resolveDirect(res.id, {}))).httpStatus).toBe(401);
    expect((await mgr.resolveDirect(res.id, { passcode: "1234" })).contentType).toBe("application/jose");
  });
});

describe("manifest rail", () => {
  test("small payloads embed; large payloads return a ticketed location", async () => {
    const { mgr } = mk({ maxEmbeddedBytes: 10 }); // force the location path
    const sealed = await encryptBundle(BUNDLE);
    const res = await mgr.create({ ciphertext: sealed.jwe });
    const manifest = await mgr.resolveManifest(res.id, { recipient: "r", embeddedLengthMax: 10 });
    const f = manifest.files[0]!;
    expect(f.embedded).toBeUndefined();
    expect(f.location).toContain(`/shl/${res.id}/f/0?t=`);

    const t = new URL(f.location!).searchParams.get("t")!;
    const file = await mgr.resolveFileTicket(res.id, "0", t);
    expect(await openSealed(file.jwe, sealed.key)).toBe(BUNDLE);

    expect((await catchErr(mgr.resolveFileTicket(res.id, "0", "bogus.sig"))).httpStatus).toBe(404);
  });
});

describe("id allocation", () => {
  test("ids are server-minted, distinct, and unguessable-length", async () => {
    const { mgr } = mk();
    const a = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe });
    const b = await mgr.create({ ciphertext: (await encryptBundle(BUNDLE)).jwe });
    expect(a.id).not.toBe(b.id);
    expect(a.id.length).toBeGreaterThanOrEqual(20); // 16 bytes base64url
  });

  test("create works on a non-CAS backend (head+put reservation fallback)", async () => {
    const store = new MemoryObjectStore();
    (store as any).capabilities = { conditionalWrite: false, presign: false, lifecycle: false, publicUrl: true };
    const mgr = new ShareManager({ store, baseUrl: "https://shl.example.com" });
    const sealed = await encryptBundle(BUNDLE);
    const res = await mgr.create({ mode: "mediated", ciphertext: sealed.jwe });
    expect(await openSealed((await mgr.resolveDirect(res.id, {})).jwe, sealed.key)).toBe(BUNDLE);
    // use-limits are refused on a non-CAS backend (honesty rule)
    expect((await catchErr(mgr.create({ ciphertext: "x", policy: { maxUses: 2 } }))).code).toBe("unsupported_control");
  });
});

describe("direct mode", () => {
  test("fileUrl is the object URL; revoke deletes it; counting controls refused", async () => {
    const { store, mgr } = mk();
    const res = await mgr.create({ mode: "direct", ciphertext: (await encryptBundle(BUNDLE)).jwe });
    expect(res.fileUrl).toBe(store.publicUrl(`shl/c/${res.id}.jwe`));

    const bad = await catchErr(mgr.create({ mode: "direct", ciphertext: "x", policy: { maxUses: 3 } }));
    expect(bad.code).toBe("unsupported_control");

    await mgr.revoke(res.id, res.manageToken);
    expect(await store.get(`shl/c/${res.id}.jwe`)).toBeNull();
  });
});

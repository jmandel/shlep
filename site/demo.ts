/**
 * demo.ts — the in-browser live demo for the landing page. It runs the REAL
 * client-side code (../src/client) so visitors can watch the blind boundary:
 * the content key is generated in their browser, the ciphertext is what a host
 * would store, and the key never leaves. No network, no server.
 */
import { composeShlink, encryptBundle, openSealed } from "../src/client";

const SAMPLE = JSON.stringify(
  {
    resourceType: "Bundle",
    type: "collection",
    entry: [
      { resource: { resourceType: "Patient", id: "p1" } },
      {
        resource: {
          resourceType: "Observation",
          status: "final",
          code: { text: "Menstrual flow" },
          valueString: "moderate",
          effectiveDateTime: "2026-06-01",
        },
      },
    ],
  },
  null,
  2,
);

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const trunc = (s: string, n = 96) => (s.length > n ? s.slice(0, n) + "…" : s);

function ready(fn: () => void) {
  if (document.readyState !== "loading") fn();
  else document.addEventListener("DOMContentLoaded", fn);
}

ready(() => {
  const input = $("plaintext") as HTMLTextAreaElement;
  input.value = SAMPLE;

  let lastKey: Uint8Array | null = null;
  let lastJwe = "";

  $("encrypt").addEventListener("click", async () => {
    try {
      const sealed = await encryptBundle(input.value);
      lastKey = sealed.key;
      lastJwe = sealed.jwe;
      const fileUrl = "https://shlep.example/shl/" + sealed.keyB64.slice(0, 16);
      const shlink = composeShlink(fileUrl, sealed.keyB64, { label: "Example export" });

      $("out-cipher").textContent = trunc(sealed.jwe, 160);
      $("out-key").textContent = sealed.keyB64;
      $("out-link").textContent = "https://viewer.example.org/#" + trunc(shlink, 120);
      $("results").classList.add("show");
      $("roundtrip").textContent = "";
    } catch (e) {
      $("out-cipher").textContent = "error: " + (e as Error).message;
    }
  });

  $("decrypt").addEventListener("click", async () => {
    if (!lastKey) return;
    try {
      const back = await openSealed(lastJwe, lastKey);
      const ok = back === input.value;
      $("roundtrip").textContent = ok
        ? "✓ Decrypted in-browser with the key — round-trips exactly. The host never saw it."
        : "decrypted, but did not match";
      $("roundtrip").className = ok ? "ok" : "bad";
    } catch (e) {
      $("roundtrip").textContent = "decrypt failed: " + (e as Error).message;
      $("roundtrip").className = "bad";
    }
  });
});

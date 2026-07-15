import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/merkle";

const ADMIN = "test-admin-token";
const PUB = "96985fcd2e6cef8ef8fc8c28351d27b83e0593462016b48e9fa8c4dd10736df4";

const post = (path: string, body: unknown, token?: string) =>
  SELF.fetch("https://registry.test/v1" + path, {
    method: "POST",
    headers: token ? { authorization: `Bearer ${token}` } : {},
    body: JSON.stringify(body),
  });
const get = (path: string) => SELF.fetch("https://registry.test/v1" + path);
const getJson = async (path: string) => (await (await get(path)).json()) as any;

/** Reproduce an advisory's canonical signing bytes exactly as `src/advisory.ts` (and the Rust client)
 *  do, so a served signature can be verified independently. */
async function canonicalBytes(a: any): Promise<Uint8Array> {
  const detailsHash = toHex(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(a.details ?? ""))),
  );
  const state = a.withdrawn ? "withdrawn" : "active";
  return new TextEncoder().encode(
    `noeta-advisory-v1\n${a.id}\n${a.package}\n${a.ranges}\n${a.severity}\n` +
      `${state}\n${a.summary}\n${detailsHash}\n${a.url ?? ""}\n`,
  );
}

async function verifySig(msg: Uint8Array, sigHex: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", fromHex(PUB), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, fromHex(sigHex), msg);
}

const ADVISORY = {
  id: "NOETA-2026-0001",
  package: "acme/http",
  ranges: ">=1.0.0, <1.2.3",
  severity: "high",
  summary: "request smuggling in the chunked decoder",
  details: "A crafted Transfer-Encoding header lets an attacker smuggle a second request.\nUpgrade to 1.2.3.",
  url: "https://example.com/advisories/1",
};

// Each test forks storage from this snapshot: exactly one published advisory (isolatedStorage means a
// test's own writes don't leak to the next).
beforeAll(async () => {
  expect((await post("/advisories", ADVISORY, ADMIN)).status).toBe(201);
});

describe("advisory feed", () => {
  it("rejects publishing without the admin token", async () => {
    expect((await post("/advisories", { ...ADVISORY, id: "NOETA-2026-9999" })).status).toBe(401);
    expect((await post("/advisories", { ...ADVISORY, id: "NOETA-2026-9999" }, "wrong")).status).toBe(401);
  });

  it("publishes a signed advisory whose signature the client can verify", async () => {
    const { advisories } = await getJson("/advisories");
    expect(advisories).toHaveLength(1);
    const a = advisories[0];
    expect(a.id).toBe(ADVISORY.id);
    expect(a.withdrawn).toBe(false);
    // The served signature verifies against the pinned public key over the reproduced bytes.
    expect(await verifySig(await canonicalBytes(a), a.signature)).toBe(true);
    // A tampered range (narrowing who is affected) breaks the signature.
    expect(await verifySig(await canonicalBytes({ ...a, ranges: ">=1.0.0, <1.0.1" }), a.signature)).toBe(false);
  });

  it("serves a signed feed head a client can reproduce and pin", async () => {
    const cp = await getJson("/advisories/checkpoint");
    expect(cp.count).toBe(1);
    // Recompute the digest over the (id-sorted) advisories and check it matches, then verify the head.
    const { advisories } = await getJson("/advisories");
    const sorted = [...advisories].sort((x, y) => (x.id < y.id ? -1 : 1));
    const parts: Uint8Array[] = [];
    for (const a of sorted) parts.push(await canonicalBytes(a));
    const total = parts.reduce((n, p) => n + p.length, 0);
    const buf = new Uint8Array(total);
    let off = 0;
    for (const p of parts) (buf.set(p, off), (off += p.length));
    const digest = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buf)));
    expect(digest).toBe(cp.digest);
    const head = new TextEncoder().encode(`noeta-advisory-feed-v1\n${cp.count}\n${cp.digest}\n`);
    expect(await verifySig(head, cp.signature)).toBe(true);
  });

  it("updates an advisory in place, bumping the cursor but not the count", async () => {
    // Starts from the seeded NOETA-0001; a second, distinct advisory advances the cursor.
    expect((await post("/advisories", { ...ADVISORY, id: "NOETA-2026-0002", package: "acme/tls" }, ADMIN)).status).toBe(201);
    const before = await getJson("/advisories/checkpoint");
    expect(before.count).toBe(2);

    // Withdraw the first (a false alarm) — same id, so an update, not a new row.
    const w = await post("/advisories", { ...ADVISORY, withdrawn: true }, ADMIN);
    expect(w.status).toBe(201);
    const list = await getJson("/advisories");
    expect(list.advisories).toHaveLength(2); // withdrawn, not deleted
    const first = list.advisories.find((a: any) => a.id === ADVISORY.id);
    expect(first.withdrawn).toBe(true);
    // The withdrawn state is bound into the signature.
    expect(await verifySig(await canonicalBytes(first), first.signature)).toBe(true);
    // The count is stable; the feed digest changed (content changed).
    const after = await getJson("/advisories/checkpoint");
    expect(after.count).toBe(2);
    expect(after.digest).not.toBe(before.digest);
  });

  it("serves only the delta with ?since=", async () => {
    // Add a second advisory (cursor advances); ?since below its seq returns just that one.
    expect((await post("/advisories", { ...ADVISORY, id: "NOETA-2026-0002", package: "acme/tls" }, ADMIN)).status).toBe(201);
    const full = await getJson("/advisories");
    const maxSeq = Math.max(...full.advisories.map((a: any) => a.seq));
    const delta = await getJson(`/advisories?since=${maxSeq - 1}`);
    expect(delta.advisories).toHaveLength(1);
    expect(delta.advisories[0].seq).toBe(maxSeq);
  });

  it("validates the advisory body", async () => {
    expect((await post("/advisories", { ...ADVISORY, id: "bad id" }, ADMIN)).status).toBe(400);
    expect((await post("/advisories", { ...ADVISORY, package: "notslashed" }, ADMIN)).status).toBe(400);
    expect((await post("/advisories", { ...ADVISORY, severity: "spicy" }, ADMIN)).status).toBe(400);
    expect((await post("/advisories", { ...ADVISORY, summary: "line\nbreak" }, ADMIN)).status).toBe(400);
    expect((await post("/advisories", { ...ADVISORY, ranges: "" }, ADMIN)).status).toBe(400);
  });
});

import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, leafHash, verifyConsistency, verifyInclusion } from "../src/merkle";

const ADMIN = "test-admin-token";
const TOKEN = "log-publish-token-abc123";

const post = (path: string, body: unknown, token?: string) =>
  SELF.fetch("https://registry.test/v1" + path, {
    method: "POST",
    headers: token ? { authorization: `Bearer ${token}` } : {},
    body: JSON.stringify(body),
  });
const get = (path: string) => SELF.fetch("https://registry.test/v1" + path);
const getJson = async (path: string) => (await (await get(path)).json()) as any;

/** Verify an Ed25519 checkpoint signature exactly as a client would. */
async function verifyCheckpointSig(pubHex: string, size: number, rootHex: string, sigHex: string) {
  const key = await crypto.subtle.importKey("raw", fromHex(pubHex), { name: "Ed25519" }, false, ["verify"]);
  const msg = new TextEncoder().encode(`noeta-log-checkpoint-v1\n${size}\n${rootHex}\n`);
  return crypto.subtle.verify("Ed25519", key, fromHex(sigHex), msg);
}

// Publish three releases so the log has a non-trivial tree.
beforeAll(async () => {
  expect((await post("/scopes", { scope: "acme", token: TOKEN }, ADMIN)).status).toBe(201);
  for (const [pkg, sha] of [["a", "aaa"], ["b", "bbb"], ["c", "ccc"]]) {
    const r = await post(`/packages/acme/${pkg}`, { version: "1.0.0", url: "u", tag: "t", sha }, TOKEN);
    expect(r.status).toBe(201);
    expect(typeof ((await r.json()) as any).log_index).toBe("number"); // publish reports the log position
  }
});

describe("transparency log", () => {
  it("serves a signed checkpoint over the current tree", async () => {
    const cp = await getJson("/log/checkpoint");
    expect(cp.tree_size).toBe(3);
    expect(cp.root_hash).toMatch(/^[0-9a-f]{64}$/);
    const { public_key } = await getJson("/log/key");
    expect(await verifyCheckpointSig(public_key, cp.tree_size, cp.root_hash, cp.signature)).toBe(true);
    // A tampered size/root does not verify against the signature.
    expect(await verifyCheckpointSig(public_key, 4, cp.root_hash, cp.signature)).toBe(false);
  });

  it("proves a release's inclusion against the checkpoint root", async () => {
    const cp = await getJson("/log/checkpoint");
    const proof = await getJson("/log/proof/acme/b/1.0.0");
    expect(proof.index).toBe(1); // acme/b was the second publish
    expect(proof.root_hash).toBe(cp.root_hash); // same tree as the checkpoint
    // Recompute the leaf from the served canonical record and verify the audit path.
    const leaf = await leafHash(new TextEncoder().encode(proof.record));
    const ok = await verifyInclusion(
      leaf,
      proof.index,
      proof.tree_size,
      proof.proof.map((h: string) => fromHex(h)),
      fromHex(proof.root_hash),
    );
    expect(ok).toBe(true);
    // The record binds the release's identity + commit.
    expect(proof.record).toContain("acme/b");
    expect(proof.record).toContain("bbb");
  });

  it("proves the log is append-only between two sizes", async () => {
    const c = await getJson("/log/consistency?from=2&to=3");
    expect(c.from).toBe(2);
    expect(c.to).toBe(3);
    const ok = await verifyConsistency(
      2,
      3,
      c.proof.map((h: string) => fromHex(h)),
      fromHex(c.root_from),
      fromHex(c.root_to),
    );
    expect(ok).toBe(true);
    // A rewritten root_to must not verify against the honest prefix root.
    const bad = await verifyConsistency(
      2,
      3,
      c.proof.map((h: string) => fromHex(h)),
      fromHex(c.root_from),
      fromHex("00".repeat(32)),
    );
    expect(bad).toBe(false);
  });

  it("404s an unlogged release and 400s a bad consistency range", async () => {
    expect((await get("/log/proof/acme/nope/9.9.9")).status).toBe(404);
    expect((await get("/log/consistency?from=5&to=3")).status).toBe(400);
  });
});

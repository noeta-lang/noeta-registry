import { describe, expect, it } from "vitest";
import {
  consistencyProof,
  inclusionProof,
  leafHash,
  merkleRoot,
  verifyConsistency,
  verifyInclusion,
} from "../src/merkle";

async function leaves(n: number): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) out.push(await leafHash(new TextEncoder().encode(`entry-${i}`)));
  return out;
}

// Exercise a range of sizes including non-powers-of-two, where the tree is unbalanced (the hard cases).
const SIZES = [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 23];

describe("merkle transparency tree", () => {
  it("verifies inclusion for every leaf at every size", async () => {
    for (const n of SIZES) {
      const ls = await leaves(n);
      const root = await merkleRoot(ls);
      for (let m = 0; m < n; m++) {
        const proof = await inclusionProof(ls, m);
        expect(await verifyInclusion(ls[m], m, n, proof, root)).toBe(true);
        // Wrong index within the same tree must not verify.
        const wrong = (m + 1) % n;
        if (wrong !== m) {
          expect(await verifyInclusion(ls[m], wrong, n, proof, root)).toBe(false);
        }
      }
    }
  });

  it("rejects a tampered inclusion proof or root", async () => {
    const ls = await leaves(9);
    const root = await merkleRoot(ls);
    const proof = await inclusionProof(ls, 3);
    expect(await verifyInclusion(ls[3], 3, 9, proof, root)).toBe(true);
    // Flip a byte in the proof.
    const bad = proof.map((h) => h.slice());
    bad[0][0] ^= 0xff;
    expect(await verifyInclusion(ls[3], 3, 9, bad, root)).toBe(false);
    // A different leaf under the same proof/root.
    expect(await verifyInclusion(ls[4], 3, 9, proof, root)).toBe(false);
    // A wrong root.
    const otherRoot = await merkleRoot(await leaves(8));
    expect(await verifyInclusion(ls[3], 3, 9, proof, otherRoot)).toBe(false);
  });

  it("verifies consistency for every prefix m ≤ n", async () => {
    for (const n of SIZES) {
      const ls = await leaves(n);
      const rootN = await merkleRoot(ls);
      for (let m = 1; m <= n; m++) {
        const rootM = await merkleRoot(ls.slice(0, m));
        const proof = await consistencyProof(ls, m);
        expect(await verifyConsistency(m, n, proof, rootM, rootN)).toBe(true);
      }
    }
  });

  it("rejects an inconsistent (rewritten) log", async () => {
    const ls = await leaves(12);
    const rootN = await merkleRoot(ls);
    const rootM = await merkleRoot(ls.slice(0, 5));
    const proof = await consistencyProof(ls, 5);
    expect(await verifyConsistency(5, 12, proof, rootM, rootN)).toBe(true);

    // A DIFFERENT history of the same size (leaf 2 rewritten) must not be consistent with the old root.
    const rewritten = ls.slice();
    rewritten[2] = await leafHash(new TextEncoder().encode("tampered"));
    const rewrittenRoot = await merkleRoot(rewritten);
    const rewrittenProof = await consistencyProof(rewritten, 5);
    expect(await verifyConsistency(5, 12, rewrittenProof, rootM, rewrittenRoot)).toBe(false);

    // A flipped proof byte fails.
    const bad = proof.map((h) => h.slice());
    if (bad.length > 0) bad[0][0] ^= 0xff;
    expect(await verifyConsistency(5, 12, bad, rootM, rootN)).toBe(false);
  });

  it("treats equal sizes and the empty prefix sensibly", async () => {
    const ls = await leaves(6);
    const root = await merkleRoot(ls);
    expect(await verifyConsistency(6, 6, [], root, root)).toBe(true);
    expect(await verifyConsistency(6, 6, [root], root, root)).toBe(false); // must be empty
  });
});

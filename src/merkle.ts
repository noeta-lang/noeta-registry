// Merkle tree over the transparency log (namespace-protection #1, transparency log) — RFC 6962
// semantics. The log is an append-only list of leaves (one per published release); its Merkle tree
// root, signed into a *checkpoint*, lets a client prove two things without trusting the registry:
//   • **inclusion** — a specific release is in the log at a given tree size/root;
//   • **consistency** — the log of size m is a prefix of the log of size n (it was only appended to,
//     never rewritten). Together these stop a compromised registry from *equivocating* — serving one
//     history to one client and a different one to another.
//
// Leaves are passed in as their **leaf hashes** (`leafHash(record)`); internal nodes use `nodeHash`.
// All hashing is SHA-256 (Web Crypto, async). Pure and dependency-free.

/** RFC 6962 leaf hash: `SHA-256(0x00 || data)`. */
export async function leafHash(data: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x00]), data));
}

/** RFC 6962 interior hash: `SHA-256(0x01 || left || right)`. */
export async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

/** The Merkle Tree Hash (root) of `leaves` (already leaf-hashed). Empty tree = `SHA-256("")`. */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  const n = leaves.length;
  if (n === 0) return sha256(new Uint8Array());
  if (n === 1) return leaves[0];
  const k = largestPowerOfTwoBelow(n);
  return nodeHash(await merkleRoot(leaves.slice(0, k)), await merkleRoot(leaves.slice(k)));
}

/** The inclusion (audit) proof for leaf `m` in a tree of `leaves`: sibling hashes bottom-up, each the
 *  root of the subtree on the other side of the split. */
export async function inclusionProof(leaves: Uint8Array[], m: number): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (n <= 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (m < k) {
    const sub = await inclusionProof(leaves.slice(0, k), m);
    return [...sub, await merkleRoot(leaves.slice(k))];
  }
  const sub = await inclusionProof(leaves.slice(k), m - k);
  return [...sub, await merkleRoot(leaves.slice(0, k))];
}

/** Verify that `leaf` at index `m` in a tree of `size` with `root` is proven by `proof`. */
export async function verifyInclusion(
  leaf: Uint8Array,
  m: number,
  size: number,
  proof: Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (m >= size) return false;
  const computed = await rootFromInclusion(leaf, m, size, proof);
  return computed !== null && equal(computed, root);
}

async function rootFromInclusion(
  leaf: Uint8Array,
  m: number,
  n: number,
  proof: Uint8Array[],
): Promise<Uint8Array | null> {
  if (n <= 1) return proof.length === 0 ? leaf : null;
  if (proof.length === 0) return null;
  const k = largestPowerOfTwoBelow(n);
  const sibling = proof[proof.length - 1];
  const rest = proof.slice(0, proof.length - 1);
  if (m < k) {
    const left = await rootFromInclusion(leaf, m, k, rest);
    return left && nodeHash(left, sibling);
  }
  const right = await rootFromInclusion(leaf, m - k, n - k, rest);
  return right && nodeHash(sibling, right);
}

/** The consistency proof that a tree of size `m` is a prefix of a tree of `leaves` (size ≥ m). */
export async function consistencyProof(leaves: Uint8Array[], m: number): Promise<Uint8Array[]> {
  if (m <= 0 || m > leaves.length) return [];
  return subproof(m, leaves, true);
}

async function subproof(m: number, leaves: Uint8Array[], b: boolean): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (m === n) return b ? [] : [await merkleRoot(leaves)];
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    const sub = await subproof(m, leaves.slice(0, k), b);
    return [...sub, await merkleRoot(leaves.slice(k))];
  }
  const sub = await subproof(m - k, leaves.slice(k), false);
  return [...sub, await merkleRoot(leaves.slice(0, k))];
}

/** Verify a consistency `proof` that a tree of size `m`/root `rootM` is a prefix of one of size `n`/
 *  root `rootN`. */
export async function verifyConsistency(
  m: number,
  n: number,
  proof: Uint8Array[],
  rootM: Uint8Array,
  rootN: Uint8Array,
): Promise<boolean> {
  if (m > n) return false;
  if (m === n) return proof.length === 0 && equal(rootM, rootN);
  if (m === 0) return true; // an empty prefix is consistent with anything
  const roots = await reconstructConsistency(proof, m, n, true, rootM);
  return roots !== null && equal(roots[0], rootM) && equal(roots[1], rootN);
}

/** Reconstruct `[MTH(0:m), MTH(0:n)]` from a consistency proof, mirroring `subproof`. `b` marks that
 *  the m-tree root at this level is the elided pinned `rootM` (RFC 6962's power-of-two seed case). */
async function reconstructConsistency(
  proof: Uint8Array[],
  m: number,
  n: number,
  b: boolean,
  rootM: Uint8Array,
): Promise<[Uint8Array, Uint8Array] | null> {
  if (m === n) {
    if (b) return [rootM, rootM]; // the shared subtree root == the pinned root
    if (proof.length === 0) return null;
    const h = proof[proof.length - 1];
    return [h, h];
  }
  if (proof.length === 0) return null;
  const k = largestPowerOfTwoBelow(n);
  const sibling = proof[proof.length - 1];
  const rest = proof.slice(0, proof.length - 1);
  if (m <= k) {
    const sub = await reconstructConsistency(rest, m, k, b, rootM);
    return sub && [sub[0], await nodeHash(sub[1], sibling)];
  }
  const sub = await reconstructConsistency(rest, m - k, n - k, false, rootM);
  return sub && [await nodeHash(sibling, sub[0]), await nodeHash(sibling, sub[1])];
}

// --- helpers -------------------------------------------------------------------------------------

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** The largest power of two strictly less than `n` (n ≥ 2) — RFC 6962's split point `k`. */
function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

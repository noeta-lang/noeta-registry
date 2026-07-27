// The transparency log (namespace-protection #1) — an append-only, tamper-evident record of every
// published release, built on the RFC 6962 Merkle tree in `merkle.ts`. Each release becomes one leaf;
// the tree root is served in a **signed checkpoint** so a client can verify, without trusting the
// registry, that a release is logged (inclusion) and that the log was only appended to, never
// rewritten (consistency). Proofs need no key; only the checkpoint is signed (Ed25519).

import { consistencyProof, fromHex, inclusionProof, leafHash, merkleRoot, toHex } from "./merkle";

const RECORD_PREFIX = "noeta-transparency-log-v1";
const CHECKPOINT_PREFIX = "noeta-log-checkpoint-v1";

interface LogEnv {
  DB: D1Database;
  LOG_PRIVATE_KEY?: string; // base64 PKCS8 Ed25519 private key (a Worker secret)
  LOG_PUBLIC_KEY?: string; // hex raw Ed25519 public key (served for clients to pin)
}

/** A release's provenance, condensed for the log leaf: the key signature, a digest of the keyless
 *  bundle (bundles are large), or `unsigned`. Binds *which* provenance the release carried. */
export async function provenanceTag(sig: string | null, bundle: string | null): Promise<string> {
  if (sig) return `key:${sig}`;
  if (bundle) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bundle));
    return `keyless:${toHex(new Uint8Array(digest))}`;
  }
  return "unsigned";
}

/** The canonical log record for a release — the exact bytes the leaf hashes, reproduced identically by
 *  the client so it can recompute the leaf and verify inclusion.
 *
 *  `license` (the release's declared SPDX expression, or "" when none) is a trailing field appended
 *  after the original six — the client parses length-tolerantly (`>= 6` fields), so records written
 *  before the field existed still verify, and a record's license is absent-vs-empty distinguishable
 *  by field count. New fields must likewise only ever be appended. */
export function logRecord(
  name: string,
  version: string,
  url: string,
  tag: string,
  sha: string,
  provenance: string,
  license: string,
): string {
  return `${RECORD_PREFIX}\n${name}\n${version}\n${url}\n${tag}\n${sha}\n${provenance}\n${license}\n`;
}

/** The next append index and the leaf hash for `record` — computed by the publish path so the release
 *  and its log entry can be inserted together (one batch). */
export async function prepareEntry(env: LogEnv, record: string): Promise<{ idx: number; leaf: string }> {
  const leaf = toHex(await leafHash(new TextEncoder().encode(record)));
  const row = await env.DB.prepare("SELECT COALESCE(MAX(idx) + 1, 0) AS next FROM log").first<{
    next: number;
  }>();
  return { idx: row?.next ?? 0, leaf };
}

async function allLeaves(env: LogEnv): Promise<Uint8Array[]> {
  const { results } = await env.DB.prepare("SELECT leaf_hash FROM log ORDER BY idx").all<{
    leaf_hash: string;
  }>();
  return (results ?? []).map((r) => fromHex(r.leaf_hash));
}

/** The signed checkpoint (RFC 6962 signed tree head): the current tree size + root, signed with the
 *  log's Ed25519 key so a client can trust a checkpoint it fetches from an untrusted path. */
export async function checkpoint(env: LogEnv): Promise<Response> {
  if (!env.LOG_PRIVATE_KEY) {
    return json({ error: "the transparency log is not configured (no signing key)" }, 501);
  }
  const leaves = await allLeaves(env);
  const size = leaves.length;
  const rootHex = toHex(await merkleRoot(leaves));
  const signature = await signCheckpoint(env.LOG_PRIVATE_KEY, size, rootHex);
  return json({ tree_size: size, root_hash: rootHex, signature });
}

/** The log's public key (hex), for a client to pin and verify checkpoint signatures against. */
export function publicKey(env: LogEnv): Response {
  if (!env.LOG_PUBLIC_KEY) return json({ error: "the transparency log has no public key" }, 404);
  return json({ public_key: env.LOG_PUBLIC_KEY });
}

/** An inclusion proof, as both the JSON body and the web browser's proof page serve it — the wire
 *  shape IS this object, so the human page and the API can never describe different proofs. */
export interface Inclusion {
  index: number;
  tree_size: number;
  root_hash: string;
  record: string;
  proof: string[];
}

/** The inclusion proof for `name@version` — its leaf index, the current tree size + root, the
 *  canonical record (so the client recomputes the leaf), and the audit path. Null if unlogged. */
export async function inclusionData(env: LogEnv, name: string, version: string): Promise<Inclusion | null> {
  const row = await env.DB.prepare("SELECT idx, record FROM log WHERE name = ? AND version = ?")
    .bind(name, version)
    .first<{ idx: number; record: string }>();
  return row ? proofAt(env, row.idx, row.record) : null;
}

/** The same proof for the leaf at an explicit `idx` (advisories are looked up by their stored log
 *  index rather than by name/version). Null if no leaf sits at that index. */
export async function inclusionDataAtIndex(env: LogEnv, idx: number): Promise<Inclusion | null> {
  const row = await env.DB.prepare("SELECT record FROM log WHERE idx = ?")
    .bind(idx)
    .first<{ record: string }>();
  return row ? proofAt(env, idx, row.record) : null;
}

async function proofAt(env: LogEnv, idx: number, record: string): Promise<Inclusion> {
  const leaves = await allLeaves(env);
  const proof = await inclusionProof(leaves, idx);
  const root = await merkleRoot(leaves);
  return {
    index: idx,
    tree_size: leaves.length,
    root_hash: toHex(root),
    record,
    proof: proof.map(toHex),
  };
}

/** `GET /v1/log/proof/{company}/{package}/{version}` — 404 if the release isn't logged. */
export async function inclusion(env: LogEnv, name: string, version: string): Promise<Response> {
  const data = await inclusionData(env, name, version);
  if (!data) return json({ error: `${name}@${version} is not in the transparency log` }, 404);
  return json(data);
}

/** An inclusion proof for the leaf at an explicit `idx` (used for non-release leaves like advisories,
 *  which are looked up by their stored log index rather than by name/version). */
export async function inclusionAtIndex(env: LogEnv, idx: number): Promise<Response> {
  const data = await inclusionDataAtIndex(env, idx);
  if (!data) return json({ error: `no transparency-log entry at index ${idx}` }, 404);
  return json(data);
}

/** The checkpoint signature over a tree head the caller already computed — what the proof page shows
 *  beside the root hash, so a reader sees the *signed* head without a second pass over the leaves.
 *  Null when no signing key is configured (the same condition that makes `/v1/log/checkpoint` 501). */
export async function signatureFor(env: LogEnv, size: number, rootHex: string): Promise<string | null> {
  if (!env.LOG_PRIVATE_KEY) return null;
  return signCheckpoint(env.LOG_PRIVATE_KEY, size, rootHex);
}

/** A consistency proof that the log at size `from` is a prefix of the log at size `to` — the
 *  append-only guarantee across two checkpoints a client has seen. */
export async function consistency(env: LogEnv, fromParam: string | null, toParam: string | null): Promise<Response> {
  const leaves = await allLeaves(env);
  const size = leaves.length;
  const from = Number(fromParam);
  const to = toParam === null ? size : Number(toParam);
  if (!Number.isInteger(from) || !Number.isInteger(to) || from < 1 || from > to || to > size) {
    return json({ error: `\`from\`/\`to\` must satisfy 1 ≤ from ≤ to ≤ ${size}` }, 400);
  }
  const prefix = leaves.slice(0, to);
  const proof = await consistencyProof(prefix, from);
  return json({
    from,
    to,
    root_from: toHex(await merkleRoot(leaves.slice(0, from))),
    root_to: toHex(await merkleRoot(prefix)),
    proof: proof.map(toHex),
  });
}

// --- signing -------------------------------------------------------------------------------------

/** The canonical checkpoint bytes that are signed — MUST match the client's verification. */
function checkpointBytes(size: number, rootHex: string): Uint8Array {
  return new TextEncoder().encode(`${CHECKPOINT_PREFIX}\n${size}\n${rootHex}\n`);
}

async function signCheckpoint(privateKeyB64: string, size: number, rootHex: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBytes(privateKeyB64),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("Ed25519", key, checkpointBytes(size, rootHex));
  return toHex(new Uint8Array(sig));
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

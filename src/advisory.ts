// Security advisory feed (namespace-protection #1) — a signed, RUSTSEC-style database of known-bad
// releases, so `noeta audit` can flag a dependency pinned to a version with a known vulnerability or a
// known-malicious release. Two layers of trust:
//   • per-advisory signatures — each advisory is individually Ed25519-signed over its canonical bytes,
//     so a network MITM or a compromised mirror cannot inject a fake advisory (a denial-of-service that
//     red-flags a healthy package) or tamper with a real one (silently narrowing its affected range);
//   • a signed feed head — `{ count, digest }` signed with the same key, which a client pins
//     trust-on-first-use so a *dropped* advisory (count regresses) is detectable.
//
// The advisory signing key is separate from the transparency-log key (distinct roles). Absent a key,
// publishing is refused and the checkpoint is a 501, but the read feed is still served (unsigned
// advisories simply won't verify client-side).

import { toHex } from "./merkle";
import * as log from "./log";

const ADVISORY_PREFIX = "noeta-advisory-v1";
const FEED_PREFIX = "noeta-advisory-feed-v1";

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);

interface AdvisoryEnv {
  DB: D1Database;
  ADVISORY_PRIVATE_KEY?: string; // base64 PKCS8 Ed25519 private key (a Worker secret)
  ADVISORY_PUBLIC_KEY?: string; // hex raw Ed25519 public key (served for clients to pin)
  ADMIN_TOKEN?: string;
}

interface AdvisoryRow {
  id: string;
  package: string;
  ranges: string;
  patched: string | null;
  severity: string;
  summary: string;
  details: string;
  url: string;
  withdrawn: number;
  seq: number;
  signature: string;
  log_index: number | null;
}

/** The security-relevant fields of an advisory, in the exact byte layout that is signed — reproduced
 *  identically by the client (`noeta-pm`'s `advisory::canonical_bytes`) so a signature verifies on both
 *  sides. `details` is folded in as a SHA-256 digest (it may be multi-line; everything else is
 *  newline-free and validated so). `state` binds the withdrawn flag, so a registry can't silently
 *  un-retract an advisory under the same signature. */
interface AdvisoryFields {
  id: string;
  package: string;
  ranges: string;
  severity: string;
  withdrawn: boolean;
  summary: string;
  details: string;
  url: string;
}

/** The canonical text form — also the exact record stored as the advisory's transparency-log leaf, so
 *  the leaf's inclusion binds this precise advisory state. */
async function canonicalText(a: AdvisoryFields): Promise<string> {
  const detailsHash = await sha256hex(a.details);
  const state = a.withdrawn ? "withdrawn" : "active";
  return (
    `${ADVISORY_PREFIX}\n${a.id}\n${a.package}\n${a.ranges}\n${a.severity}\n` +
    `${state}\n${a.summary}\n${detailsHash}\n${a.url}\n`
  );
}

async function canonicalBytes(a: AdvisoryFields): Promise<Uint8Array> {
  return new TextEncoder().encode(await canonicalText(a));
}

/** The signed feed head (RFC-6962-style signed tree head, adapted): the advisory count plus a digest
 *  over every advisory's canonical bytes (id-sorted), signed so a client that pinned an earlier head
 *  can detect a dropped or rolled-back feed. */
function feedHeadBytes(count: number, digestHex: string): Uint8Array {
  return new TextEncoder().encode(`${FEED_PREFIX}\n${count}\n${digestHex}\n`);
}

/** SHA-256 (hex) of the id-sorted concatenation of every advisory's canonical bytes. Deterministic and
 *  reproducible by the client from the served feed, so a served digest that doesn't match the served
 *  advisories (a withheld entry) is caught. */
async function feedDigest(rows: AdvisoryRow[]): Promise<string> {
  const sorted = [...rows].sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  const parts: Uint8Array[] = [];
  for (const r of sorted) {
    parts.push(
      await canonicalBytes({
        id: r.id,
        package: r.package,
        ranges: r.ranges,
        severity: r.severity,
        withdrawn: r.withdrawn !== 0,
        summary: r.summary,
        details: r.details,
        url: r.url,
      }),
    );
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buf)));
}

/** POST /v1/advisories — publish or update an advisory (admin only; issuing advisories is an operator
 *  action). Idempotent per id: re-posting the same id updates it (e.g. to withdraw or re-scope) and
 *  bumps the feed cursor. The server re-signs on every write with its advisory key. */
export async function publishAdvisory(request: Request, env: AdvisoryEnv): Promise<Response> {
  if (!env.ADMIN_TOKEN) return json({ error: "advisory publishing is disabled" }, 403);
  const presented = bearer(request);
  if (!presented || !timingEqual(presented, env.ADMIN_TOKEN)) {
    return json({ error: "admin token required" }, 401);
  }
  if (!env.ADVISORY_PRIVATE_KEY) {
    return json({ error: "the advisory feed is not configured (no signing key)" }, 501);
  }
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const b = body as Record<string, unknown>;

  const id = b.id;
  const pkg = b.package;
  const ranges = b.ranges;
  const severity = b.severity;
  const summary = b.summary;
  const details = b.details ?? "";
  const url = b.url ?? "";
  const patched = b.patched ?? null;
  const withdrawn = b.withdrawn === true;

  const noNewline = (s: unknown): s is string => typeof s === "string" && !/[\n\r]/.test(s);
  if (!noNewline(id) || !/^[A-Za-z0-9_.-]+$/.test(id)) {
    return json({ error: "`id` must be a single-line token of [A-Za-z0-9_.-]" }, 400);
  }
  if (!noNewline(pkg) || !NAME.test(pkg)) {
    return json({ error: "`package` must be company/package" }, 400);
  }
  if (!noNewline(ranges) || ranges.length === 0) {
    return json({ error: "`ranges` must be a non-empty single-line SemVer requirement" }, 400);
  }
  if (typeof severity !== "string" || !SEVERITIES.has(severity)) {
    return json({ error: `\`severity\` must be one of ${[...SEVERITIES].join(", ")}` }, 400);
  }
  if (!noNewline(summary) || summary.length === 0) {
    return json({ error: "`summary` must be a non-empty single line" }, 400);
  }
  if (!noNewline(url)) return json({ error: "`url` must be single-line" }, 400);
  if (typeof details !== "string") return json({ error: "`details` must be a string" }, 400);
  if (patched !== null && !noNewline(patched)) {
    return json({ error: "`patched` must be single-line or omitted" }, 400);
  }

  const fields: AdvisoryFields = { id, package: pkg, ranges, severity, withdrawn, summary, details, url };
  const record = await canonicalText(fields);
  const signature = toHex(new Uint8Array(await sign(env.ADVISORY_PRIVATE_KEY, new TextEncoder().encode(record))));

  const now = new Date().toISOString();
  const nextSeq = ((
    await env.DB.prepare("SELECT COALESCE(MAX(seq) + 1, 0) AS next FROM advisories").first<{ next: number }>()
  )?.next ?? 0);
  // Bind this issuance into the transparency log: the leaf's record is the advisory's canonical bytes,
  // so its inclusion (and each later state, e.g. a withdrawal) is permanent and consistency-covered,
  // exactly like a release. Advisory row + log leaf are written atomically in one batch.
  const { idx, leaf } = await log.prepareEntry(env, record);
  await env.DB.batch([
    env.DB
      .prepare(
        "INSERT INTO advisories (id, package, ranges, patched, severity, summary, details, url, withdrawn, seq, signature, log_index, created_at, updated_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(id) DO UPDATE SET package = excluded.package, ranges = excluded.ranges, patched = excluded.patched, " +
          "severity = excluded.severity, summary = excluded.summary, details = excluded.details, url = excluded.url, " +
          "withdrawn = excluded.withdrawn, seq = excluded.seq, signature = excluded.signature, log_index = excluded.log_index, " +
          "updated_at = excluded.updated_at",
      )
      .bind(id, pkg, ranges, patched, severity, summary, details, url, withdrawn ? 1 : 0, nextSeq, signature, idx, now, now),
    env.DB
      .prepare("INSERT INTO log (idx, leaf_hash, name, version, record, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(idx, leaf, `advisory:${id}`, String(nextSeq), record, now),
  ]);
  return json({ status: "advisory published", id, seq: nextSeq, log_index: idx }, 201);
}

/** GET /v1/log/advisory/{id} — the inclusion proof for an advisory's current log leaf, so a client can
 *  verify (against the signed checkpoint) that the advisory it was served is the one in the log. */
export async function advisoryInclusion(env: AdvisoryEnv, id: string): Promise<Response> {
  const row = await env.DB.prepare("SELECT log_index FROM advisories WHERE id = ?")
    .bind(id)
    .first<{ log_index: number | null }>();
  if (!row || row.log_index === null) {
    return json({ error: `advisory \`${id}\` is not in the transparency log` }, 404);
  }
  return log.inclusionAtIndex(env, row.log_index);
}

/** GET /v1/advisories[?since=seq] — the advisory feed. `since` returns only entries with a strictly
 *  greater cursor (delta sync); omitted returns the full feed. Each entry carries its signature so the
 *  client verifies it against the pinned advisory key. */
export async function listAdvisories(env: AdvisoryEnv, sinceParam: string | null): Promise<Response> {
  let rows: AdvisoryRow[];
  if (sinceParam !== null) {
    const since = Number(sinceParam);
    if (!Number.isInteger(since) || since < 0) {
      return json({ error: "`since` must be a non-negative integer cursor" }, 400);
    }
    rows = (
      await env.DB.prepare("SELECT * FROM advisories WHERE seq > ? ORDER BY seq").bind(since).all<AdvisoryRow>()
    ).results ?? [];
  } else {
    rows = (await env.DB.prepare("SELECT * FROM advisories ORDER BY seq").all<AdvisoryRow>()).results ?? [];
  }
  return json({ advisories: rows.map(toWire) });
}

/** GET /v1/advisories/checkpoint — the signed feed head `{ count, digest, signature }`. The count is
 *  the *total* advisory count (not the delta), so a client can pin it and detect a shrunken feed. */
export async function advisoryCheckpoint(env: AdvisoryEnv): Promise<Response> {
  if (!env.ADVISORY_PRIVATE_KEY) {
    return json({ error: "the advisory feed is not configured (no signing key)" }, 501);
  }
  const rows = (await env.DB.prepare("SELECT * FROM advisories").all<AdvisoryRow>()).results ?? [];
  const digest = await feedDigest(rows);
  const signature = toHex(new Uint8Array(await sign(env.ADVISORY_PRIVATE_KEY, feedHeadBytes(rows.length, digest))));
  return json({ count: rows.length, digest, signature });
}

/** GET /v1/advisories/key — the advisory feed's public key (hex), for a client to pin. */
export function advisoryPublicKey(env: AdvisoryEnv): Response {
  if (!env.ADVISORY_PUBLIC_KEY) return json({ error: "the advisory feed has no public key" }, 404);
  return json({ public_key: env.ADVISORY_PUBLIC_KEY });
}

function toWire(r: AdvisoryRow) {
  return {
    id: r.id,
    package: r.package,
    ranges: r.ranges,
    patched: r.patched ?? undefined,
    severity: r.severity,
    summary: r.summary,
    details: r.details,
    url: r.url,
    withdrawn: r.withdrawn !== 0,
    seq: r.seq,
    signature: r.signature,
    log_index: r.log_index ?? undefined,
  };
}

// --- signing / helpers (kept local so this module is self-contained) ------------------------------

async function sign(privateKeyB64: string, message: Uint8Array): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("pkcs8", b64ToBytes(privateKeyB64), { name: "Ed25519" }, false, ["sign"]);
  return crypto.subtle.sign("Ed25519", key, message);
}

async function sha256hex(s: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bearer(request: Request): string | null {
  const h = request.headers.get("authorization") ?? "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function timingEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function readJson(request: Request): Promise<unknown | Response> {
  try {
    return await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
}

const NAME = /^[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z_][A-Za-z0-9_]*$/;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

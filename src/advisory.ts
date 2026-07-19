// Security advisory feed (namespace-protection #1 + advisory-intake arc) — a signed, RUSTSEC-style
// database of known-bad releases, so `noeta audit` can flag a dependency pinned to a version with a
// known vulnerability or a known-malicious release. Two layers of trust:
//   • per-advisory signatures — each advisory is individually Ed25519-signed over its canonical bytes,
//     so a network MITM or a compromised mirror cannot inject a fake advisory (a denial-of-service that
//     red-flags a healthy package) or tamper with a real one (silently narrowing its affected range);
//   • a signed feed head — `{ count, digest }` signed with the same key, which a client pins
//     trust-on-first-use so a *dropped* advisory (count regresses) is detectable.
//
// The advisory signing key is separate from the transparency-log key (distinct roles). Absent a key,
// publishing is refused and the checkpoint is a 501, but the read feed is still served (unsigned
// advisories simply won't verify client-side).
//
// **Intake tiers (advisory-intake arc).** Every advisory records its *trust tier* — how it entered the
// feed — bound into its canonical signing bytes so a client can trust which tier was served:
//   • `operator`  — operator-curated, admin-issued (this file's `publishAdvisory`; the anchor).
//   • `publisher` — issued by a scope's own owner for their own scope, carrying a keyless Sigstore
//     `bundle` the consumer verifies offline (`publishScopeAdvisory`).
//   • `imported`  — mirrored from OSV/GHSA/RUSTSEC via the operator-curated name map (`imports.ts`).
// The registry automates *provenance*, never *judgment*: a public report (`reports.ts`) is never an
// advisory until an operator or scope owner promotes it here.

import { toHex } from "./merkle";
import * as log from "./log";

const ADVISORY_PREFIX = "noeta-advisory-v1";
const FEED_PREFIX = "noeta-advisory-feed-v1";

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);

/** The three intake tiers, in canonical spelling. `operator` is the default (the pre-arc behavior). */
export const TIERS = new Set(["operator", "publisher", "imported"]);
export type AdvisoryTier = "operator" | "publisher" | "imported";

export interface AdvisoryEnv {
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
  tier: string;
  bundle: string | null;
  upstream_id: string | null;
  upstream_url: string | null;
}

/** The security-relevant fields of an advisory, in the exact byte layout that is signed — reproduced
 *  identically by the client (`noeta-pm`'s `advisory::canonical_bytes`) so a signature verifies on both
 *  sides. `details` is folded in as a SHA-256 digest (it may be multi-line; everything else is
 *  newline-free and validated so). `state` binds the withdrawn flag, so a registry can't silently
 *  un-retract an advisory under the same signature. `tier` is the trailing field appended by the
 *  advisory-intake arc — bound so a client can trust *which* tier the registry served. */
interface AdvisoryFields {
  id: string;
  package: string;
  ranges: string;
  severity: string;
  withdrawn: boolean;
  summary: string;
  details: string;
  url: string;
  tier: string;
}

/** The canonical text form — also the exact record stored as the advisory's transparency-log leaf, so
 *  the leaf's inclusion binds this precise advisory state. `tier` is appended after the original eight
 *  fields (record-evolution rule: new fields are only ever appended); the Rust client reproduces this
 *  byte-for-byte. */
async function canonicalText(a: AdvisoryFields): Promise<string> {
  const detailsHash = await sha256hex(a.details);
  const state = a.withdrawn ? "withdrawn" : "active";
  return (
    `${ADVISORY_PREFIX}\n${a.id}\n${a.package}\n${a.ranges}\n${a.severity}\n` +
    `${state}\n${a.summary}\n${detailsHash}\n${a.url}\n${a.tier}\n`
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
    parts.push(await canonicalBytes(rowFields(r)));
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

function rowFields(r: AdvisoryRow): AdvisoryFields {
  return {
    id: r.id,
    package: r.package,
    ranges: r.ranges,
    severity: r.severity,
    withdrawn: r.withdrawn !== 0,
    summary: r.summary,
    details: r.details,
    url: r.url,
    tier: r.tier,
  };
}

/** The validated, ready-to-store shape of one advisory, whatever tier issued it. The four intake paths
 *  (operator publish, publisher self-service, import, promote-from-report) each validate their own
 *  concerns then hand a `PreparedAdvisory` to {@link upsertAdvisory}, which signs, logs, and stores it
 *  identically — so the canonical bytes, the feed digest, and the transparency-log leaf are computed in
 *  exactly one place regardless of tier. */
export interface PreparedAdvisory {
  id: string;
  package: string;
  ranges: string;
  severity: string;
  summary: string;
  details: string;
  url: string;
  patched: string | null;
  withdrawn: boolean;
  tier: AdvisoryTier;
  bundle: string | null;
  upstream_id: string | null;
  upstream_url: string | null;
}

/** Validate the fields common to every tier (id/package/ranges/severity/summary/details/url/patched),
 *  returning them or a 400. Tier-specific fields (bundle, upstream links) are validated by each path. */
export function validateCommon(b: Record<string, unknown>):
  | { id: string; package: string; ranges: string; severity: string; summary: string; details: string; url: string; patched: string | null; withdrawn: boolean }
  | Response {
  const id = b.id;
  const pkg = b.package;
  const ranges = b.ranges;
  const severity = b.severity;
  const summary = b.summary;
  const details = b.details ?? "";
  const url = b.url ?? "";
  const patched = b.patched ?? null;
  const withdrawn = b.withdrawn === true;

  if (!noNewline(id) || !/^[A-Za-z0-9_.-]+$/.test(id as string)) {
    return json({ error: "`id` must be a single-line token of [A-Za-z0-9_.-]" }, 400);
  }
  if (!noNewline(pkg) || !NAME.test(pkg as string)) {
    return json({ error: "`package` must be company/package" }, 400);
  }
  if (!noNewline(ranges) || (ranges as string).length === 0) {
    return json({ error: "`ranges` must be a non-empty single-line SemVer requirement" }, 400);
  }
  if (typeof severity !== "string" || !SEVERITIES.has(severity)) {
    return json({ error: `\`severity\` must be one of ${[...SEVERITIES].join(", ")}` }, 400);
  }
  if (!noNewline(summary) || (summary as string).length === 0) {
    return json({ error: "`summary` must be a non-empty single line" }, 400);
  }
  if (!noNewline(url)) return json({ error: "`url` must be single-line" }, 400);
  if (typeof details !== "string") return json({ error: "`details` must be a string" }, 400);
  if (patched !== null && !noNewline(patched)) {
    return json({ error: "`patched` must be single-line or omitted" }, 400);
  }
  return {
    id: id as string,
    package: pkg as string,
    ranges: ranges as string,
    severity,
    summary: summary as string,
    details,
    url: url as string,
    patched: patched as string | null,
    withdrawn,
  };
}

/** Sign, transparency-log, and store one prepared advisory — the single write path all four intake
 *  tiers converge on. Idempotent per id: re-issuing the same id updates it in place (e.g. to withdraw,
 *  re-scope, or re-import), bumps the feed cursor, re-signs, and appends the new state to the log. */
export async function upsertAdvisory(env: AdvisoryEnv, a: PreparedAdvisory): Promise<{ seq: number; idx: number }> {
  const fields: AdvisoryFields = {
    id: a.id,
    package: a.package,
    ranges: a.ranges,
    severity: a.severity,
    withdrawn: a.withdrawn,
    summary: a.summary,
    details: a.details,
    url: a.url,
    tier: a.tier,
  };
  const record = await canonicalText(fields);
  const signature = toHex(new Uint8Array(await sign(env.ADVISORY_PRIVATE_KEY!, new TextEncoder().encode(record))));

  const now = new Date().toISOString();
  const nextSeq =
    (await env.DB.prepare("SELECT COALESCE(MAX(seq) + 1, 0) AS next FROM advisories").first<{ next: number }>())?.next ??
    0;
  const { idx, leaf } = await log.prepareEntry(env, record);
  await env.DB.batch([
    env.DB
      .prepare(
        "INSERT INTO advisories (id, package, ranges, patched, severity, summary, details, url, withdrawn, seq, signature, log_index, tier, bundle, upstream_id, upstream_url, created_at, updated_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(id) DO UPDATE SET package = excluded.package, ranges = excluded.ranges, patched = excluded.patched, " +
          "severity = excluded.severity, summary = excluded.summary, details = excluded.details, url = excluded.url, " +
          "withdrawn = excluded.withdrawn, seq = excluded.seq, signature = excluded.signature, log_index = excluded.log_index, " +
          "tier = excluded.tier, bundle = excluded.bundle, upstream_id = excluded.upstream_id, upstream_url = excluded.upstream_url, " +
          "updated_at = excluded.updated_at",
      )
      .bind(
        a.id,
        a.package,
        a.ranges,
        a.patched,
        a.severity,
        a.summary,
        a.details,
        a.url,
        a.withdrawn ? 1 : 0,
        nextSeq,
        signature,
        idx,
        a.tier,
        a.bundle,
        a.upstream_id,
        a.upstream_url,
        now,
        now,
      ),
    env.DB
      .prepare("INSERT INTO log (idx, leaf_hash, name, version, record, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(idx, leaf, `advisory:${a.id}`, String(nextSeq), record, now),
  ]);
  return { seq: nextSeq, idx };
}

/** POST /v1/advisories — publish or update an **operator**-tier advisory (admin only; issuing an
 *  operator advisory is an operator action). Idempotent per id. */
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
  const common = validateCommon(body as Record<string, unknown>);
  if (common instanceof Response) return common;

  const { seq, idx } = await upsertAdvisory(env, {
    ...common,
    tier: "operator",
    bundle: null,
    upstream_id: null,
    upstream_url: null,
  });
  return json({ status: "advisory published", id: common.id, tier: "operator", seq, log_index: idx }, 201);
}

/** POST /v1/scopes/{scope}/advisories — publish or update a **publisher**-tier advisory: a scope's own
 *  owner issuing an advisory for a package *in their own scope* (advisory-intake arc, tier 2).
 *
 *  Authenticated exactly like publish — the bearer token must own `{scope}` (see `authorizeScope`) — and
 *  the advisory's `package` must be under that scope, so an owner can only advise their own packages. It
 *  carries a keyless Sigstore `bundle` (required): the scope owner's attestation over the advisory's
 *  canonical bytes, stored verbatim (the registry is not the trust boundary — the consumer verifies the
 *  bundle offline against the scope's pinned keyless identity, exactly like a release bundle). */
export async function publishScopeAdvisory(
  request: Request,
  env: AdvisoryEnv,
  scope: string,
  authorizeScope: (request: Request, env: AdvisoryEnv, company: string) => Promise<Response | true>,
): Promise<Response> {
  if (!env.ADVISORY_PRIVATE_KEY) {
    return json({ error: "the advisory feed is not configured (no signing key)" }, 501);
  }
  const auth = await authorizeScope(request, env, scope);
  if (auth instanceof Response) return auth;

  const body = await readJson(request);
  if (body instanceof Response) return body;
  const common = validateCommon(body as Record<string, unknown>);
  if (common instanceof Response) return common;

  // A scope owner may only advise packages *in their own scope*.
  if (common.package.split("/")[0] !== scope) {
    return json(
      { error: `a publisher advisory's \`package\` must be in scope \`${scope}\` (got \`${common.package}\`)` },
      403,
    );
  }
  // The keyless bundle is the publisher-tier provenance — required, stored verbatim, verified offline
  // by the consumer against the scope's pinned identity (never verified server-side, like a release).
  const rawBundle = (body as Record<string, unknown>).bundle;
  if (typeof rawBundle !== "string" || rawBundle.length === 0) {
    return json({ error: "a publisher advisory must carry a `bundle` (a keyless Sigstore attestation)" }, 400);
  }
  try {
    JSON.parse(rawBundle);
  } catch {
    return json({ error: "`bundle` must be valid JSON (a Sigstore bundle)" }, 400);
  }

  const { seq, idx } = await upsertAdvisory(env, {
    ...common,
    tier: "publisher",
    bundle: rawBundle,
    upstream_id: null,
    upstream_url: null,
  });
  return json({ status: "advisory published", id: common.id, tier: "publisher", seq, log_index: idx }, 201);
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
    tier: r.tier,
    bundle: r.bundle ?? undefined,
    upstream_id: r.upstream_id ?? undefined,
    upstream_url: r.upstream_url ?? undefined,
  };
}

// --- signing / helpers (kept local so this module is self-contained) ------------------------------

const noNewline = (s: unknown): s is string => typeof s === "string" && !/[\n\r]/.test(s);

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

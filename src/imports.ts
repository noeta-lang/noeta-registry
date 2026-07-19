// Imported advisory feeds (advisory-intake arc, tier 3). Advisories mirrored from an external ecosystem
// database — OSV, GHSA, RUSTSEC — mapped onto Noeta package identities via the operator-curated
// `name_mappings` table. An imported advisory is marked `tier = imported` and carries its upstream
// provenance (the upstream id + a link), so a consumer sees exactly where it came from.
//
// The registry automates provenance, never judgment: the *mapping* (this external package IS this Noeta
// package) is a human decision recorded by an operator; the import itself only applies those mappings
// to upstream records. An upstream record for a package with no mapping is **skipped**, never guessed.
//
// Idempotent per upstream id: the derived advisory id is a function of the upstream id (and the mapped
// package, when one record maps to several), so a re-import — manual or the scheduled cron — updates in
// place rather than duplicating.

import { upsertAdvisory, AdvisoryEnv } from "./advisory";
import { scoreVector } from "./cvss";

export interface ImportEnv extends AdvisoryEnv {
  DB: D1Database;
  ADMIN_TOKEN?: string;
  // Per-source upstream adapters (advisory-intake residual c; see sources.ts). Each is independently
  // gated — an unset source is a no-op, never an error — so an operator turns on exactly the feeds they
  // want. All are queried against the operator-curated name map; only mapped packages ever import.
  //   • OSV (api.osv.dev): on by default; `OSV_API=off` disables. `OSV_API_URL` overrides the endpoint.
  //   • GHSA (GitHub GraphQL): needs `GITHUB_TOKEN` (absent → skip). `GITHUB_GRAPHQL_URL` overrides.
  //   • RUSTSEC: its published OSV feed at `RUSTSEC_IMPORT_URL` (absent → skip).
  OSV_API?: string;
  OSV_API_URL?: string;
  GITHUB_TOKEN?: string;
  GITHUB_GRAPHQL_URL?: string;
  RUSTSEC_IMPORT_URL?: string;
  // A single pre-assembled OSV feed (a JSON array of OSV records) — the manual/testing override, kept
  // working alongside the per-source adapters for backfills and one-off imports.
  OSV_IMPORT_URL?: string;
}

/** One operator-curated name mapping (external ecosystem package → Noeta package). The source adapters
 *  read these to query only the mapped set. */
export interface NameMapping {
  ecosystem: string;
  external_name: string;
  noeta_package: string;
}

/** The operator-curated name map — the exact set of upstream packages the adapters query for. */
export async function fetchMappings(env: ImportEnv): Promise<NameMapping[]> {
  return (
    (await env.DB.prepare("SELECT ecosystem, external_name, noeta_package FROM name_mappings").all<NameMapping>())
      .results ?? []
  );
}

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const ID_CHARSET = /^[A-Za-z0-9_.-]+$/;

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}
interface OsvRange {
  type?: string;
  events?: OsvEvent[];
}
interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: OsvRange[];
}
/** An OSV `severity[]` entry: a scoring `type` (we honour `CVSS_V3`) and a `score` field which — for a
 *  CVSS entry — holds the vector *string* (the OSV schema's confusing name for it). */
interface OsvSeverity {
  type?: string;
  score?: string;
}
export interface OsvRecord {
  id?: string;
  summary?: string;
  details?: string;
  withdrawn?: string;
  severity?: OsvSeverity[] | string | unknown;
  database_specific?: { severity?: string };
  affected?: OsvAffected[];
  references?: { url?: string }[];
}

/** POST /v1/name-mappings — add (or update) an operator-curated mapping (admin only). Body
 *  `{ ecosystem, external_name, noeta_package }`. This is the human judgment the import layer applies. */
export async function addNameMapping(request: Request, env: ImportEnv): Promise<Response> {
  const presented = bearer(request);
  if (!env.ADMIN_TOKEN || !presented || !timingEqual(presented, env.ADMIN_TOKEN)) {
    return json({ error: "admin token required" }, 401);
  }
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const b = body as Record<string, unknown>;
  const ecosystem = b.ecosystem;
  const externalName = b.external_name;
  const noetaPackage = b.noeta_package;
  if (!noNewline(ecosystem) || (ecosystem as string).length === 0) {
    return json({ error: "`ecosystem` must be a non-empty single-line string" }, 400);
  }
  if (!noNewline(externalName) || (externalName as string).length === 0) {
    return json({ error: "`external_name` must be a non-empty single-line string" }, 400);
  }
  if (!noNewline(noetaPackage) || !NAME.test(noetaPackage as string)) {
    return json({ error: "`noeta_package` must be company/package" }, 400);
  }
  await env.DB.prepare(
    "INSERT INTO name_mappings (ecosystem, external_name, noeta_package, created_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(ecosystem, external_name) DO UPDATE SET noeta_package = excluded.noeta_package",
  )
    .bind(ecosystem, externalName, noetaPackage, new Date().toISOString())
    .run();
  return json({ status: "mapping registered", ecosystem, external_name: externalName, noeta_package: noetaPackage }, 201);
}

/** GET /v1/name-mappings — the operator-curated mappings (public: transparency about how imports map). */
export async function listNameMappings(env: ImportEnv): Promise<Response> {
  const rows =
    (
      await env.DB.prepare("SELECT ecosystem, external_name, noeta_package FROM name_mappings ORDER BY ecosystem, external_name").all<{
        ecosystem: string;
        external_name: string;
        noeta_package: string;
      }>()
    ).results ?? [];
  return json({ mappings: rows });
}

/** POST /v1/advisories/import — import a batch of OSV-format records (admin only). Body
 *  `{ advisories: [<osv record>, …] }`. Each record is mapped through `name_mappings`; unmapped
 *  packages are skipped. Returns `{ imported, skipped }`. */
export async function importAdvisoriesFromRequest(request: Request, env: ImportEnv): Promise<Response> {
  const presented = bearer(request);
  if (!env.ADMIN_TOKEN || !presented || !timingEqual(presented, env.ADMIN_TOKEN)) {
    return json({ error: "admin token required" }, 401);
  }
  if (!env.ADVISORY_PRIVATE_KEY) {
    return json({ error: "the advisory feed is not configured (no signing key)" }, 501);
  }
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const records = (body as Record<string, unknown>).advisories;
  if (!Array.isArray(records)) {
    return json({ error: "body must be { advisories: [<osv record>, …] }" }, 400);
  }
  const result = await importRecords(env, records as OsvRecord[]);
  return json({ status: "import complete", ...result }, 200);
}

/** Map + upsert a batch of OSV records. Shared by the manual admin path and the scheduled cron. Returns
 *  the count imported (mapped and written) and skipped (no mapping, or unusable record). */
export async function importRecords(
  env: ImportEnv,
  records: OsvRecord[],
): Promise<{ imported: number; skipped: number }> {
  let imported = 0;
  let skipped = 0;
  for (const rec of records) {
    const upstreamId = rec.id;
    if (typeof upstreamId !== "string" || !ID_CHARSET.test(upstreamId)) {
      skipped++;
      continue;
    }
    const affected = Array.isArray(rec.affected) ? rec.affected : [];
    // Collect the distinct Noeta packages this record maps to.
    const mapped: { noeta: string; ranges: string; patched: string | null }[] = [];
    for (const aff of affected) {
      const ecosystem = aff.package?.ecosystem;
      const name = aff.package?.name;
      if (typeof ecosystem !== "string" || typeof name !== "string") continue;
      const row = await env.DB.prepare("SELECT noeta_package FROM name_mappings WHERE ecosystem = ? AND external_name = ?")
        .bind(ecosystem, name)
        .first<{ noeta_package: string }>();
      if (!row) continue;
      const { ranges, patched } = deriveRange(aff.ranges);
      if (!mapped.some((m) => m.noeta === row.noeta_package)) {
        mapped.push({ noeta: row.noeta_package, ranges, patched });
      }
    }
    if (mapped.length === 0) {
      skipped++;
      continue;
    }
    const { severity, cvss } = severityOf(rec);
    const summary = (rec.summary ?? rec.details ?? upstreamId).split(/[\n\r]/)[0].slice(0, 200) || upstreamId;
    const details = typeof rec.details === "string" ? rec.details : "";
    const url = referenceUrl(rec, upstreamId);
    const withdrawn = typeof rec.withdrawn === "string" && rec.withdrawn.length > 0;

    for (const m of mapped) {
      // One record may map to several Noeta packages; the advisory id stays a deterministic function of
      // the upstream id (suffixed by the package when there is more than one), so re-import is idempotent.
      const id = mapped.length === 1 ? upstreamId : `${upstreamId}~${m.noeta.replace("/", "-")}`;
      await upsertAdvisory(env, {
        id,
        package: m.noeta,
        ranges: m.ranges,
        severity,
        summary,
        details,
        url,
        patched: m.patched,
        withdrawn,
        tier: "imported",
        bundle: null,
        upstream_id: upstreamId,
        upstream_url: url,
        cvss,
      });
      imported++;
    }
  }
  return { imported, skipped };
}

/** The scheduled-cron entry (advisory-intake residual c): pull every configured upstream source (OSV,
 *  GHSA, RUSTSEC, and the manual `OSV_IMPORT_URL` override) via the per-ecosystem adapters, then import
 *  the combined, de-duplicated records through the name map. A no-op when no source is configured.
 *  Idempotent per upstream id, so a repeated run refreshes rather than duplicating. */
export async function runScheduledImport(env: ImportEnv): Promise<{ imported: number; skipped: number }> {
  // Imported lazily to avoid a cycle (sources.ts imports the shared types from here).
  const { collectFromSources } = await import("./sources");
  const records = await collectFromSources(env);
  return importRecords(env, records);
}

// --- OSV field extraction -------------------------------------------------------------------------

/** Turn an OSV affected-package's SEMVER ranges into a single SemVer requirement string and a patched
 *  version. OSV expresses a range as ordered `introduced`/`fixed` events; we take the first usable range
 *  (`>=introduced, <fixed`). A record with no derivable range yields `>=0.0.0` (matches all) rather than
 *  dropping the advisory — an over-broad flag is safer than a silent miss, and the operator can re-scope. */
function deriveRange(ranges: OsvRange[] | undefined): { ranges: string; patched: string | null } {
  for (const r of ranges ?? []) {
    if (r.type && r.type !== "SEMVER") continue;
    let introduced: string | null = null;
    let fixed: string | null = null;
    for (const ev of r.events ?? []) {
      // OSV's `introduced: "0"` is the sentinel for "from the beginning" — no lower bound to emit.
      if (typeof ev.introduced === "string" && ev.introduced !== "0" && ev.introduced !== "0.0.0") {
        introduced = ev.introduced;
      }
      if (typeof ev.fixed === "string") fixed = ev.fixed;
    }
    const parts: string[] = [];
    if (introduced) parts.push(`>=${introduced}`);
    if (fixed) parts.push(`<${fixed}`);
    if (parts.length > 0) return { ranges: parts.join(", "), patched: fixed };
  }
  return { ranges: ">=0.0.0", patched: null };
}

/** Derive an imported advisory's severity band (and the CVSS vector it came from, when any). A CVSS
 *  v3.x vector — computed honestly to a base score — is the strongest signal and is preferred: it gives
 *  the canonical band *and* the vector is kept so a consumer can re-derive the score. The OSV `severity[]`
 *  array carries CVSS entries (`{ type: "CVSS_V3", score: "<vector>" }`); the GHSA adapter maps
 *  `cvss.vectorString` into the same shape. Falls back to the textual `database_specific.severity`
 *  (LOW/MODERATE/HIGH/CRITICAL), then an explicit `severity` string, else `medium`. A CVSS score of 0.0
 *  ("none" band) is treated as no signal — the text fallback wins, since an imported record is a real
 *  advisory and shouldn't land below `low`. */
function severityOf(rec: OsvRecord): { severity: string; cvss: string | null } {
  if (Array.isArray(rec.severity)) {
    for (const entry of rec.severity as OsvSeverity[]) {
      if (entry?.type === "CVSS_V3" && typeof entry.score === "string") {
        const scored = scoreVector(entry.score);
        if (scored && scored.band !== "none") {
          return { severity: scored.band, cvss: entry.score };
        }
      }
    }
  }
  const text = rec.database_specific?.severity;
  if (typeof text === "string") {
    const t = text.toLowerCase();
    if (t === "moderate") return { severity: "medium", cvss: null };
    if (SEVERITIES.has(t)) return { severity: t, cvss: null };
  }
  if (typeof rec.severity === "string" && SEVERITIES.has(rec.severity.toLowerCase())) {
    return { severity: rec.severity.toLowerCase(), cvss: null };
  }
  return { severity: "medium", cvss: null };
}

/** The best link for an imported advisory: the first reference url, else the OSV canonical page. */
function referenceUrl(rec: OsvRecord, upstreamId: string): string {
  for (const ref of rec.references ?? []) {
    if (typeof ref.url === "string" && /^https?:\/\//.test(ref.url)) return ref.url;
  }
  return `https://osv.dev/vulnerability/${upstreamId}`;
}

// --- helpers --------------------------------------------------------------------------------------

const noNewline = (s: unknown): s is string => typeof s === "string" && !/[\n\r]/.test(s);
const NAME = /^[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z_][A-Za-z0-9_]*$/;

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

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

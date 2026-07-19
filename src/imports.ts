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

export interface ImportEnv extends AdvisoryEnv {
  DB: D1Database;
  ADMIN_TOKEN?: string;
  // The OSV-format feed the scheduled cron pulls (a JSON array of OSV records). Absent → the cron is a
  // no-op and only the manual admin import path runs.
  OSV_IMPORT_URL?: string;
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
interface OsvRecord {
  id?: string;
  summary?: string;
  details?: string;
  withdrawn?: string;
  severity?: unknown;
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
    const severity = severityOf(rec);
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
      });
      imported++;
    }
  }
  return { imported, skipped };
}

/** The scheduled-cron entry: pull the configured OSV feed and import it. A no-op when `OSV_IMPORT_URL`
 *  is unset. Errors are surfaced to the caller (the cron handler logs them). */
export async function runScheduledImport(env: ImportEnv): Promise<{ imported: number; skipped: number }> {
  if (!env.OSV_IMPORT_URL) return { imported: 0, skipped: 0 };
  const resp = await fetch(env.OSV_IMPORT_URL, { headers: { accept: "application/json" } });
  if (!resp.ok) throw new Error(`OSV feed ${env.OSV_IMPORT_URL} returned ${resp.status}`);
  const payload = (await resp.json()) as unknown;
  // Accept either a bare array of records or `{ advisories: [...] }`.
  const records = Array.isArray(payload)
    ? payload
    : Array.isArray((payload as Record<string, unknown>)?.advisories)
      ? ((payload as Record<string, unknown>).advisories as unknown[])
      : [];
  return importRecords(env, records as OsvRecord[]);
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

/** Map an OSV/GHSA severity to the feed's `low|medium|high|critical`. Prefers GHSA's textual
 *  `database_specific.severity` (LOW/MODERATE/HIGH/CRITICAL), then an explicit `severity` string, else
 *  `medium`. CVSS-vector scoring is deliberately out of scope — the operator can re-scope on review. */
function severityOf(rec: OsvRecord): string {
  const text = rec.database_specific?.severity;
  if (typeof text === "string") {
    const t = text.toLowerCase();
    if (t === "moderate") return "medium";
    if (SEVERITIES.has(t)) return t;
  }
  if (typeof rec.severity === "string" && SEVERITIES.has(rec.severity.toLowerCase())) {
    return rec.severity.toLowerCase();
  }
  return "medium";
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

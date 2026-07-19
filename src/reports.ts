// Public report queue (advisory-intake arc, tier 4 — intake ONLY). Anyone may *file* a report that a
// package looks vulnerable or malicious; a report is never an advisory and never appears in the signed
// advisory feed. A report becomes an advisory only when an operator (admin token) or the package's own
// scope owner (scope publish token) **promotes** it — the arc's rule: automate provenance, never
// judgment. Intake is unauthenticated but **rate-limited** by a hash of the reporter's IP, so the open
// surface can't be flooded.

import { upsertAdvisory, validateCommon, AdvisoryEnv, AdvisoryTier } from "./advisory";

export interface ReportEnv extends AdvisoryEnv {
  DB: D1Database;
  ADMIN_TOKEN?: string;
  // Max reports one IP may file per hour (default 5). A flood-control valve, not an account model.
  REPORT_RATE_LIMIT?: string;
}

interface ReportRow {
  id: string;
  package: string;
  ranges: string;
  summary: string;
  details: string;
  url: string;
  reporter: string;
  status: string;
  advisory_id: string | null;
  created_at: string;
  updated_at: string;
}

const DEFAULT_RATE_LIMIT = 5;
const MAX_DETAILS = 8192;

/** POST /v1/reports — file a report (unauthenticated, rate-limited). The body is a package + a one-line
 *  summary, plus optional affected `ranges`, `details`, `url`, and a self-identifying `reporter`. The
 *  response returns only the opaque report id and a note that it is queued for triage — never a promise
 *  that an advisory will follow (that is a human judgment). */
export async function fileReport(request: Request, env: ReportEnv): Promise<Response> {
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const b = body as Record<string, unknown>;

  const pkg = b.package;
  const summary = b.summary;
  const ranges = b.ranges ?? "";
  const details = b.details ?? "";
  const url = b.url ?? "";
  const reporter = b.reporter ?? "";

  if (!noNewline(pkg) || !NAME.test(pkg as string)) {
    return json({ error: "`package` must be company/package" }, 400);
  }
  if (!noNewline(summary) || (summary as string).length === 0 || (summary as string).length > 200) {
    return json({ error: "`summary` must be a non-empty single line of ≤ 200 chars" }, 400);
  }
  if (!noNewline(ranges)) return json({ error: "`ranges` must be single-line or omitted" }, 400);
  if (!noNewline(url)) return json({ error: "`url` must be single-line or omitted" }, 400);
  if (!noNewline(reporter) || (reporter as string).length > 200) {
    return json({ error: "`reporter` must be a single line of ≤ 200 chars or omitted" }, 400);
  }
  if (typeof details !== "string" || details.length > MAX_DETAILS) {
    return json({ error: `\`details\` must be a string of ≤ ${MAX_DETAILS} chars` }, 400);
  }

  // Rate-limit by a hash of the reporter's IP over a one-hour window. The raw IP is never stored or
  // served — only its SHA-256, used solely to count recent reports.
  const ip = request.headers.get("CF-Connecting-IP") ?? request.headers.get("X-Forwarded-For") ?? "";
  const ipHash = await sha256hex(ip);
  const limit = Number(env.REPORT_RATE_LIMIT ?? "") || DEFAULT_RATE_LIMIT;
  const oneHourAgo = new Date(Date.now() - 3600_000).toISOString();
  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE ip_hash = ? AND created_at > ?")
    .bind(ipHash, oneHourAgo)
    .first<{ n: number }>();
  if (ipHash !== (await sha256hex("")) && (recent?.n ?? 0) >= limit) {
    return json({ error: `report rate limit reached (${limit}/hour) — try again later` }, 429);
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO reports (id, package, ranges, summary, details, url, reporter, status, advisory_id, ip_hash, created_at, updated_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, ?, ?)",
  )
    .bind(id, pkg, ranges, summary, details, url, reporter, ipHash, now, now)
    .run();
  return json(
    { status: "report filed", id, note: "queued for triage — a report is not an advisory until it is promoted" },
    201,
  );
}

/** GET /v1/reports[?status=pending] — the triage queue (admin only). Never public: a report is
 *  unverified, possibly a false alarm or an attack on a healthy package, so it is only ever visible to
 *  the operator triaging it (or, via `?package=`, a scope owner triaging their own — checked at the
 *  route). `ip_hash` is never included. */
export async function listReports(
  env: ReportEnv,
  statusFilter: string | null,
  pkgFilter: string | null,
  scopeFilter: string | null = null,
): Promise<Response> {
  const clauses: string[] = [];
  const binds: string[] = [];
  if (statusFilter !== null) {
    if (!["pending", "promoted", "dismissed"].includes(statusFilter)) {
      return json({ error: "`status` must be pending, promoted, or dismissed" }, 400);
    }
    clauses.push("status = ?");
    binds.push(statusFilter);
  }
  if (pkgFilter !== null) {
    clauses.push("package = ?");
    binds.push(pkgFilter);
  }
  if (scopeFilter !== null) {
    // Reports for a scope's own packages. A scope is an identifier (no GLOB metacharacters), and GLOB
    // — unlike LIKE — does not treat `_` as a wildcard, which identifiers contain.
    clauses.push("package GLOB ?");
    binds.push(`${scopeFilter}/*`);
  }
  const where = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
  const rows =
    (await env.DB.prepare(`SELECT * FROM reports${where} ORDER BY created_at`).bind(...binds).all<ReportRow>()).results ??
    [];
  return json({ reports: rows.map(toWire) });
}

/** GET /v1/reports/{id} — one report by id, for a promoter to fetch-and-prefill (advisory-intake
 *  residual a). Authorized as the **operator** (admin token) or the **scope owner** of the report's own
 *  package (scope publish token) — the same two identities that may promote it. Never public (a report
 *  is unverified); `ip_hash` is never included. */
export async function getReport(
  request: Request,
  env: ReportEnv,
  id: string,
  authorizeScope: (request: Request, env: AdvisoryEnv, company: string) => Promise<Response | true>,
): Promise<Response> {
  const report = await env.DB.prepare("SELECT * FROM reports WHERE id = ?").bind(id).first<ReportRow>();
  if (!report) return json({ error: `report \`${id}\` not found` }, 404);
  const presented = bearer(request);
  const isAdmin = !!env.ADMIN_TOKEN && !!presented && timingEqual(presented, env.ADMIN_TOKEN);
  if (!isAdmin) {
    const scope = report.package.split("/")[0];
    const auth = await authorizeScope(request, env, scope);
    if (auth instanceof Response) return auth;
  }
  return json({ report: toWire(report) });
}

/** POST /v1/reports/{id}/promote — turn a report into an advisory. Authenticated as either an
 *  **operator** (admin token → an `operator`-tier advisory) or the **scope owner** of the report's
 *  package (scope publish token → a `publisher`-tier advisory, which must carry a keyless `bundle`). The
 *  body carries the *triaged* advisory fields — a report is raw intake; the promoter supplies the real
 *  id, range, severity, and summary. Marks the report `promoted` and records the advisory id it
 *  produced. */
export async function promoteReport(
  request: Request,
  env: ReportEnv,
  id: string,
  authorizeScope: (request: Request, env: AdvisoryEnv, company: string) => Promise<Response | true>,
): Promise<Response> {
  if (!env.ADVISORY_PRIVATE_KEY) {
    return json({ error: "the advisory feed is not configured (no signing key)" }, 501);
  }
  const report = await env.DB.prepare("SELECT * FROM reports WHERE id = ?").bind(id).first<ReportRow>();
  if (!report) return json({ error: `report \`${id}\` not found` }, 404);
  if (report.status !== "pending") {
    return json({ error: `report \`${id}\` is already ${report.status}` }, 409);
  }

  const body = await readJson(request);
  if (body instanceof Response) return body;
  const common = validateCommon(body as Record<string, unknown>);
  if (common instanceof Response) return common;
  // The promoted advisory must be about the reported package (the promoter can't redirect a report at a
  // different package).
  if (common.package !== report.package) {
    return json(
      { error: `the advisory's \`package\` (${common.package}) must match the report's (${report.package})` },
      400,
    );
  }

  // Determine the promoter: the admin token → an operator advisory; else the scope owner of the
  // package → a publisher advisory (which requires a keyless bundle, like a direct publisher advisory).
  const presented = bearer(request);
  const isAdmin = !!env.ADMIN_TOKEN && !!presented && timingEqual(presented, env.ADMIN_TOKEN);
  let tier: AdvisoryTier;
  let bundle: string | null = null;
  if (isAdmin) {
    tier = "operator";
  } else {
    const scope = report.package.split("/")[0];
    const auth = await authorizeScope(request, env, scope);
    if (auth instanceof Response) return auth;
    tier = "publisher";
    const rawBundle = (body as Record<string, unknown>).bundle;
    if (typeof rawBundle !== "string" || rawBundle.length === 0) {
      return json({ error: "a scope owner's promotion is a publisher advisory and must carry a `bundle`" }, 400);
    }
    try {
      JSON.parse(rawBundle);
    } catch {
      return json({ error: "`bundle` must be valid JSON (a Sigstore bundle)" }, 400);
    }
    bundle = rawBundle;
  }

  const { seq, idx } = await upsertAdvisory(env, {
    ...common,
    tier,
    bundle,
    upstream_id: null,
    upstream_url: null,
    cvss: null,
  });
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE reports SET status = 'promoted', advisory_id = ?, updated_at = ? WHERE id = ?")
    .bind(common.id, now, id)
    .run();
  return json({ status: "report promoted", report: id, advisory: common.id, tier, seq, log_index: idx }, 201);
}

/** POST /v1/reports/{id}/dismiss — close a report without issuing an advisory (admin only; a false
 *  alarm or a duplicate). The report is kept (never deleted) with `status = dismissed`. */
export async function dismissReport(request: Request, env: ReportEnv, id: string): Promise<Response> {
  const presented = bearer(request);
  if (!env.ADMIN_TOKEN || !presented || !timingEqual(presented, env.ADMIN_TOKEN)) {
    return json({ error: "admin token required" }, 401);
  }
  const now = new Date().toISOString();
  const res = await env.DB.prepare("UPDATE reports SET status = 'dismissed', updated_at = ? WHERE id = ? AND status = 'pending'")
    .bind(now, id)
    .run();
  if (!res.meta || res.meta.changes === 0) {
    const exists = await env.DB.prepare("SELECT status FROM reports WHERE id = ?").bind(id).first<{ status: string }>();
    if (!exists) return json({ error: `report \`${id}\` not found` }, 404);
    return json({ error: `report \`${id}\` is already ${exists.status}` }, 409);
  }
  return json({ status: "report dismissed", id });
}

function toWire(r: ReportRow) {
  return {
    id: r.id,
    package: r.package,
    ranges: r.ranges || undefined,
    summary: r.summary,
    details: r.details || undefined,
    url: r.url || undefined,
    reporter: r.reporter || undefined,
    status: r.status,
    advisory_id: r.advisory_id ?? undefined,
    created_at: r.created_at,
  };
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

async function sha256hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
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

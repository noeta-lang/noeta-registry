// Per-ecosystem upstream source adapters (advisory-intake residual c). The scheduled cron pulls real
// upstream advisory databases — OSV, GHSA, RUSTSEC — and hands their records to the shared import path
// (`imports.ts`), which maps them onto Noeta package identities through the operator-curated name map
// and skips anything unmapped. Each adapter yields OSV-format records; the import layer is unchanged.
//
// Operating on Cloudflare Workers (the cron runs in the `scheduled` handler, which shares the ~1000-
// subrequest budget of a Bundled Worker — 50 on the Free plan) shapes the design:
//
//   • OSV (api.osv.dev) and GHSA (GitHub GraphQL) are queried **per mapped package**, not swept whole.
//     The set we import is exactly the operator-curated name map — small and human-sized — so bounding
//     the query to it keeps subrequests proportional to the curated set (not to the millions of records
//     upstream), and matches the arc's principle: only mapped packages ever import. OSV's per-package
//     `POST /v1/query` returns full records (no second per-id fetch), and GHSA's `securityVulnerabilities`
//     filters server-side by (ecosystem, package). Both paginate; we cap pages per query as a backstop.
//   • RUSTSEC is a single published OSV feed (env-configured URL), streamed with page/`next` pagination
//     and a page cap. (RustSec is also mirrored into OSV, so the OSV adapter already covers crates.io;
//     the dedicated feed is for operators who want RustSec directly / independently of osv.dev.)
//
// Every adapter is idempotent through the import layer (dedup per upstream id) and fully env-gated: an
// adapter with no configuration (no token, no URL) is a no-op, never an error. `OSV_IMPORT_URL` stays a
// manual single-feed override for testing and one-off backfills.
//
// All network access is `fetch`; tests stub it (cloudflare:test `fetchMock`) — nothing here hits a real
// network in the suite.

import { ImportEnv, OsvRecord, fetchMappings, NameMapping } from "./imports";

/** A per-query page cap — a backstop against an upstream that paginates unboundedly, keeping the cron's
 *  subrequest use predictable regardless of upstream volume. */
const MAX_PAGES = 20;

const USER_AGENT = "noeta-registry-advisory-import/1";

/** Gather OSV-format records from every configured upstream source. Called by the scheduled cron. Each
 *  source is best-effort and independent: one failing (a 500, a bad token) is logged and skipped so the
 *  others still import. Records are de-duplicated by upstream id (an advisory mirrored in two sources —
 *  e.g. a RustSec advisory present both in its own feed and via OSV — imports once). */
export async function collectFromSources(env: ImportEnv): Promise<OsvRecord[]> {
  const mappings = await fetchMappings(env);
  const byId = new Map<string, OsvRecord>();
  const add = (records: OsvRecord[]) => {
    for (const r of records) {
      if (typeof r.id === "string" && !byId.has(r.id)) byId.set(r.id, r);
    }
  };

  const sources: [string, () => Promise<OsvRecord[]>][] = [
    ["OSV", () => osvApiSource(env, mappings)],
    ["GHSA", () => ghsaSource(env, mappings)],
    ["RUSTSEC", () => rustsecSource(env)],
    ["OSV_IMPORT_URL", () => manualFeedSource(env)],
  ];
  for (const [name, run] of sources) {
    try {
      add(await run());
    } catch (err) {
      console.error(`advisory source ${name} failed: ${String(err)}`);
    }
  }
  return [...byId.values()];
}

// --- OSV (api.osv.dev) -----------------------------------------------------------------------------

/** api.osv.dev per-package query. For each mapped package, `POST /v1/query` returns the full OSV records
 *  affecting it; `page_token` in the response drives pagination. Enabled by default; set `OSV_API=off`
 *  to disable. `OSV_API_URL` overrides the endpoint (tests point it at the mock). */
export async function osvApiSource(env: ImportEnv, mappings: NameMapping[]): Promise<OsvRecord[]> {
  if ((env.OSV_API ?? "").toLowerCase() === "off") return [];
  const base = env.OSV_API_URL ?? "https://api.osv.dev";
  const out: OsvRecord[] = [];
  for (const m of mappings) {
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const body: Record<string, unknown> = { package: { ecosystem: m.ecosystem, name: m.external_name } };
      if (pageToken) body.page_token = pageToken;
      const resp = await fetch(`${base}/v1/query`, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": USER_AGENT },
        body: JSON.stringify(body),
      });
      if (!resp.ok) throw new Error(`osv.dev /v1/query for ${m.ecosystem}:${m.external_name} → ${resp.status}`);
      const payload = (await resp.json()) as { vulns?: OsvRecord[]; next_page_token?: string };
      for (const v of payload.vulns ?? []) out.push(v);
      pageToken = payload.next_page_token;
      if (!pageToken) break;
    }
  }
  return out;
}

// --- GHSA (GitHub GraphQL security-advisories) -----------------------------------------------------

// OSV ecosystem name → GitHub `SecurityAdvisoryEcosystem` enum. Only ecosystems GitHub tracks appear;
// a mapping in an ecosystem GitHub doesn't cover is simply not queried against GHSA.
const GHSA_ECOSYSTEM: Record<string, string> = {
  "crates.io": "RUST",
  npm: "NPM",
  PyPI: "PIP",
  Go: "GO",
  RubyGems: "RUBYGEMS",
  Maven: "MAVEN",
  NuGet: "NUGET",
  Packagist: "COMPOSER",
  Pub: "PUB",
  Hex: "ERLANG",
};

interface GhsaVulnerability {
  vulnerableVersionRange?: string;
  firstPatchedVersion?: { identifier?: string } | null;
  package?: { name?: string };
  advisory?: {
    ghsaId?: string;
    summary?: string;
    description?: string;
    withdrawnAt?: string | null;
    permalink?: string;
    references?: { url?: string }[];
    cvss?: { vectorString?: string | null } | null;
  };
}

/** GHSA via the GitHub GraphQL `securityVulnerabilities` connection, filtered server-side by (ecosystem,
 *  package) for each mapped package. `GITHUB_TOKEN` gates the whole source — absent → skip (GHSA needs
 *  auth). `GITHUB_GRAPHQL_URL` overrides the endpoint for tests. Each GHSA vulnerability becomes an OSV
 *  record carrying the advisory's CVSS vector (so the import derives the honest band). */
export async function ghsaSource(env: ImportEnv, mappings: NameMapping[]): Promise<OsvRecord[]> {
  const token = env.GITHUB_TOKEN;
  if (!token) return [];
  const endpoint = env.GITHUB_GRAPHQL_URL ?? "https://api.github.com/graphql";
  const out: OsvRecord[] = [];
  for (const m of mappings) {
    const ecosystem = GHSA_ECOSYSTEM[m.ecosystem];
    if (!ecosystem) continue;
    let after: string | null = null;
    for (let page = 0; page < MAX_PAGES; page++) {
      const query = `query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $after: String) {
        securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 100, after: $after) {
          pageInfo { hasNextPage endCursor }
          nodes {
            vulnerableVersionRange
            firstPatchedVersion { identifier }
            package { name }
            advisory { ghsaId summary description withdrawnAt permalink references { url } cvss { vectorString } }
          }
        }
      }`;
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "user-agent": USER_AGENT,
        },
        body: JSON.stringify({ query, variables: { ecosystem, package: m.external_name, after } }),
      });
      if (!resp.ok) throw new Error(`GitHub GraphQL for ${ecosystem}:${m.external_name} → ${resp.status}`);
      const payload = (await resp.json()) as {
        data?: { securityVulnerabilities?: { pageInfo?: { hasNextPage?: boolean; endCursor?: string }; nodes?: GhsaVulnerability[] } };
        errors?: { message?: string }[];
      };
      if (payload.errors?.length) throw new Error(`GitHub GraphQL error: ${payload.errors[0].message ?? "unknown"}`);
      const conn = payload.data?.securityVulnerabilities;
      for (const node of conn?.nodes ?? []) {
        const rec = ghsaToOsv(node, m.ecosystem);
        if (rec) out.push(rec);
      }
      if (!conn?.pageInfo?.hasNextPage || !conn.pageInfo.endCursor) break;
      after = conn.pageInfo.endCursor;
    }
  }
  return out;
}

/** Map one GHSA `securityVulnerabilities` node onto an OSV record in the ecosystem the mapping named, so
 *  the shared import path handles it identically to a native OSV record. The GHSA CVSS vector is carried
 *  in an OSV `severity[]` CVSS_V3 entry. */
function ghsaToOsv(node: GhsaVulnerability, osvEcosystem: string): OsvRecord | null {
  const adv = node.advisory;
  if (!adv?.ghsaId) return null;
  const vector = adv.cvss?.vectorString;
  return {
    id: adv.ghsaId,
    summary: adv.summary,
    details: adv.description,
    withdrawn: adv.withdrawnAt ?? undefined,
    severity: vector ? [{ type: "CVSS_V3", score: vector }] : undefined,
    affected: [
      {
        package: { ecosystem: osvEcosystem, name: node.package?.name },
        ranges: [{ type: "SEMVER", events: ghsaRangeToEvents(node.vulnerableVersionRange, node.firstPatchedVersion?.identifier) }],
      },
    ],
    references: [
      ...(adv.permalink ? [{ url: adv.permalink }] : []),
      ...(adv.references ?? []),
    ],
  };
}

/** Convert a GHSA `vulnerableVersionRange` (e.g. `">= 1.0.0, < 1.2.0"`, `"<= 1.4.0"`, `"= 2.0.1"`) plus
 *  an optional first-patched version into OSV `introduced`/`fixed` events, so the existing OSV range
 *  derivation produces the same range string as a native OSV record would. */
function ghsaRangeToEvents(range: string | undefined, firstPatched: string | undefined): { introduced?: string; fixed?: string }[] {
  const events: { introduced?: string; fixed?: string }[] = [{ introduced: "0" }];
  for (const part of (range ?? "").split(",")) {
    const t = part.trim();
    const lower = t.match(/^>=?\s*([0-9][0-9A-Za-z.+-]*)$/);
    const upper = t.match(/^<\s*([0-9][0-9A-Za-z.+-]*)$/);
    if (lower) events[0].introduced = lower[1];
    else if (upper) events.push({ fixed: upper[1] });
  }
  // A first-patched version is the canonical fixed boundary when the range didn't carry an exclusive one.
  if (firstPatched && !events.some((e) => e.fixed)) events.push({ fixed: firstPatched });
  return events;
}

// --- RUSTSEC (published OSV feed) ------------------------------------------------------------------

/** RUSTSEC via its published OSV export. `RUSTSEC_IMPORT_URL` is the feed URL (absent → skip). The feed
 *  is a JSON array of OSV records or `{ advisories: [...] }` / `{ vulns: [...] }`; pagination follows a
 *  `next_page_token` (as a `?page_token=` query) or a `next` URL in the payload, capped at MAX_PAGES. */
export async function rustsecSource(env: ImportEnv): Promise<OsvRecord[]> {
  const url = env.RUSTSEC_IMPORT_URL;
  if (!url) return [];
  const out: OsvRecord[] = [];
  let next: string | null = url;
  for (let page = 0; page < MAX_PAGES && next; page++) {
    const resp = await fetch(next, { headers: { accept: "application/json", "user-agent": USER_AGENT } });
    if (!resp.ok) throw new Error(`RUSTSEC feed ${next} → ${resp.status}`);
    const payload = (await resp.json()) as unknown;
    for (const r of recordsOf(payload)) out.push(r);
    next = nextPage(payload, next);
  }
  return out;
}

// --- manual OSV_IMPORT_URL override ---------------------------------------------------------------

/** The pre-arc single-feed override: pull `OSV_IMPORT_URL` (a JSON array, or `{ advisories: [...] }`).
 *  Kept for manual backfills and testing; no pagination (a single assembled feed). */
export async function manualFeedSource(env: ImportEnv): Promise<OsvRecord[]> {
  if (!env.OSV_IMPORT_URL) return [];
  const resp = await fetch(env.OSV_IMPORT_URL, { headers: { accept: "application/json", "user-agent": USER_AGENT } });
  if (!resp.ok) throw new Error(`OSV feed ${env.OSV_IMPORT_URL} returned ${resp.status}`);
  return recordsOf(await resp.json());
}

// --- shared payload shaping ------------------------------------------------------------------------

/** Accept a bare array of OSV records or an object wrapping them under `advisories`/`vulns`. */
function recordsOf(payload: unknown): OsvRecord[] {
  if (Array.isArray(payload)) return payload as OsvRecord[];
  const obj = payload as Record<string, unknown> | null;
  if (Array.isArray(obj?.advisories)) return obj!.advisories as OsvRecord[];
  if (Array.isArray(obj?.vulns)) return obj!.vulns as OsvRecord[];
  return [];
}

/** The next page URL for a paginated feed: an explicit `next` URL, or a `next_page_token` folded onto
 *  the current URL as `?page_token=`. `null` ends pagination. */
function nextPage(payload: unknown, current: string): string | null {
  const obj = payload as Record<string, unknown> | null;
  if (typeof obj?.next === "string" && obj.next.length > 0) return obj.next;
  if (typeof obj?.next_page_token === "string" && obj.next_page_token.length > 0) {
    const u = new URL(current);
    u.searchParams.set("page_token", obj.next_page_token);
    return u.toString();
  }
  return null;
}

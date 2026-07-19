// Noeta registry — a Cloudflare Worker over D1 (see PROTOCOL.md).
//
// The index maps `company/package` + version → git coordinates (url + tag + pinned commit SHA). It
// never stores or serves source. Security-relevant invariants enforced here:
//   • immutable versions — a published (name, version) can be yanked but never re-pointed;
//   • scope ownership — a publish token is bound to a `company`, so only its owner publishes there;
//   • the SHA is recorded at publish time, so the index is authoritative on version→commit.
//
// Intentionally dependency-free (a registry that fights supply-chain attacks shouldn't itself pull a
// tree of npm deps): plain routing, the Workers `crypto` for token hashing, D1 for storage.

import { handleWeb } from "./web";
import { oidcConfig, verifyOidc } from "./oidc";
import { githubConfig, verifyGithubOwnership } from "./github";
import { domainConfig, verifyDomainOwnership } from "./domain";
import * as log from "./log";
import * as advisory from "./advisory";
import * as reports from "./reports";
import * as imports from "./imports";

export interface Env {
  DB: D1Database;
  // A Worker secret; gates the bootstrap `POST /v1/scopes` endpoint.
  ADMIN_TOKEN?: string;
  // OIDC config for self-service scope claiming (namespace-protection #1). Absent AUDIENCE disables
  // claiming (see `oidcConfig`). Defaults target GitHub Actions' public issuer.
  OIDC_ISSUER?: string;
  OIDC_AUDIENCE?: string;
  OIDC_JWKS_URL?: string;
  // GitHub REST API base for the laptop (device-flow) claim's ownership check; defaults to
  // https://api.github.com.
  GITHUB_API_URL?: string;
  // Scheme for the domain-proof well-known fetch (namespace-protection #1); defaults to https. Only a
  // test double sets it — production always verifies over https.
  DOMAIN_SCHEME?: string;
  // Transparency log (namespace-protection #1). LOG_PRIVATE_KEY (base64 PKCS8 Ed25519, a secret) signs
  // checkpoints; LOG_PUBLIC_KEY (hex) is served for clients to pin. Absent → checkpoints are 501, but
  // the log is still appended to and proofs are still served.
  LOG_PRIVATE_KEY?: string;
  LOG_PUBLIC_KEY?: string;
  // Security advisory feed (namespace-protection #1). A key distinct from the log key (separate role):
  // ADVISORY_PRIVATE_KEY (base64 PKCS8 Ed25519, a secret) signs each advisory and the feed head;
  // ADVISORY_PUBLIC_KEY (hex) is served for clients to pin. Absent → publishing is 403/501, but the
  // read feed is still served.
  ADVISORY_PRIVATE_KEY?: string;
  ADVISORY_PUBLIC_KEY?: string;
  // Advisory-intake arc. REPORT_RATE_LIMIT caps how many public reports one IP may file per hour
  // (tier 4, default 5). OSV_IMPORT_URL is the OSV-format feed the scheduled cron pulls to import
  // external advisories through the operator-curated name map (tier 3); absent → the cron is a no-op.
  REPORT_RATE_LIMIT?: string;
  OSV_IMPORT_URL?: string;
}

interface VersionRow {
  version: string;
  url: string;
  tag: string;
  sha: string;
  deps: string; // JSON array of { package, req }
  sig: string | null; // hex Ed25519 signature over the attestation, or null (unsigned)
  bundle: string | null; // JSON Sigstore keyless bundle, or null
  yanked: number;
  published_at: string; // ISO-8601 UTC publish time (for the client's publish-cooldown window)
  license: string | null; // declared SPDX expression, or null (immutable with the release)
  description: string | null; // one-line search blurb, or null
}

interface Dep {
  package: string; // company/package
  req: string; // SemVer requirement
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const NAME = /^[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z_][A-Za-z0-9_]*$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;
/** A discovery keyword: one canonical spelling per tag, so a listing groups instead of fragmenting. */
const KEYWORD = /^[a-z0-9][a-z0-9-]{0,19}$/;
/** Enough to place a package; few enough that a keyword still means something (crates.io's limit). */
const MAX_KEYWORDS = 5;
/** A one-line search blurb — long enough to be useful, short enough to stay a single result-card row. */
const MAX_DESCRIPTION = 200;

// Reserved namespaces (namespace-protection arcs #2/#1) — MUST match noeta-pm's `reserved` module.
// `std`/`noeta`/`core` are toolchain built-ins: satisfied by the compiler, never living in a
// registry, so they can never be registered, published, or claimed here (a `std/*` release could
// only be a supply-chain attack trying to shadow core code).
const BUILTIN_SCOPES = new Set(["std", "noeta", "core"]);

// First-party *published* namespaces → the GitHub org allowed to own them. These are resolvable like
// any package, but reserved so a random org can't grab the name: unlike an ordinary scope (claimable
// by the org/user of the *same* name), a first-party scope is claimable only by its **designated
// org** — `para` only by `noeta-dev`. It still flows through the normal OIDC claim, so the first party
// needs no admin token; the admin bootstrap remains an escape hatch.
const FIRST_PARTY_SCOPES = new Map<string, string>([["para", "noeta-dev"]]);

// Scopes the *web browser* needs for its own URLs. Packages live at the root (`/{company}/{package}`),
// so a root path the browser owns — `/keywords/{keyword}` — would shadow a same-named scope's
// packages. Reserving the name keeps that ambiguity from ever existing.
//
// Deliberately separate from BUILTIN_SCOPES: that set means "the compiler provides this, it can never
// be a package", and noeta-pm mirrors it. This one is a registry-server URL concern the client has no
// stake in — resolution semantics are unchanged, so noeta-pm needs no matching entry.
const RESERVED_WEB_SCOPES = new Set(["keywords", "search"]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (err) {
      return json({ error: `internal error: ${String(err)}` }, 500);
    }
  },

  // Scheduled cron (advisory-intake arc, tier 3): pull the configured OSV feed and import mapped
  // advisories. Idempotent per upstream id, so a repeated run refreshes rather than duplicating. A no-op
  // when OSV_IMPORT_URL is unset; a fetch/parse failure is logged, never thrown past the platform.
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      imports.runScheduledImport(env).then(
        (r) => console.log(`advisory import: ${r.imported} imported, ${r.skipped} skipped`),
        (err) => console.error(`advisory import failed: ${String(err)}`),
      ),
    );
  },
};

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean); // e.g. ["v1","packages","acme","imgfx"]

  // Everything not under `/v1` is the public, read-only **web browser** (see web.ts): the JSON API
  // lives at `/v1`, humans get HTML everywhere else. Read-only, so only GET/HEAD.
  if (parts[0] !== "v1") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "method not allowed" }, 405);
    }
    return handleWeb(env, parts, url.searchParams);
  }

  // POST /v1/scopes  (admin bootstrap)
  if (parts.length === 2 && parts[1] === "scopes" && request.method === "POST") {
    return registerScope(request, env);
  }
  // POST /v1/scopes/claim  — self-service claim, proven by a GitHub OIDC token
  if (parts.length === 3 && parts[1] === "scopes" && parts[2] === "claim" && request.method === "POST") {
    return claimScope(request, env);
  }
  // POST /v1/scopes/{scope}/policy  — set the scope's publishing policy (owner-authenticated)
  if (parts.length === 4 && parts[1] === "scopes" && parts[3] === "policy" && request.method === "POST") {
    return setScopePolicy(request, env, parts[2]);
  }
  // POST /v1/scopes/{scope}/advisories  — publisher-tier advisory for the scope's own package
  // (owner-authenticated, carries a keyless bundle) (advisory-intake arc, tier 2)
  if (parts.length === 4 && parts[1] === "scopes" && parts[3] === "advisories" && request.method === "POST") {
    return advisory.publishScopeAdvisory(request, env, parts[2], authorizeScope);
  }
  // GET /v1/scopes/{scope}/reports  — the scope owner's own triage queue (only their packages'
  // reports; owner-authenticated) (advisory-intake arc, tier 4)
  if (parts.length === 4 && parts[1] === "scopes" && parts[3] === "reports" && request.method === "GET") {
    const auth = await authorizeScope(request, env, parts[2]);
    if (auth instanceof Response) return auth;
    return reports.listReports(env, url.searchParams.get("status"), null, parts[2]);
  }
  // GET /v1/scopes/{scope}  — the scope's public key (for verifying its release signatures)
  if (parts.length === 3 && parts[1] === "scopes" && request.method === "GET") {
    return getScopeKey(env, parts[2]);
  }

  // Transparency log (namespace-protection #1). All read-only.
  if (parts[1] === "log" && request.method === "GET") {
    if (parts.length === 3 && parts[2] === "checkpoint") return log.checkpoint(env);
    if (parts.length === 3 && parts[2] === "key") return log.publicKey(env);
    if (parts.length === 3 && parts[2] === "consistency") {
      return log.consistency(env, url.searchParams.get("from"), url.searchParams.get("to"));
    }
    // GET /v1/log/proof/{company}/{package}/{version}
    if (parts.length === 6 && parts[2] === "proof") {
      return log.inclusion(env, `${parts[3]}/${parts[4]}`, parts[5]);
    }
    // GET /v1/log/advisory/{id} — inclusion proof for an advisory's current leaf
    if (parts.length === 4 && parts[2] === "advisory") {
      return advisory.advisoryInclusion(env, parts[3]);
    }
  }

  // Security advisory feed (namespace-protection #1).
  if (parts[1] === "advisories") {
    // POST /v1/advisories  — publish/update an operator-tier advisory (admin only)
    if (parts.length === 2 && request.method === "POST") return advisory.publishAdvisory(request, env);
    // POST /v1/advisories/import  — import a batch of OSV records through the name map (admin, tier 3)
    if (parts.length === 3 && parts[2] === "import" && request.method === "POST") {
      return imports.importAdvisoriesFromRequest(request, env);
    }
    if (request.method === "GET") {
      if (parts.length === 2) return advisory.listAdvisories(env, url.searchParams.get("since"));
      if (parts.length === 3 && parts[2] === "checkpoint") return advisory.advisoryCheckpoint(env);
      if (parts.length === 3 && parts[2] === "key") return advisory.advisoryPublicKey(env);
    }
  }

  // Name mappings (advisory-intake arc, tier 3): external ecosystem name → Noeta package identity, the
  // operator-curated data the OSV/GHSA/RUSTSEC import applies. Write is admin; read is public.
  if (parts[1] === "name-mappings" && parts.length === 2) {
    if (request.method === "POST") return imports.addNameMapping(request, env);
    if (request.method === "GET") return imports.listNameMappings(env);
  }

  // Public report queue (advisory-intake arc, tier 4 — intake only). Filing is unauthenticated +
  // rate-limited; listing/promote/dismiss are gated (admin, or the scope owner via the scope route above).
  if (parts[1] === "reports") {
    // POST /v1/reports  — file a report (anyone, rate-limited)
    if (parts.length === 2 && request.method === "POST") return reports.fileReport(request, env);
    // GET /v1/reports  — the operator triage queue (admin only)
    if (parts.length === 2 && request.method === "GET") {
      const presented = bearer(request);
      if (!env.ADMIN_TOKEN || !presented || !timingEqual(presented, env.ADMIN_TOKEN)) {
        return json({ error: "admin token required" }, 401);
      }
      return reports.listReports(env, url.searchParams.get("status"), url.searchParams.get("package"));
    }
    // POST /v1/reports/{id}/promote  — promote a report into an advisory (operator or scope owner)
    if (parts.length === 4 && parts[3] === "promote" && request.method === "POST") {
      return reports.promoteReport(request, env, parts[2], authorizeScope);
    }
    // POST /v1/reports/{id}/dismiss  — close a report without issuing an advisory (admin only)
    if (parts.length === 4 && parts[3] === "dismiss" && request.method === "POST") {
      return reports.dismissReport(request, env, parts[2]);
    }
  }

  // /v1/packages/{company}/{package}[/{version}/yank]
  if (parts[1] === "packages") {
    const company = parts[2];
    const pkg = parts[3];
    if (!company || !pkg || !IDENT.test(company) || !IDENT.test(pkg)) {
      return json({ error: "package must be company/package (identifier segments)" }, 400);
    }
    const name = `${company}/${pkg}`;

    if (parts.length === 4 && request.method === "GET") return getVersions(env, name);
    if (parts.length === 4 && request.method === "POST") return publish(request, env, company, name);
    if (parts.length === 6 && parts[5] === "yank" && request.method === "POST") {
      return yank(request, env, company, name, parts[4]);
    }
    // Documentation artifact (docs-ingestion): PUT stores, GET serves — path
    // `.../packages/{company}/{package}/docs/{version}` (the `docs` literal precedes the version,
    // distinct from yank's trailing `/yank`).
    if (parts.length === 6 && parts[4] === "docs") {
      if (request.method === "PUT") return putDocs(request, env, company, name, parts[5]);
      if (request.method === "GET") return getDocs(env, name, parts[5]);
    }
    // README artifact: same shape as docs, but the blob is raw markdown, rendered on the
    // package's browser page rather than the /docs page.
    if (parts.length === 6 && parts[4] === "readme") {
      if (request.method === "PUT") return putReadme(request, env, company, name, parts[5]);
      if (request.method === "GET") return getReadme(env, name, parts[5]);
    }
  }

  return json({ error: "not found" }, 404);
}

/** A release's keywords, sorted — the order they were stored in and are echoed in. */
async function keywordsFor(env: Env, name: string, version: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT keyword FROM package_keywords WHERE name = ? AND version = ? ORDER BY keyword",
  )
    .bind(name, version)
    .all<{ keyword: string }>();
  return (results ?? []).map((r) => r.keyword);
}

/** GET — every published version (an unknown package is an empty list, not a 404). */
async function getVersions(env: Env, name: string): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT version, url, tag, sha, deps, sig, bundle, yanked, published_at, license, description FROM packages WHERE name = ? ORDER BY version",
  )
    .bind(name)
    .all<VersionRow>();
  // One query for the package's keywords, grouped in memory — a per-version query would be N+1.
  const { results: kwRows } = await env.DB.prepare(
    "SELECT version, keyword FROM package_keywords WHERE name = ? ORDER BY keyword",
  )
    .bind(name)
    .all<{ version: string; keyword: string }>();
  const keywordsByVersion = new Map<string, string[]>();
  for (const r of kwRows ?? []) {
    const list = keywordsByVersion.get(r.version);
    if (list) list.push(r.keyword);
    else keywordsByVersion.set(r.version, [r.keyword]);
  }
  const versions = (results ?? []).map((r) => {
    // `published_at` (publish-cooldown, namespace-protection #1): echo the stored ISO timestamp and a
    // parsed epoch-millis so the client can apply a cooldown window without an ISO-8601 date parser.
    // A NaN parse (shouldn't happen — the column is NOT NULL ISO) is dropped, treating the release as
    // undateable (never in cooldown) rather than failing the whole listing.
    const ms = Date.parse(r.published_at);
    return {
      version: r.version,
      url: r.url,
      tag: r.tag,
      sha: r.sha,
      deps: parseDeps(r.deps),
      signature: r.sig ?? undefined,
      bundle: r.bundle ?? undefined,
      yanked: r.yanked !== 0,
      published_at: r.published_at,
      published_at_unix: Number.isNaN(ms) ? undefined : ms,
      license: r.license ?? undefined,
      keywords: keywordsByVersion.get(r.version),
      description: r.description ?? undefined,
    };
  });
  return json({ name, versions });
}

/** GET /v1/scopes/{scope} — the scope's registered public key (404 if unregistered). */
async function getScopeKey(env: Env, scope: string): Promise<Response> {
  if (!IDENT.test(scope)) return json({ error: "scope must be an identifier" }, 400);
  const row = await env.DB.prepare("SELECT public_key FROM scopes WHERE scope = ?")
    .bind(scope)
    .first<{ public_key: string | null }>();
  if (!row || !row.public_key) return json({ error: `scope \`${scope}\` has no public key` }, 404);
  return json({ scope, public_key: row.public_key });
}

/** The maximum stored docs.json size (bytes). Generous for a real package's API surface, bounded so
 *  a single upload can't bloat the row store; a larger artifact is a 413. */
const MAX_DOCS_BYTES = 1024 * 1024;

/** PUT …/docs/{version} — store a release's documentation artifact (advisory, scope-owned,
 *  last-wins). The release must be published (docs belong to a release); the body is the verbatim
 *  `docs.json` and must be valid JSON. */
async function putDocs(
  request: Request,
  env: Env,
  company: string,
  name: string,
  version: string,
): Promise<Response> {
  if (!SEMVER.test(version)) return json({ error: "version must be semver" }, 400);
  const auth = await authorizeScope(request, env, company);
  if (auth instanceof Response) return auth;

  const body = await request.text();
  if (body.length > MAX_DOCS_BYTES) {
    return json({ error: `docs artifact exceeds ${MAX_DOCS_BYTES} bytes` }, 413);
  }
  // Store verbatim, but reject a non-JSON blob so the index never serves garbage back.
  try {
    JSON.parse(body);
  } catch {
    return json({ error: "docs body must be valid JSON (the `docs.json` artifact)" }, 400);
  }

  // Docs belong to a published release — refuse orphan docs for a version that doesn't exist.
  const release = await env.DB.prepare("SELECT 1 FROM packages WHERE name = ? AND version = ?")
    .bind(name, version)
    .first();
  if (!release) return json({ error: `${name}@${version} is not published` }, 404);

  await env.DB.prepare(
    "INSERT INTO docs (name, version, docs_json, updated_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(name, version) DO UPDATE SET docs_json = excluded.docs_json, updated_at = excluded.updated_at",
  )
    .bind(name, version, body, new Date().toISOString())
    .run();
  return json({ status: "docs stored", name, version });
}

/** GET …/docs/{version} — serve a release's stored documentation artifact verbatim (404 if none). */
async function getDocs(env: Env, name: string, version: string): Promise<Response> {
  if (!SEMVER.test(version)) return json({ error: "version must be semver" }, 400);
  const row = await env.DB.prepare("SELECT docs_json FROM docs WHERE name = ? AND version = ?")
    .bind(name, version)
    .first<{ docs_json: string }>();
  if (!row) return json({ error: `no docs stored for ${name}@${version}` }, 404);
  // The stored blob is the client's `docs.json` verbatim — serve it as-is, not re-wrapped.
  return new Response(row.docs_json, {
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

/** The maximum stored README size (bytes). A README is prose, not an API surface — far smaller
 *  than a docs artifact; anything past this is a 413 (and likely not a README). */
const MAX_README_BYTES = 256 * 1024;

/** PUT …/readme/{version} — store a release's README markdown (advisory, scope-owned, last-wins).
 *  Same rules as docs: the release must be published, and the blob never affects resolution. The
 *  body is raw markdown — no JSON validation; the web renderer is escape-first, so the registry
 *  stores it verbatim and the trust boundary is at render time. */
async function putReadme(
  request: Request,
  env: Env,
  company: string,
  name: string,
  version: string,
): Promise<Response> {
  if (!SEMVER.test(version)) return json({ error: "version must be semver" }, 400);
  const auth = await authorizeScope(request, env, company);
  if (auth instanceof Response) return auth;

  const body = await request.text();
  if (body.length > MAX_README_BYTES) {
    return json({ error: `README exceeds ${MAX_README_BYTES} bytes` }, 413);
  }
  if (body.length === 0) return json({ error: "README body must be non-empty markdown" }, 400);

  // A README belongs to a published release — refuse an orphan for a version that doesn't exist.
  const release = await env.DB.prepare("SELECT 1 FROM packages WHERE name = ? AND version = ?")
    .bind(name, version)
    .first();
  if (!release) return json({ error: `${name}@${version} is not published` }, 404);

  await env.DB.prepare(
    "INSERT INTO readmes (name, version, readme_md, updated_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(name, version) DO UPDATE SET readme_md = excluded.readme_md, updated_at = excluded.updated_at",
  )
    .bind(name, version, body, new Date().toISOString())
    .run();
  return json({ status: "readme stored", name, version });
}

/** GET …/readme/{version} — serve a release's stored README verbatim (404 if none). */
async function getReadme(env: Env, name: string, version: string): Promise<Response> {
  if (!SEMVER.test(version)) return json({ error: "version must be semver" }, 400);
  const row = await env.DB.prepare("SELECT readme_md FROM readmes WHERE name = ? AND version = ?")
    .bind(name, version)
    .first<{ readme_md: string }>();
  if (!row) return json({ error: `no readme stored for ${name}@${version}` }, 404);
  return new Response(row.readme_md, {
    headers: { "content-type": "text/markdown; charset=utf-8" },
  });
}

/** POST — publish a release. Immutable + scope-owned. */
async function publish(request: Request, env: Env, company: string, name: string): Promise<Response> {
  // A built-in scope is never a registry package (namespace-protection #2) — refuse before auth so
  // the endpoint never even implies `std/*` could be owned. No scope is ever registered for these
  // (registerScope refuses them too), so this is defense in depth, returned as an explicit 403.
  if (BUILTIN_SCOPES.has(company)) {
    return json(
      { error: `\`${company}\` is a reserved built-in namespace and cannot be published to the registry` },
      403,
    );
  }
  const auth = await authorizeScope(request, env, company);
  if (auth instanceof Response) return auth;

  const body = await readJson(request);
  if (body instanceof Response) return body;
  const { version, url, tag, sha } = body as Record<string, unknown>;
  if (
    typeof version !== "string" || !SEMVER.test(version) ||
    typeof url !== "string" || url.length === 0 ||
    typeof tag !== "string" || tag.length === 0 ||
    typeof sha !== "string" || sha.length === 0
  ) {
    return json({ error: "body must be { version (semver), url, tag, sha }" }, 400);
  }
  const deps = validateDeps((body as Record<string, unknown>).deps);
  if (deps instanceof Response) return deps;
  const depsJson = JSON.stringify(deps);

  const keywords = validateKeywords((body as Record<string, unknown>).keywords);
  if (keywords instanceof Response) return keywords;

  const description = validateDescription((body as Record<string, unknown>).description);
  if (description instanceof Response) return description;

  // Optional declared license — an SPDX expression like "MIT OR Apache-2.0". Part of the immutable
  // release record (and bound into the log leaf below), unlike advisory docs/READMEs: consumers and
  // audit tooling must be able to trust what the index said at resolve time. Shape-checked only
  // (SPDX charset, bounded) — the registry never fetches source, so the *claim* is the publisher's;
  // the SHA pin lets a consumer check the actual LICENSE file.
  const rawLicense = (body as Record<string, unknown>).license;
  let license: string | null = null;
  if (rawLicense !== undefined && rawLicense !== null) {
    if (
      typeof rawLicense !== "string" ||
      rawLicense.trim().length === 0 ||
      rawLicense.length > 120 ||
      !/^[0-9A-Za-z .+()-]+$/.test(rawLicense)
    ) {
      return json({ error: "`license` must be an SPDX license expression (≤ 120 chars)" }, 400);
    }
    license = rawLicense.trim();
  }

  // Provenance (Phase 4 #2): if a signature is present, verify it against the scope's registered
  // public key over the canonical attestation — reject a bad or unverifiable signature so the index
  // never serves a signature that doesn't actually attest this release. Absent → unsigned (allowed
  // while provenance is adopted gradually).
  const rawSig = (body as Record<string, unknown>).signature;
  const rawBundle = (body as Record<string, unknown>).bundle;
  const hasSig = rawSig !== undefined && rawSig !== null;
  const hasBundle = rawBundle !== undefined && rawBundle !== null;
  // A release carries at most one trust root (matches the client's `Release::check_provenance_shape`):
  // two roots would make "which did the consumer verify?" ambiguous and give a downgrade a second surface.
  if (hasSig && hasBundle) {
    return json({ error: "a release carries either a `signature` (key) or a `bundle` (keyless), not both" }, 400);
  }

  // Key trust root: verify the Ed25519 signature against the scope's registered public key over the
  // canonical attestation, so the index never serves a signature that doesn't attest this release.
  let sig: string | null = null;
  if (hasSig) {
    if (typeof rawSig !== "string" || !/^[0-9a-f]{128}$/.test(rawSig)) {
      return json({ error: "`signature` must be a 128-char hex Ed25519 signature" }, 400);
    }
    const scopeRow = await env.DB.prepare("SELECT public_key FROM scopes WHERE scope = ?")
      .bind(company)
      .first<{ public_key: string | null }>();
    if (!scopeRow || !scopeRow.public_key) {
      return json({ error: `scope \`${company}\` has no public key registered to verify a signature` }, 400);
    }
    const ok = await verifyEd25519(scopeRow.public_key, sig_message(name, version, sha), rawSig);
    if (!ok) return json({ error: "signature does not verify against the scope's public key" }, 400);
    sig = rawSig;
  }

  // Keyless trust root: stored verbatim, NOT verified server-side. Its root is Sigstore's public
  // infrastructure (Fulcio/Rekor), not a per-scope key — verification would need those roots and full
  // cert-chain + inclusion-proof checking (heavy, dependency-bearing) — and a keyless consumer
  // verifies the bundle offline against its own pinned policy regardless, so the registry is never
  // the trust boundary for it. Validate only shape: a non-empty JSON document.
  let bundle: string | null = null;
  if (hasBundle) {
    if (typeof rawBundle !== "string" || rawBundle.length === 0) {
      return json({ error: "`bundle` must be a non-empty JSON Sigstore bundle string" }, 400);
    }
    try {
      JSON.parse(rawBundle);
    } catch {
      return json({ error: "`bundle` must be valid JSON (a Sigstore bundle)" }, 400);
    }
    bundle = rawBundle;
  }

  // Enforce the scope's provenance policy (require-provenance, namespace-protection #1). When on, a
  // release must carry the required trust root, so a leaked token alone — without the signing key
  // (`key`) or the OIDC identity behind a bundle (`keyless`) — can't publish. `sig` is already
  // verified above against the scope's public key, so its presence here means a *valid* signature.
  const policy = await env.DB.prepare(
    "SELECT require_provenance, provenance_root FROM scopes WHERE scope = ?",
  )
    .bind(company)
    .first<{ require_provenance: number; provenance_root: string | null }>();
  if (policy && policy.require_provenance) {
    const root = policy.provenance_root; // "key" | "keyless" | null (either)
    const satisfied = root === "key" ? sig !== null : root === "keyless" ? bundle !== null : (sig !== null || bundle !== null);
    if (!satisfied) {
      const need = root ? `\`${root}\` provenance` : "signed provenance (a key signature or a keyless bundle)";
      return json({ error: `scope \`${company}\` requires ${need}; this release carries none` }, 403);
    }
  }

  const existing = await env.DB.prepare(
    "SELECT url, tag, sha, deps, license, description FROM packages WHERE name = ? AND version = ?",
  )
    .bind(name, version)
    .first<{ url: string; tag: string; sha: string; deps: string; license: string | null; description: string | null }>();
  if (existing) {
    // Idempotent re-publish of identical coordinates + deps + license + keywords + description;
    // otherwise immutable. Every mutable-looking field joins the comparison so a re-publish that
    // only changes one (e.g. re-tagging or editing the blurb) is a 409, not a silent no-op.
    const existingKeywords = await keywordsFor(env, name, version);
    if (
      existing.url === url && existing.tag === tag && existing.sha === sha &&
      existing.deps === depsJson && existing.license === license &&
      existing.description === description &&
      existingKeywords.join(" ") === keywords.join(" ")
    ) {
      return json({ status: "already published", name, version }, 200);
    }
    return json(
      { error: `${name}@${version} is already published with different coordinates — immutable` },
      409,
    );
  }

  // Append the release to the transparency log in the same batch as the package row, so the two are
  // written atomically — a published release is always logged (namespace-protection #1).
  const now = new Date().toISOString();
  const record = log.logRecord(name, version, url, tag, sha, await log.provenanceTag(sig, bundle), license ?? "");
  const { idx, leaf } = await log.prepareEntry(env, record);
  await env.DB.batch([
    env.DB
      .prepare(
        "INSERT INTO packages (name, version, url, tag, sha, deps, sig, bundle, yanked, published_by, published_at, license, description) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)",
      )
      .bind(name, version, url, tag, sha, depsJson, sig, bundle, company, now, license, description),
    env.DB
      .prepare(
        "INSERT INTO log (idx, leaf_hash, name, version, record, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(idx, leaf, name, version, record, now),
    // Keywords ride the same batch as the release they describe, so a published release never exists
    // un-tagged (they are not in the log leaf — see migrations/0011_keywords.sql for why).
    ...keywords.map((k) =>
      env.DB
        .prepare("INSERT INTO package_keywords (name, version, keyword) VALUES (?, ?, ?)")
        .bind(name, version, k),
    ),
    // Refresh the package's search row to this release. It is by definition the most recent publish
    // (published_at = now), which is the release search shows — so every publish overwrites the
    // one-row-per-package FTS entry (delete-by-name + insert). See migrations/0012_search.sql.
    env.DB.prepare("DELETE FROM package_fts WHERE name = ?").bind(name),
    env.DB
      .prepare(
        "INSERT INTO package_fts (name, description, keywords, version, license, published_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(name, description ?? "", keywords.join(" "), version, license ?? "", now),
  ]);
  return json(
    {
      status: "published",
      name,
      version,
      sha,
      license: license ?? undefined,
      keywords: keywords.length ? keywords : undefined,
      description: description ?? undefined,
      provenance: sig ? "key" : bundle ? "keyless" : "unsigned",
      log_index: idx,
    },
    201,
  );
}

/** POST …/yank — mark (or clear) a version yanked; never deletes. */
async function yank(
  request: Request,
  env: Env,
  company: string,
  name: string,
  version: string,
): Promise<Response> {
  const auth = await authorizeScope(request, env, company);
  if (auth instanceof Response) return auth;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const yanked = (body as Record<string, unknown>).yanked;
  if (typeof yanked !== "boolean") return json({ error: "body must be { yanked: boolean }" }, 400);

  const res = await env.DB.prepare(
    "UPDATE packages SET yanked = ? WHERE name = ? AND version = ?",
  )
    .bind(yanked ? 1 : 0, name, version)
    .run();
  if (!res.meta || res.meta.changes === 0) {
    return json({ error: `${name}@${version} is not published` }, 404);
  }
  return json({ status: yanked ? "yanked" : "unyanked", name, version });
}

/** POST /v1/scopes — bootstrap a scope's publish token (admin only). */
async function registerScope(request: Request, env: Env): Promise<Response> {
  if (!env.ADMIN_TOKEN) return json({ error: "scope registration is disabled" }, 403);
  const presented = bearer(request);
  if (!presented || !timingEqual(presented, env.ADMIN_TOKEN)) {
    return json({ error: "admin token required" }, 401);
  }
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const { scope, token, public_key } = body as Record<string, unknown>;
  if (typeof scope === "string" && BUILTIN_SCOPES.has(scope)) {
    // Built-in scopes live in the compiler, not the registry — no token may ever own `std/*`.
    // (A first-party scope like `para` is intentionally *allowed* here: this endpoint is the admin
    // bootstrap, i.e. the first party itself. Open self-service claims are where `para` is guarded,
    // arriving in namespace-protection #1.)
    return json({ error: `\`${scope}\` is a reserved built-in namespace and cannot be registered` }, 403);
  }
  if (typeof scope === "string" && RESERVED_WEB_SCOPES.has(scope)) {
    return json({ error: `\`${scope}\` is reserved by the registry's web browser and cannot be registered` }, 403);
  }
  if (typeof scope !== "string" || !IDENT.test(scope) || typeof token !== "string" || token.length < 16) {
    return json({ error: "body must be { scope (identifier), token (>=16 chars) }" }, 400);
  }
  // Optional Ed25519 public key (hex) to verify this scope's release signatures (provenance).
  if (public_key !== undefined && (typeof public_key !== "string" || !/^[0-9a-f]{64}$/.test(public_key))) {
    return json({ error: "`public_key` must be a 64-char hex Ed25519 public key" }, 400);
  }
  await env.DB.prepare(
    "INSERT INTO scopes (scope, token_sha, public_key, owner_kind, owner_id, created_at) " +
      "VALUES (?, ?, ?, 'admin', NULL, ?) " +
      "ON CONFLICT(scope) DO UPDATE SET token_sha = excluded.token_sha, public_key = excluded.public_key, " +
      "owner_kind = 'admin', owner_id = NULL",
  )
    .bind(scope, await sha256hex(token), (public_key as string | undefined) ?? null, new Date().toISOString())
    .run();
  return json({ status: "scope registered", scope }, 201);
}

/** POST /v1/scopes/claim — self-service scope claiming (namespace-protection #1).
 *
 * A scope is claimed by whoever proves they control the GitHub org/user *of the same name* — via a
 * GitHub Actions **OIDC** token (`oidc`, from CI) or a GitHub OAuth **access token** (`github_token`,
 * from the laptop device flow). That proof-of-control is the anti-squatting mechanism: you cannot
 * claim `stripe` unless you are `stripe` (or an admin of the `stripe` org), so popular names can't be
 * drive-by registered. Both proofs resolve to the owner's **stable GitHub numeric id**, pinned as
 * `owner_id` under one `owner_kind` (`github`) — so re-claims (token rotation) require the same
 * identity, a renamed/transferred org can't take a scope over, and the CI and laptop paths are
 * interchangeable. Reserved namespaces are never claimable here. */
async function claimScope(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const { scope, token, oidc, github_token, domain } = body as Record<string, unknown>;
  if (typeof scope !== "string" || !IDENT.test(scope) || typeof token !== "string" || token.length < 16) {
    return json({ error: "body must be { scope (identifier), token (>=16 chars), and one proof }" }, 400);
  }
  const hasOidc = typeof oidc === "string" && oidc.length > 0;
  const hasGithub = typeof github_token === "string" && github_token.length > 0;
  const hasDomain = typeof domain === "string" && domain.length > 0;
  if ([hasOidc, hasGithub, hasDomain].filter(Boolean).length !== 1) {
    return json(
      {
        error:
          "provide exactly one proof of ownership: `oidc` (CI), `github_token` (device flow), or " +
          "`domain` (DNS/well-known)",
      },
      400,
    );
  }
  // A built-in scope is never claimable — it lives in the compiler, not the registry.
  if (BUILTIN_SCOPES.has(scope)) {
    return json({ error: `\`${scope}\` is a reserved built-in namespace and cannot be claimed` }, 403);
  }
  if (RESERVED_WEB_SCOPES.has(scope)) {
    return json({ error: `\`${scope}\` is reserved by the registry's web browser and cannot be claimed` }, 403);
  }

  // The anti-squat rule: an ordinary scope is claimable by the org/user of the *same* name; a reserved
  // first-party scope only by its designated org (so only `noeta-dev` can claim `para`).
  const designatedOwner = FIRST_PARTY_SCOPES.get(scope);
  const requiredOwner = designatedOwner ?? scope;

  // Verify the presented proof → an (owner_kind, owner_id) principal. GitHub proofs (OIDC/OAuth) share
  // the `github` kind + numeric id (interchangeable); a domain proof is the `domain` kind + the domain.
  let ownerKind: string;
  let ownerId: string;
  let provenOwner: string; // what to echo as the owner in the response
  if (hasDomain) {
    // Domain proof binds the scope to a domain whose first label is the scope; a first-party scope has
    // a designated *GitHub org*, so it isn't domain-claimable.
    if (designatedOwner) {
      return json(
        {
          error: `\`${scope}\` is a reserved first-party namespace, claimable only by the \`${designatedOwner}\` GitHub org, not by domain proof`,
        },
        403,
      );
    }
    try {
      ownerId = await verifyDomainOwnership(scope, domain as string, domainConfig(env));
    } catch (err) {
      return json(
        { error: `cannot claim scope \`${scope}\` by domain: ${err instanceof Error ? err.message : String(err)}` },
        403,
      );
    }
    ownerKind = "domain";
    provenOwner = ownerId;
  } else if (hasOidc) {
    const cfg = oidcConfig(env);
    if (!cfg) return json({ error: "OIDC scope claiming is not configured on this registry" }, 501);
    let claims;
    try {
      claims = await verifyOidc(oidc as string, cfg);
    } catch (err) {
      return json({ error: `OIDC verification failed: ${err instanceof Error ? err.message : String(err)}` }, 401);
    }
    if (claims.repository_owner !== requiredOwner) {
      return json(
        {
          error: designatedOwner
            ? `\`${scope}\` is a reserved first-party namespace, claimable only by the \`${designatedOwner}\` org (not \`${claims.repository_owner}\`)`
            : `your GitHub identity \`${claims.repository_owner}\` cannot claim scope \`${scope}\` — ` +
              `a scope is claimable only by the org/user of the same name`,
        },
        403,
      );
    }
    ownerId = claims.repository_owner_id;
    ownerKind = "github";
    provenOwner = requiredOwner;
  } else {
    try {
      ownerId = await verifyGithubOwnership(github_token as string, requiredOwner, githubConfig(env));
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      return json(
        {
          error: designatedOwner
            ? `\`${scope}\` is a reserved first-party namespace, claimable only by the \`${designatedOwner}\` org: ${reason}`
            : `cannot claim scope \`${scope}\`: ${reason}`,
        },
        403,
      );
    }
    ownerKind = "github";
    provenOwner = requiredOwner;
  }

  const existing = await env.DB.prepare("SELECT owner_kind, owner_id FROM scopes WHERE scope = ?")
    .bind(scope)
    .first<{ owner_kind: string | null; owner_id: string | null }>();
  if (existing) {
    // Only the same proven principal may re-claim (to rotate its token). Anything else — an
    // admin-owned scope, a different owner_kind (e.g. a domain trying to take a GitHub-owned scope), or
    // a different owner_id — is refused; ownership never transfers implicitly.
    if (existing.owner_kind !== ownerKind || existing.owner_id !== ownerId) {
      return json({ error: `scope \`${scope}\` is already owned by another principal` }, 409);
    }
    await env.DB.prepare("UPDATE scopes SET token_sha = ? WHERE scope = ?")
      .bind(await sha256hex(token), scope)
      .run();
    return json({ status: "scope re-claimed", scope, owner: provenOwner }, 200);
  }

  await env.DB.prepare(
    "INSERT INTO scopes (scope, token_sha, public_key, owner_kind, owner_id, created_at) VALUES (?, ?, NULL, ?, ?, ?)",
  )
    .bind(scope, await sha256hex(token), ownerKind, ownerId, new Date().toISOString())
    .run();
  return json({ status: "scope claimed", scope, owner: provenOwner }, 201);
}

/** POST /v1/scopes/{scope}/policy — set a scope's publishing policy (namespace-protection #1,
 *  require-provenance). Owner-authenticated with the scope's publish token (same auth as publish).
 *  Body `{ require_provenance: boolean, root?: "key" | "keyless" }`: when on, publishing a release
 *  that lacks the required provenance is refused, so a leaked token alone can't push. `root` narrows
 *  which trust root is required; omitted = either a key signature or a keyless bundle satisfies it. */
async function setScopePolicy(request: Request, env: Env, scope: string): Promise<Response> {
  if (!IDENT.test(scope)) return json({ error: "scope must be an identifier" }, 400);
  const auth = await authorizeScope(request, env, scope);
  if (auth instanceof Response) return auth;

  const body = await readJson(request);
  if (body instanceof Response) return body;
  const { require_provenance, root } = body as Record<string, unknown>;
  if (typeof require_provenance !== "boolean") {
    return json({ error: "body must be { require_provenance: boolean, root?: \"key\"|\"keyless\" }" }, 400);
  }
  let provenanceRoot: string | null = null;
  if (require_provenance && root !== undefined) {
    if (root !== "key" && root !== "keyless") {
      return json({ error: "`root` must be \"key\" or \"keyless\"" }, 400);
    }
    provenanceRoot = root;
  }
  await env.DB.prepare("UPDATE scopes SET require_provenance = ?, provenance_root = ? WHERE scope = ?")
    .bind(require_provenance ? 1 : 0, provenanceRoot, scope)
    .run();
  return json({
    status: "policy updated",
    scope,
    require_provenance,
    root: provenanceRoot ?? undefined,
  });
}

/** Authorize a publish/yank: the bearer token must own `company`'s scope. */
async function authorizeScope(request: Request, env: Env, company: string): Promise<Response | true> {
  const token = bearer(request);
  if (!token) return json({ error: "missing bearer token" }, 401);
  const row = await env.DB.prepare("SELECT token_sha FROM scopes WHERE scope = ?")
    .bind(company)
    .first<{ token_sha: string }>();
  if (!row) return json({ error: `scope \`${company}\` is not registered` }, 403);
  if (!timingEqual(await sha256hex(token), row.token_sha)) {
    return json({ error: `token does not own scope \`${company}\`` }, 403);
  }
  return true;
}

// --- helpers -------------------------------------------------------------------------------------

/** Parse a stored `deps` JSON column back to an array (tolerating a corrupt/empty value). */
function parseDeps(raw: string): Dep[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Validate an incoming `deps` field: absent → `[]`; else an array of `{ package (company/package),
 *  req (non-empty) }`. Returns the normalized deps or a 400 Response. */
function validateDeps(raw: unknown): Dep[] | Response {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) return json({ error: "`deps` must be an array" }, 400);
  const out: Dep[] = [];
  for (const d of raw) {
    const pkg = (d as Record<string, unknown>)?.package;
    const req = (d as Record<string, unknown>)?.req;
    if (typeof pkg !== "string" || !NAME.test(pkg) || typeof req !== "string" || req.length === 0) {
      return json({ error: "each dep must be { package: \"company/package\", req: string }" }, 400);
    }
    out.push({ package: pkg, req });
  }
  return out;
}

/** Validate an incoming `keywords` field: absent → `[]`; else up to `MAX_KEYWORDS` topic tags.
 *
 *  Keywords are a *set*: duplicates collapse (the table's primary key enforces that anyway) and the
 *  result is sorted, so the stored rows and every echo of them are deterministic regardless of the
 *  order the publisher sent. The charset is deliberately narrow — one spelling per tag is what makes
 *  `#aether` a usable index rather than a pile of near-misses (`Aether`, `aether_`, ` aether`).
 *  Returns the normalized keywords or a 400 Response. */
function validateKeywords(raw: unknown): string[] | Response {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) return json({ error: "`keywords` must be an array of strings" }, 400);
  const out: string[] = [];
  for (const k of raw) {
    if (typeof k !== "string" || !KEYWORD.test(k)) {
      return json(
        { error: "each keyword must be 1–20 chars of lowercase a–z, 0–9 and `-`, starting alphanumeric" },
        400,
      );
    }
    if (!out.includes(k)) out.push(k);
  }
  if (out.length > MAX_KEYWORDS) {
    return json({ error: `at most ${MAX_KEYWORDS} keywords` }, 400);
  }
  return out.sort();
}

/** Validate an incoming `description` field: absent → `null`; else a single-line blurb, trimmed,
 *  ≤ `MAX_DESCRIPTION` chars, no control characters (it's shown inline in search results and on the
 *  package page, so newlines and control chars have no place). Returns the value or a 400 Response. */
function validateDescription(raw: unknown): string | null | Response {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") return json({ error: "`description` must be a string" }, 400);
  const trimmed = raw.trim();
  // A single inline line: no control characters, which includes newlines and tabs.
  if (trimmed.length === 0 || trimmed.length > MAX_DESCRIPTION || /[\u0000-\u001f\u007f]/.test(trimmed)) {
    return json({ error: `\`description\` must be a single line of ≤ ${MAX_DESCRIPTION} characters` }, 400);
  }
  return trimmed;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function readJson(request: Request): Promise<unknown | Response> {
  try {
    return await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
}

function bearer(request: Request): string | null {
  const h = request.headers.get("authorization") ?? "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

/** The canonical attestation bytes — MUST match noeta-pm's `Attestation::canonical_bytes`. */
function sig_message(name: string, version: string, sha: string): Uint8Array {
  return new TextEncoder().encode(`noeta-attestation-v1\n${name}\n${version}\n${sha}\n`);
}

/** Verify a hex Ed25519 signature over `message` against a hex public key (Web Crypto). */
async function verifyEd25519(publicHex: string, message: Uint8Array, signatureHex: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(publicHex),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify("Ed25519", key, hexToBytes(signatureHex), message);
  } catch {
    return false;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function sha256hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Length-independent constant-time-ish string compare (both are fixed-length hashes in practice). */
function timingEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

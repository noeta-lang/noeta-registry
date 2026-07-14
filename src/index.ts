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

export interface Env {
  DB: D1Database;
  // A Worker secret; gates the bootstrap `POST /v1/scopes` endpoint.
  ADMIN_TOKEN?: string;
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
}

interface Dep {
  package: string; // company/package
  req: string; // SemVer requirement
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const NAME = /^[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z_][A-Za-z0-9_]*$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;

// Reserved built-in namespaces (namespace-protection arc #2) — MUST match noeta-pm's `reserved`
// module. `std`/`noeta`/`core` are toolchain built-ins: satisfied by the compiler, never living in a
// registry, so they can never be registered or published here (a `std/*` release could only be a
// supply-chain attack trying to shadow core code). First-party *published* namespaces like `para`
// are resolvable like any package but reserved against open self-service claims — that guard arrives
// with self-service claiming in namespace-protection #1; admin bootstrap (the first party) may
// register them today.
const BUILTIN_SCOPES = new Set(["std", "noeta", "core"]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (err) {
      return json({ error: `internal error: ${String(err)}` }, 500);
    }
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
    return handleWeb(env, parts);
  }

  // POST /v1/scopes  (admin bootstrap)
  if (parts.length === 2 && parts[1] === "scopes" && request.method === "POST") {
    return registerScope(request, env);
  }
  // GET /v1/scopes/{scope}  — the scope's public key (for verifying its release signatures)
  if (parts.length === 3 && parts[1] === "scopes" && request.method === "GET") {
    return getScopeKey(env, parts[2]);
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
  }

  return json({ error: "not found" }, 404);
}

/** GET — every published version (an unknown package is an empty list, not a 404). */
async function getVersions(env: Env, name: string): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT version, url, tag, sha, deps, sig, bundle, yanked FROM packages WHERE name = ? ORDER BY version",
  )
    .bind(name)
    .all<VersionRow>();
  const versions = (results ?? []).map((r) => ({
    version: r.version,
    url: r.url,
    tag: r.tag,
    sha: r.sha,
    deps: parseDeps(r.deps),
    signature: r.sig ?? undefined,
    bundle: r.bundle ?? undefined,
    yanked: r.yanked !== 0,
  }));
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

  const existing = await env.DB.prepare(
    "SELECT url, tag, sha, deps FROM packages WHERE name = ? AND version = ?",
  )
    .bind(name, version)
    .first<{ url: string; tag: string; sha: string; deps: string }>();
  if (existing) {
    // Idempotent re-publish of identical coordinates + deps; otherwise the version is immutable.
    if (existing.url === url && existing.tag === tag && existing.sha === sha && existing.deps === depsJson) {
      return json({ status: "already published", name, version }, 200);
    }
    return json(
      { error: `${name}@${version} is already published with different coordinates — immutable` },
      409,
    );
  }

  await env.DB.prepare(
    "INSERT INTO packages (name, version, url, tag, sha, deps, sig, bundle, yanked, published_by, published_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
  )
    .bind(name, version, url, tag, sha, depsJson, sig, bundle, company, new Date().toISOString())
    .run();
  return json(
    { status: "published", name, version, sha, provenance: sig ? "key" : bundle ? "keyless" : "unsigned" },
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
  if (typeof scope !== "string" || !IDENT.test(scope) || typeof token !== "string" || token.length < 16) {
    return json({ error: "body must be { scope (identifier), token (>=16 chars) }" }, 400);
  }
  // Optional Ed25519 public key (hex) to verify this scope's release signatures (provenance).
  if (public_key !== undefined && (typeof public_key !== "string" || !/^[0-9a-f]{64}$/.test(public_key))) {
    return json({ error: "`public_key` must be a 64-char hex Ed25519 public key" }, 400);
  }
  await env.DB.prepare(
    "INSERT INTO scopes (scope, token_sha, public_key, created_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(scope) DO UPDATE SET token_sha = excluded.token_sha, public_key = excluded.public_key",
  )
    .bind(scope, await sha256hex(token), (public_key as string | undefined) ?? null, new Date().toISOString())
    .run();
  return json({ status: "scope registered", scope }, 201);
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

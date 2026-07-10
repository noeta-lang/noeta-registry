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
  yanked: number;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;

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

  if (parts[0] !== "v1") return json({ error: "unknown API version" }, 404);

  // POST /v1/scopes  (admin bootstrap)
  if (parts.length === 2 && parts[1] === "scopes" && request.method === "POST") {
    return registerScope(request, env);
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
  }

  return json({ error: "not found" }, 404);
}

/** GET — every published version (an unknown package is an empty list, not a 404). */
async function getVersions(env: Env, name: string): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT version, url, tag, sha, yanked FROM packages WHERE name = ? ORDER BY version",
  )
    .bind(name)
    .all<VersionRow>();
  const versions = (results ?? []).map((r) => ({
    version: r.version,
    url: r.url,
    tag: r.tag,
    sha: r.sha,
    yanked: r.yanked !== 0,
  }));
  return json({ name, versions });
}

/** POST — publish a release. Immutable + scope-owned. */
async function publish(request: Request, env: Env, company: string, name: string): Promise<Response> {
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

  const existing = await env.DB.prepare(
    "SELECT url, tag, sha FROM packages WHERE name = ? AND version = ?",
  )
    .bind(name, version)
    .first<{ url: string; tag: string; sha: string }>();
  if (existing) {
    // Idempotent re-publish of identical coordinates; otherwise the version is immutable.
    if (existing.url === url && existing.tag === tag && existing.sha === sha) {
      return json({ status: "already published", name, version }, 200);
    }
    return json(
      { error: `${name}@${version} is already published with different coordinates — immutable` },
      409,
    );
  }

  await env.DB.prepare(
    "INSERT INTO packages (name, version, url, tag, sha, yanked, published_by, published_at) " +
      "VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
  )
    .bind(name, version, url, tag, sha, company, new Date().toISOString())
    .run();
  return json({ status: "published", name, version, sha }, 201);
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
  const { scope, token } = body as Record<string, unknown>;
  if (typeof scope !== "string" || !IDENT.test(scope) || typeof token !== "string" || token.length < 16) {
    return json({ error: "body must be { scope (identifier), token (>=16 chars) }" }, 400);
  }
  await env.DB.prepare(
    "INSERT INTO scopes (scope, token_sha, created_at) VALUES (?, ?, ?) " +
      "ON CONFLICT(scope) DO UPDATE SET token_sha = excluded.token_sha",
  )
    .bind(scope, await sha256hex(token), new Date().toISOString())
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

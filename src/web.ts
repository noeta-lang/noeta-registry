// Noeta registry — the public, read-only **web browser** (docs-ingestion follow-up).
//
// Everything under a path that is not `/v1` is the human surface: a package/version browser and a
// docs.rs-style renderer of the `docs.json` artifacts `noeta publish` stores. It is entirely
// **public and read-only** — it renders already-public index data (listings, versions, deps,
// provenance) and stored docs, so it needs no auth, no sessions, and no account model. The JSON
// API under `/v1` is untouched.
//
// Dependency-free, matching the Worker's posture: the small Markdown renderer below is hand-written
// and **escape-first** — doc prose is publisher-supplied and rendered in other readers' browsers, so
// it is HTML-escaped before any formatting and links are scheme-sanitized (no `javascript:`), so a
// malicious `docs.json` cannot inject script.

import type { Env } from "./index";
import { satisfies } from "./semver";

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;
/** Mirrors the publish-side KEYWORD in index.ts — the browse route validates before it queries. */
const KEYWORD = /^[a-z0-9][a-z0-9-]{0,19}$/;

/** The package page's sections. Each is its own URL: the CSP forbids scripts, so "tabs" are links. */
const TABS = ["readme", "docs", "versions", "deps", "security"] as const;
type Tab = (typeof TABS)[number];
/** How each section names itself in a page <title> — the slug is a route detail, not a label. */
const TAB_TITLES: Record<Tab, string> = {
  readme: "readme",
  docs: "documentation",
  versions: "versions",
  deps: "dependencies",
  security: "security",
};

interface Row {
  version: string;
  url: string;
  tag: string;
  sha: string;
  deps: string;
  sig: string | null;
  bundle: string | null;
  yanked: number;
  published_at: string;
  license: string | null;
}

/** An advisory as the Security tab needs it — the feed's own shape lives in `advisory.ts`. */
interface AdvisoryRow {
  id: string;
  ranges: string;
  patched: string | null;
  severity: string;
  summary: string;
  details: string;
  url: string;
  withdrawn: number;
}

/** A rendered page and its HTTP status. */
interface Page {
  status: number;
  body: string;
}

/** Route a human (non-`/v1`) GET. Unknown shapes render the 404 page. */
export async function handleWeb(env: Env, parts: string[]): Promise<Response> {
  const page = await routeWeb(env, parts);
  return html(page.body, page.status);
}

async function routeWeb(env: Env, parts: string[]): Promise<Page> {
  // `/`
  if (parts.length === 0) return { status: 200, body: await homePage(env) };
  // `/keywords/{keyword}` — every package tagged with it.
  if (parts.length === 2 && parts[0] === "keywords") {
    return keywordPage(env, parts[1]);
  }
  // `/{company}/{package}[/{version}[/{tab}]]`. The readme is the bare version URL, so `/readme`
  // is not a route — one canonical address per section.
  const [company, pkg, version, sub] = parts;
  const tab = sub !== undefined && sub !== "readme" && (TABS as readonly string[]).includes(sub) ? (sub as Tab) : null;
  if (
    parts.length >= 2 &&
    parts.length <= 4 &&
    IDENT.test(company) &&
    IDENT.test(pkg) &&
    (version === undefined || SEMVER.test(version)) &&
    (sub === undefined || tab !== null)
  ) {
    return packagePage(env, `${company}/${pkg}`, version, tab ?? "readme");
  }
  return { status: 404, body: notFoundPage() };
}

// --- pages ---------------------------------------------------------------------------------------

async function homePage(env: Env): Promise<string> {
  const { results } = await env.DB.prepare(
    "SELECT name, version, published_at, license FROM packages ORDER BY published_at DESC LIMIT 200",
  ).all<{ name: string; version: string; published_at: string; license: string | null }>();
  // Most-recent publish per package, in publish order — its license rides along.
  const seen = new Set<string>();
  const recent: { name: string; version: string; license: string | null }[] = [];
  for (const r of results ?? []) {
    if (seen.has(r.name)) continue;
    seen.add(r.name);
    recent.push({ name: r.name, version: r.version, license: r.license });
    if (recent.length >= 40) break;
  }
  const list = recent.length
    ? `<ul class="pkglist">${recent
        .map(
          (r) =>
            `<li><a href="/${esc(r.name)}">${esc(r.name)}</a> <span class="muted">${esc(r.version)}</span>${
              r.license ? ` <span class="badge license">${esc(r.license)}</span>` : ""
            }</li>`,
        )
        .join("")}</ul>`
    : `<p class="muted">No packages published yet.</p>`;
  return layout(
    "Noeta registry",
    `<p class="eyebrow">Package registry</p>
     <h1>The Noeta registry</h1>
     <p class="lead">The package index for <a href="https://noeta.dev">Noeta</a>. Browse published
     packages and their documentation below.</p>
     <h2>Recently published</h2>
     ${list}`,
  );
}

/**
 * One release, in five sections. Every tab renders the same shell — header, tab bar, and the
 * metadata sidebar — around a different main column, so a reader never loses the release's identity
 * (or its install line) by navigating within it.
 */
async function packagePage(env: Env, name: string, version?: string, tab: Tab = "readme"): Promise<Page> {
  const rows = await packageRows(env, name);
  if (rows.length === 0) {
    return { status: 404, body: notFoundPage(`No package \`${name}\` is published.`) };
  }
  const selected = version ? rows.find((r) => r.version === version) : rows[0];
  if (!selected) {
    return { status: 404, body: notFoundPage(`${name} has no version ${version}.`) };
  }
  const v = selected.version;

  const [hasDocs, advisories, logIndex, keywords] = await Promise.all([
    docsExist(env, name, v),
    advisoriesFor(env, name),
    logIndexFor(env, name, v),
    keywordsFor(env, name, v),
  ]);
  // A withdrawn advisory is a retraction — it is not a live claim about any version.
  const live = advisories.filter((a) => a.withdrawn === 0);
  const affecting = live.filter((a) => satisfies(v, a.ranges) === true);
  const deps = parseDeps(selected.deps);

  let main: string;
  switch (tab) {
    case "readme": {
      // The publisher-uploaded README (npm/crates.io model), rendered through the same escape-first
      // markdown renderer as doc prose — publisher markdown is untrusted input.
      const readme = await readmeMd(env, name, v);
      main = readme
        ? `<div class="prose readme">${md(readme)}</div>`
        : `<p class="muted">This release has no README.</p>`;
      break;
    }
    case "docs": {
      const raw = await docsJson(env, name, v);
      if (raw === null) {
        return { status: 404, body: notFoundPage(`No documentation stored for ${name}@${v}.`) };
      }
      let doc: DocsArtifact;
      try {
        doc = JSON.parse(raw) as DocsArtifact;
      } catch {
        return { status: 500, body: notFoundPage("The stored documentation for this release is unreadable.") };
      }
      main = docsMain(doc);
      break;
    }
    case "versions":
      main = versionsMain(name, rows, v);
      break;
    case "deps":
      main = depsMain(deps);
      break;
    case "security":
      main = securityMain(live, v);
      break;
  }

  // The <title> reads as the section a human sees, not the route's internal slug.
  const title = tab === "readme" ? `${name} — Noeta registry` : `${name} ${v} — ${TAB_TITLES[tab]}`;
  return {
    status: 200,
    body: layout(
      title,
      `<nav class="crumb"><a href="/">registry</a> / <span>${esc(name)}</span></nav>
       <h1>${esc(name)} <span class="version">${esc(v)}</span></h1>
       <p class="badges">${provenanceBadge(selected)}${licenseBadge(selected)}${
         selected.yanked ? `<span class="badge yanked">yanked</span>` : ""
       }</p>
       ${keywordChips(keywords)}
       ${tabBar(name, v, tab, { docs: hasDocs, versions: rows.length, deps: deps.length, affecting: affecting.length })}
       <div class="pkg-grid">
         <div class="pkg-main">${main}</div>
         ${sidebar(name, selected, logIndex)}
       </div>`,
      "wide",
    ),
  };
}

/** The tab bar. Documentation is inert when the release published none — the affordance still says
 *  so, rather than the link 404ing. */
function tabBar(
  name: string,
  version: string,
  current: Tab,
  counts: { docs: boolean; versions: number; deps: number; affecting: number },
): string {
  const base = `/${esc(name)}/${esc(version)}`;
  const link = (tab: Tab, label: string, href: string) =>
    `<a class="tab${tab === current ? " is-here" : ""}"${tab === current ? ' aria-current="page"' : ""} href="${href}">${label}</a>`;
  const versions = `${counts.versions} Version${counts.versions === 1 ? "" : "s"}`;
  const deps = `${counts.deps} ${counts.deps === 1 ? "Dependency" : "Dependencies"}`;
  const security = counts.affecting
    ? `Security <span class="tab-count is-alert">${counts.affecting}</span>`
    : "Security";
  return `<nav class="tabs" aria-label="Package sections">
    ${link("readme", "Readme", base)}
    ${counts.docs ? link("docs", "Documentation", `${base}/docs`) : `<span class="tab is-off">Documentation</span>`}
    ${link("versions", versions, `${base}/versions`)}
    ${link("deps", deps, `${base}/deps`)}
    ${link("security", security, `${base}/security`)}
  </nav>`;
}

/** The metadata rail: what the release *is*, and how to depend on it. */
function sidebar(name: string, r: Row, logIndex: number | null): string {
  const provenance = r.sig ? "signed (key)" : r.bundle ? "signed (keyless)" : "unsigned";
  // The import root `noeta add` derives when the key is omitted: the `package` half of `company/pkg`.
  const key = name.split("/")[1];
  const req = `^${r.version}`;
  // Split across shell continuations rather than one long line: the rail is too narrow to show the
  // whole command, and neither truncating it (the version scrolls out of sight) nor letting it wrap
  // (line-breaking is allowed after a hyphen, so `--version` splits) is honest. This pastes as-is.
  const install = `noeta add \\\n  --package ${name} \\\n  --version ${req}`;
  // Stays a one-line inline table: TOML 1.0 inline tables may not span lines or carry a trailing
  // comma, so the pretty multi-line form would be a snippet that doesn't parse.
  const manifest = `${key} = { version = "${req}", package = "${name}" }`;
  return `<aside class="pkg-side">
    <h3>Metadata</h3>
    <table class="kv side-kv">
      <tr><td>published</td><td class="mono">${esc(r.published_at.slice(0, 10))}</td></tr>
      <tr><td>license</td><td>${r.license ? esc(r.license) : `<span class="muted">not declared</span>`}</td></tr>
      <tr><td>provenance</td><td>${esc(provenance)}</td></tr>
      <tr><td>tag</td><td class="mono">${esc(r.tag)}</td></tr>
      <!-- The full SHA, wrapped rather than truncated: the index is authoritative on
           "this version = this commit", so the value a reader verifies against must be on the page
           and selectable, not hidden behind a tooltip. -->
      <tr><td>commit</td><td class="mono sha">${esc(r.sha)}</td></tr>
      ${
        logIndex !== null
          ? `<tr><td>log entry</td><td class="mono"><a href="/v1/log/proof/${esc(name)}/${esc(r.version)}">#${logIndex}</a></td></tr>`
          : ""
      }
    </table>

    <h3>Install</h3>
    <p class="side-note">Run this in your project directory:</p>
    <pre><code>${esc(install)}</code></pre>
    <p class="side-note">Or add it to your <code>noeta.toml</code>:</p>
    <pre><code>${esc(manifest)}</code></pre>

    <h3>Repository</h3>
    ${
      /^https?:\/\//i.test(r.url)
        ? `<p><a class="button side-button" href="${esc(r.url)}">${esc(repoLabel(r.url))} →</a></p>`
        : `<p class="mono muted">${esc(r.url)}</p>`
    }
  </aside>`;
}

/** `https://github.com/acme/imgfx` → `github.com/acme/imgfx`, so the button reads as a destination. */
function repoLabel(url: string): string {
  const label = url.replace(/^https?:\/\//i, "").replace(/\.git$/i, "").replace(/\/$/, "");
  return label.length > 34 ? `${label.slice(0, 33)}…` : label;
}

function docsMain(doc: DocsArtifact): string {
  const modules = Array.isArray(doc.modules) ? doc.modules : [];
  const nav =
    modules.length > 1
      ? `<nav class="modnav"><strong>Modules</strong><ul>${modules
          .map((m) => {
            const title = m.namespace || m.file || "module";
            return `<li><a href="#mod-${slug(title)}">${esc(title)}</a></li>`;
          })
          .join("")}</ul></nav>`
      : "";
  const body = modules.length
    ? modules.map(renderModule).join("\n")
    : `<p class="muted">This release has no documented items.</p>`;
  return `${nav}${body}`;
}

function versionsMain(name: string, rows: Row[], selected: string): string {
  const versionRows = rows
    .map((r) => {
      const here = r.version === selected;
      const badges = `${provenanceBadge(r)}${r.yanked ? `<span class="badge yanked">yanked</span>` : ""}`;
      return `<tr${here ? ' class="here"' : ""}>
        <td><a href="/${esc(name)}/${esc(r.version)}">${esc(r.version)}</a></td>
        <td>${badges}</td>
        <td class="muted mono">${esc(r.published_at.slice(0, 10))}</td>
      </tr>`;
    })
    .join("");
  return `<table class="versions"><tbody>${versionRows}</tbody></table>`;
}

function depsMain(deps: { package: string; req: string }[]): string {
  if (deps.length === 0) return `<p class="muted">This release declares no dependencies.</p>`;
  return `<ul class="deps">${deps
    .map(
      (d) =>
        `<li><a href="/${esc(d.package)}">${esc(d.package)}</a> <span class="muted mono">${esc(d.req)}</span></li>`,
    )
    .join("")}</ul>`;
}

/**
 * Known advisories against this package. Each is matched against the selected release with the same
 * comparator semantics the client audits with (`src/semver.ts`), but a range this Worker cannot
 * parse is reported as *unknown* rather than silently treated as "not affected" — and `noeta audit`
 * stays the authority either way.
 */
function securityMain(advisories: AdvisoryRow[], version: string): string {
  if (advisories.length === 0) {
    return `<p class="muted">No advisories have been published against this package.</p>`;
  }
  // Match once per advisory, then sort on the result: hits first, unknowns next, misses last.
  const judged = advisories.map((a) => ({ a, hit: satisfies(version, a.ranges) }));
  const rank = (hit: boolean | null) => (hit === true ? 0 : hit === null ? 1 : 2);
  judged.sort((x, y) => rank(x.hit) - rank(y.hit));
  const items = judged
    .map(({ a, hit }) => {
      const verdict =
        hit === true
          ? `<span class="badge yanked">affects ${esc(version)}</span>`
          : hit === false
            ? `<span class="badge">${esc(version)} not affected</span>`
            : `<span class="badge">unknown for ${esc(version)}</span>`;
      return `<article class="advisory${hit === true ? " is-hit" : ""}">
        <h3><span class="sev sev-${esc(a.severity)}">${esc(a.severity)}</span> ${esc(a.summary)}</h3>
        <p class="adv-meta">
          <span class="badge mono">${esc(a.id)}</span>${verdict}
        </p>
        <table class="kv">
          <tr><td>affected</td><td class="mono">${esc(a.ranges)}</td></tr>
          ${a.patched ? `<tr><td>patched in</td><td class="mono">${esc(a.patched)}</td></tr>` : ""}
        </table>
        ${a.details ? `<div class="prose">${md(a.details)}</div>` : ""}
        ${a.url ? `<p><a href="${sanitizeUrl(a.url)}">${esc(a.url)}</a></p>` : ""}
      </article>`;
    })
    .join("");
  return `${items}<p class="side-note">Advisory data is served signed at <code>/v1/advisories</code>; <code>noeta audit</code> is the authority for whether a build is affected.</p>`;
}

function renderModule(m: DocsModule): string {
  const title = m.namespace || m.file || "module";
  const modId = slug(title);
  const items = Array.isArray(m.items) ? m.items : [];
  const isDecl = (i: DocsSection | DocsDecl): i is DocsDecl =>
    typeof (i as DocsSection).section !== "string" && !!(i as DocsDecl).name && !!(i as DocsDecl).kind;
  const decls = items.filter(isDecl);
  // A per-module contents list (jump links) for modules with several declarations — the by-module
  // API reference (e.g. std.math's 26 functions) reads as one long flat list otherwise. CSS-only.
  const toc =
    decls.length >= 3
      ? `<ul class="toc">${decls
          .map((d) => `<li><a href="#${modId}--${slug(d.name!)}"><code>${esc(d.name!)}</code></a></li>`)
          .join("")}</ul>`
      : "";
  const itemsHtml = items
    .map((item) => {
      if (typeof (item as DocsSection).section === "string") {
        return `<div class="prose">${md((item as DocsSection).section)}</div>`;
      }
      const d = item as DocsDecl;
      if (!d.name || !d.kind) return "";
      // Anchor scoped by module: two modules may each expose a `new`, so a bare `decl-new` would
      // collide across the by-module API reference.
      return `<section class="decl" id="${modId}--${slug(d.name)}">
        <h3><span class="kind">${esc(d.kind)}</span> <code>${esc(d.name)}</code></h3>
        ${d.signature ? `<pre class="sig"><code>${esc(d.signature)}</code></pre>` : ""}
        ${d.doc ? `<div class="prose">${md(d.doc)}</div>` : ""}
      </section>`;
    })
    .join("\n");
  return `<section class="module" id="mod-${modId}">
    <h2>${esc(title)}${m.file && m.namespace ? ` <span class="muted mono">${esc(m.file)}</span>` : ""}</h2>
    ${m.doc ? `<div class="prose">${md(m.doc)}</div>` : ""}
    ${toc}
    ${itemsHtml}
  </section>`;
}

/**
 * `/keywords/{keyword}` — every package carrying the tag, latest release first. The question the
 * index could not answer before: "what builds on top of para?"
 *
 * The `keywords` scope is reserved server-side (see RESERVED_WEB_SCOPES in index.ts), so this route
 * can never shadow a real package.
 */
async function keywordPage(env: Env, keyword: string): Promise<Page> {
  if (!KEYWORD.test(keyword)) {
    return { status: 404, body: notFoundPage(`\`${keyword}\` is not a keyword.`) };
  }
  // One row per tagged *release*, newest first; the newest release of each package wins the listing.
  // Bounded like the home page: a keyword on a package with many published versions returns a row
  // per version, so an unbounded scan would read far more than the page can ever show.
  const { results } = await env.DB.prepare(
    "SELECT k.name AS name, k.version AS version, p.license AS license FROM package_keywords k " +
      "JOIN packages p ON p.name = k.name AND p.version = k.version " +
      "WHERE k.keyword = ? ORDER BY p.published_at DESC LIMIT 400",
  )
    .bind(keyword)
    .all<{ name: string; version: string; license: string | null }>();

  const seen = new Set<string>();
  const packages: { name: string; version: string; license: string | null }[] = [];
  for (const r of results ?? []) {
    if (seen.has(r.name)) continue;
    seen.add(r.name);
    packages.push(r);
    if (packages.length >= 100) break;
  }

  // The true total, independent of the listing's bound — so the headline count never silently
  // undercounts once a keyword outgrows the page.
  const total =
    (
      await env.DB.prepare("SELECT COUNT(DISTINCT name) AS n FROM package_keywords WHERE keyword = ?")
        .bind(keyword)
        .first<{ n: number }>()
    )?.n ?? 0;

  const list = packages.length
    ? `<ul class="pkglist">${packages
        .map(
          (r) =>
            `<li><a href="/${esc(r.name)}">${esc(r.name)}</a> <span class="muted">${esc(r.version)}</span>${
              r.license ? ` <span class="badge license">${esc(r.license)}</span>` : ""
            }</li>`,
        )
        .join("")}</ul>${
        total > packages.length
          ? `<p class="muted">Showing ${packages.length} of ${total}.</p>`
          : ""
      }`
    : `<p class="muted">No packages are tagged <code>${esc(keyword)}</code>.</p>`;

  return {
    status: 200,
    body: layout(
      `#${keyword} — Noeta registry`,
      `<nav class="crumb"><a href="/">registry</a> / <span>keywords</span></nav>
       <p class="eyebrow">Keyword</p>
       <h1>#${esc(keyword)}</h1>
       <p class="lead">${total} package${total === 1 ? "" : "s"} tagged
       <code>${esc(keyword)}</code>.</p>
       ${list}`,
    ),
  };
}

/** A release's keywords as chips, each linking its listing. */
function keywordChips(keywords: string[]): string {
  if (keywords.length === 0) return "";
  return `<ul class="keywords">${keywords
    .map((k) => `<li><a href="/keywords/${esc(k)}">#${esc(k)}</a></li>`)
    .join("")}</ul>`;
}

function notFoundPage(message = "That page does not exist."): string {
  return layout(
    "Not found — Noeta registry",
    `<h1>Not found</h1><p class="muted">${esc(message)}</p><p><a href="/">← registry</a></p>`,
  );
}

// --- data ----------------------------------------------------------------------------------------

async function packageRows(env: Env, name: string): Promise<Row[]> {
  const { results } = await env.DB.prepare(
    "SELECT version, url, tag, sha, deps, sig, bundle, yanked, published_at, license FROM packages WHERE name = ?",
  )
    .bind(name)
    .all<Row>();
  const rows = results ?? [];
  // Highest semver first — the "latest" a bare package URL shows.
  rows.sort((a, b) => semverCompare(b.version, a.version));
  return rows;
}

async function docsExist(env: Env, name: string, version: string): Promise<boolean> {
  const row = await env.DB.prepare("SELECT 1 FROM docs WHERE name = ? AND version = ?")
    .bind(name, version)
    .first();
  return row !== null;
}

async function docsJson(env: Env, name: string, version: string): Promise<string | null> {
  const row = await env.DB.prepare("SELECT docs_json FROM docs WHERE name = ? AND version = ?")
    .bind(name, version)
    .first<{ docs_json: string }>();
  return row ? row.docs_json : null;
}

/** Every advisory naming this package, worst first. Range matching happens in the renderer, which
 *  knows which release is selected. */
async function advisoriesFor(env: Env, name: string): Promise<AdvisoryRow[]> {
  const order = `CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`;
  const { results } = await env.DB.prepare(
    `SELECT id, ranges, patched, severity, summary, details, url, withdrawn FROM advisories ` +
      `WHERE package = ? ORDER BY ${order}, id`,
  )
    .bind(name)
    .all<AdvisoryRow>();
  return results ?? [];
}

/** A release's keywords, sorted (the order they were stored in). */
async function keywordsFor(env: Env, name: string, version: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT keyword FROM package_keywords WHERE name = ? AND version = ? ORDER BY keyword",
  )
    .bind(name, version)
    .all<{ keyword: string }>();
  return (results ?? []).map((r) => r.keyword);
}

/** The release's transparency-log index, so the sidebar can link its inclusion proof. */
async function logIndexFor(env: Env, name: string, version: string): Promise<number | null> {
  const row = await env.DB.prepare("SELECT idx FROM log WHERE name = ? AND version = ?")
    .bind(name, version)
    .first<{ idx: number }>();
  return row ? row.idx : null;
}

async function readmeMd(env: Env, name: string, version: string): Promise<string | null> {
  const row = await env.DB.prepare("SELECT readme_md FROM readmes WHERE name = ? AND version = ?")
    .bind(name, version)
    .first<{ readme_md: string }>();
  return row ? row.readme_md : null;
}

/** Compare two SemVer strings (major.minor.patch, prerelease sorts before its release). Enough for
 *  ordering a package's versions "latest first"; not a full SemVer implementation. */
function semverCompare(a: string, b: string): number {
  const parse = (v: string) => {
    const [core, pre] = v.split("-", 2);
    const nums = core.split(".").map((n) => parseInt(n, 10) || 0);
    return { nums, pre };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  // A prerelease is lower than the same core release; otherwise compare prerelease strings.
  if (pa.pre && !pb.pre) return -1;
  if (!pa.pre && pb.pre) return 1;
  if (pa.pre && pb.pre) return pa.pre < pb.pre ? -1 : pa.pre > pb.pre ? 1 : 0;
  return 0;
}

function parseDeps(raw: string): { package: string; req: string }[] {
  try {
    const p = JSON.parse(raw);
    return Array.isArray(p) ? p : [];
  } catch {
    return [];
  }
}

// --- rendering helpers ---------------------------------------------------------------------------

interface DocsArtifact {
  schema?: number;
  package?: { name?: string; version?: string } | null;
  modules?: DocsModule[];
}
interface DocsModule {
  file?: string;
  namespace?: string | null;
  doc?: string | null;
  items?: (DocsSection | DocsDecl)[];
}
interface DocsSection {
  section: string;
}
interface DocsDecl {
  kind?: string;
  name?: string;
  signature?: string;
  doc?: string | null;
  public?: boolean;
}

function provenanceBadge(r: Row): string {
  if (r.sig) return `<span class="badge signed">signed · key</span>`;
  if (r.bundle) return `<span class="badge signed">signed · keyless</span>`;
  return `<span class="badge unsigned">unsigned</span>`;
}

/** The release's declared SPDX license (publisher-asserted — the SHA-pinned source is the ground
 *  truth), or nothing when the release declared none. */
function licenseBadge(r: Row): string {
  return r.license ? `<span class="badge license">${esc(r.license)}</span>` : "";
}


function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** A stable, safe anchor slug from a title/name. */
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "x";
}

/**
 * Render a **small, safe Markdown subset** to HTML. Escape-first (the input is publisher-supplied),
 * then apply block + inline formatting on the escaped text — Markdown's syntax characters
 * (`# * ` [ ] ( ) -`) survive HTML escaping, so parsing after escaping is sound and injection-proof.
 * Supports: fenced code, ATX headings, unordered lists, paragraphs; inline code, bold, italic, and
 * scheme-sanitized links.
 */
function md(input: string): string {
  const escaped = esc(input);
  const lines = escaped.split("\n");
  const out: string[] = [];
  let i = 0;
  let para: string[] = [];
  const flushPara = () => {
    if (para.length) {
      out.push(`<p>${inline(para.join(" "))}</p>`);
      para = [];
    }
  };
  while (i < lines.length) {
    const line = lines[i];
    // Fenced code block.
    if (line.trimStart().startsWith("```")) {
      flushPara();
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        code.push(lines[i]);
        i++;
      }
      i++; // consume closing fence
      out.push(`<pre><code>${code.join("\n")}</code></pre>`);
      continue;
    }
    // ATX heading — offset by +2 so a doc `#` nests under the page's h1/h2 as an h3.
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      flushPara();
      const level = Math.min(6, h[1].length + 2);
      out.push(`<h${level}>${inline(h[2])}</h${level}>`);
      i++;
      continue;
    }
    // Unordered list.
    if (/^\s*[-*]\s+/.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(`<li>${inline(lines[i].replace(/^\s*[-*]\s+/, ""))}</li>`);
        i++;
      }
      out.push(`<ul>${items.join("")}</ul>`);
      continue;
    }
    // Blank line ends a paragraph.
    if (line.trim() === "") {
      flushPara();
      i++;
      continue;
    }
    para.push(line);
    i++;
  }
  flushPara();
  return out.join("\n");
}

/** Inline Markdown on already-escaped text: code spans (protected first), links, bold, italic. */
function inline(text: string): string {
  // Protect inline-code spans so bold/italic never fire inside them. The placeholder is
  // NUL-delimited (`\x00N\x00`) so it can't collide with real content the way a bare
  // ` 2 ` in prose would (which would restore to `undefined`); escaped text never has NUL.
  const codes: string[] = [];
  let s = text.replace(/`([^`]+)`/g, (_m, c) => {
    codes.push(`<code>${c}</code>`);
    return `\x00${codes.length - 1}\x00`;
  });
  // Links [text](url) — url is scheme-sanitized; a rejected scheme renders as the bare text.
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label, url) => {
    const safe = sanitizeUrl(url);
    return safe ? `<a href="${safe}" rel="nofollow noopener">${label}</a>` : label;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>");
  s = s.replace(/_([^_]+)_/g, "<em>$1</em>");
  // Restore code spans.
  s = s.replace(/\x00(\d+)\x00/g, (_m, n) => codes[Number(n)]);
  return s;
}

/**
 * Allow only http(s), root-relative, anchor, and mailto URLs — everything else (notably
 * `javascript:`) is rejected so a doc link can't run script. The input is HTML-escaped, so it is
 * already safe to place in an attribute; this gates the *scheme*.
 */
function sanitizeUrl(url: string): string | null {
  const u = url.trim();
  if (/^https?:\/\//i.test(u)) return u;
  if (u.startsWith("/") || u.startsWith("#") || /^mailto:/i.test(u)) return u;
  return null;
}

// --- HTML shell ----------------------------------------------------------------------------------

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      // The page renders only its own inline styles and no scripts — a strict CSP is cheap defense
      // in depth over the escape-first renderer. The two Google Fonts hosts are the only concession,
      // so the registry can wear the shared "Signal" typography without bundling font binaries.
      "content-security-policy":
        "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src https://fonts.gstatic.com; img-src https:",
    },
  });
}

/**
 * The shared page shell. The registry has no build step (it is a dependency-free Worker), so rather
 * than importing `@noeta/theme` the way the Astro sites do, its tokens + chrome are inlined here —
 * the same "Signal" design language as noeta.dev, docs, and the playground: a cool slate theme with
 * a blue human accent and a mint machine accent, the atmospheric `.field` backdrop, a paper light
 * mode that follows the browser preference, and the Inter / JetBrains Mono pair from Google Fonts.
 */
function layout(title: string, body: string, variant: "" | "wide" = ""): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#0b0d10">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#f6f8fb">
<title>${esc(title)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300..700&family=JetBrains+Mono:ital,wght@0,400..600;1,400&display=swap');
:root{
--bg:#0b0d10;--surface-1:#111419;--surface-2:#171b21;--surface-3:#1f242c;
--text-0:#e8ebef;--text-1:#a3adba;--text-2:#69727e;
--accent:#4f8ff7;--accent-bright:#7aa9ff;--accent-dim:rgba(79,143,247,.14);
--accent-2:#4fe0a8;--accent-2-bright:#7defc0;--danger:#e5766a;
--syn-string:#8fd6a0;--syn-number:#e0a878;
--line:rgba(233,237,243,.08);--line-strong:rgba(233,237,243,.14);
--font-body:"Inter","Segoe UI",system-ui,sans-serif;
--font-mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
--max:60rem;--radius:12px;color-scheme:dark;
}
*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text-0);font-family:var(--font-body);font-size:1.0313rem;line-height:1.65;font-weight:400;letter-spacing:-.006em;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:inherit;text-decoration:none}
::selection{background:rgba(79,143,247,.3);color:#fff}
/* atmosphere */
.field{position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(58rem 40rem at 84% -12%,rgba(79,143,247,.1),transparent 60%),radial-gradient(52rem 40rem at -6% 108%,rgba(79,224,168,.055),transparent 58%),var(--bg)}
.field::after{content:"";position:absolute;inset:0;opacity:.02;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2'/%3E%3C/filter%3E%3Crect width='140' height='140' filter='url(%23n)'/%3E%3C/svg%3E")}
/* header */
.wrap{max-width:var(--max);margin-inline:auto;padding-inline:clamp(1.25rem,4vw,2.5rem)}
.site-head{position:sticky;top:0;z-index:10;backdrop-filter:blur(16px);background:color-mix(in srgb,var(--bg) 72%,transparent);border-bottom:1px solid var(--line)}
.site-head .wrap{display:flex;align-items:center;justify-content:space-between;height:3.75rem}
.wordmark{font-family:var(--font-body);font-size:1.2rem;font-weight:620;letter-spacing:-.02em;color:var(--text-0)}
.wordmark .tld{color:var(--text-2);font-weight:500}
.site-nav{display:flex;gap:clamp(1rem,3vw,1.9rem);align-items:center;font-family:var(--font-mono);font-size:.82rem}
.site-nav a{color:var(--text-1);transition:color 160ms ease}.site-nav a:hover{color:var(--accent-bright)}
@media (max-width:38rem){.site-head .wrap{height:auto;flex-wrap:wrap;gap:.1rem 1rem;padding-block:.7rem}}
/* main */
.page{max-width:var(--max);margin-inline:auto;padding:clamp(2rem,5vh,3.25rem) clamp(1.25rem,4vw,2.5rem) 5rem}
.eyebrow{display:inline-flex;align-items:center;gap:.55rem;font-family:var(--font-mono);font-size:.75rem;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);font-weight:500;margin-bottom:.5rem}
.eyebrow::before{content:"";width:1.4rem;height:1px;background:currentColor;opacity:.6}
h1{font-family:var(--font-body);font-weight:640;font-size:clamp(2.1rem,5vw,3rem);line-height:1.08;letter-spacing:-.03em;margin:.1rem 0 .6rem}
h2{font-family:var(--font-body);font-weight:600;font-size:clamp(1.4rem,3vw,1.8rem);line-height:1.15;letter-spacing:-.02em;margin:2.4rem 0 .7rem;padding-bottom:.35rem;border-bottom:1px solid var(--line)}
h3{font-family:var(--font-body);font-weight:600;font-size:1.08rem;letter-spacing:-.01em;margin:1.4rem 0 .4rem}
.lead{color:var(--text-1);max-width:60ch;font-size:1.08rem}
.version{font-family:var(--font-mono);color:var(--accent-2);font-weight:500;font-size:.95em}
.crumb{font-family:var(--font-mono);color:var(--text-2);font-size:.82rem;letter-spacing:.02em;margin-bottom:1.4rem}
.crumb a{color:var(--text-1)}.crumb a:hover{color:var(--accent-bright)}
.muted{color:var(--text-2)}
.mono{font-family:var(--font-mono);font-size:.88em}
.page a{color:var(--accent-bright)}.page a:hover{color:var(--accent);text-decoration:underline}
/* badges */
.badge{display:inline-block;font-family:var(--font-mono);font-size:.72rem;letter-spacing:.02em;padding:.14rem .6rem;border-radius:999px;border:1px solid var(--line-strong);background:color-mix(in srgb,var(--surface-2) 70%,transparent);color:var(--text-1);margin-right:.35rem;vertical-align:middle}
.badge.signed{color:var(--syn-string);border-color:color-mix(in srgb,var(--syn-string) 40%,var(--line-strong))}
.badge.unsigned{color:var(--text-2)}
.badge.yanked{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 45%,var(--line-strong))}
.badge.license{color:var(--text-0)}
/* buttons */
.button{display:inline-flex;align-items:center;gap:.5rem;font-family:var(--font-mono);font-size:.875rem;font-weight:500;padding:.6rem 1.2rem;border-radius:8px;border:1px solid var(--line-strong);color:var(--text-0);transition:border-color 180ms ease,background 180ms ease,transform 180ms ease,color 180ms ease}
.page a.button{color:var(--text-0)}
.button:hover{border-color:var(--accent);background:var(--accent-dim);color:var(--accent-bright);transform:translateY(-1px)}
/* out-specifies .page a:hover, which would otherwise underline a button's label */
.page a.button:hover{text-decoration:none}
/* package shell: tab bar + metadata rail. Tabs are links (the CSP forbids scripts), so each
   section is its own URL and stays linkable/back-navigable. */
.page.wide{max-width:76rem}
.badges{margin:.2rem 0 .7rem}
/* keyword chips — the machine accent, since they are index terms rather than prose */
ul.keywords{list-style:none;padding:0;margin:0 0 1.15rem;display:flex;flex-wrap:wrap;gap:.35rem .45rem}
ul.keywords li{padding:0}
.page ul.keywords a{display:inline-block;padding:.1rem .6rem;border:1px solid var(--line-strong);border-radius:999px;background:color-mix(in srgb,var(--surface-2) 60%,transparent);color:var(--text-1);font-family:var(--font-mono);font-size:.75rem}
.page ul.keywords a:hover{border-color:var(--accent-2);color:var(--accent-2-bright);text-decoration:none}
.tabs{display:flex;flex-wrap:wrap;gap:.1rem;border-bottom:1px solid var(--line);margin:0 0 1.7rem}
.tab{display:inline-flex;align-items:center;gap:.45rem;padding:.55rem .95rem;font-family:var(--font-mono);font-size:.84rem;color:var(--text-1);border-bottom:2px solid transparent;margin-bottom:-1px;transition:color 160ms ease,border-color 160ms ease}
.page a.tab:hover{color:var(--text-0);border-bottom-color:var(--line-strong);text-decoration:none}
.page a.tab.is-here{color:var(--accent-bright);border-bottom-color:var(--accent)}
.tab.is-off{color:var(--text-2);opacity:.5}
.tab-count{font-family:var(--font-mono);font-size:.7rem;padding:.04rem .42rem;border-radius:999px;background:var(--surface-3);color:var(--text-1)}
.tab-count.is-alert{background:color-mix(in srgb,var(--danger) 20%,transparent);color:var(--danger)}
.pkg-grid{display:grid;grid-template-columns:minmax(0,1fr) 17.5rem;gap:clamp(1.5rem,4vw,3rem);align-items:start}
.pkg-main{min-width:0}
.pkg-main>:first-child{margin-top:0}
.pkg-side{position:sticky;top:4.75rem}
.pkg-side h3{margin:1.6rem 0 .5rem;font-family:var(--font-mono);font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--text-2);font-weight:500}
.pkg-side h3:first-child{margin-top:0}
.side-kv td{font-size:.85rem;padding:.3rem .5rem .3rem 0}
.side-kv td:first-child{width:6.4rem}
/* a hex SHA is one unbroken "word" — let it wrap so the whole value stays visible */
.side-kv td.sha{font-size:.78rem;overflow-wrap:anywhere;line-height:1.45}
.side-note{font-size:.82rem;color:var(--text-2);margin:.55rem 0 .35rem}
/* Snippets never wrap: line-breaking is allowed after a hyphen, so a wrapped "--version" splits
   across lines and reads as a typo. The install command carries its own shell continuations; the
   one-line TOML table scrolls. */
.pkg-side pre{padding:.55rem .7rem;white-space:pre;overflow-x:auto}
.pkg-side pre code{font-size:.75rem;line-height:1.55}
.side-button{width:100%;justify-content:center;font-size:.78rem;padding:.5rem .7rem}
@media (max-width:52rem){.pkg-grid{grid-template-columns:1fr}.pkg-side{position:static;order:-1}}
/* advisories */
.advisory{border:1px solid var(--line);border-radius:var(--radius);padding:1rem 1.15rem;margin:0 0 1rem;background:color-mix(in srgb,var(--surface-1) 55%,transparent)}
.advisory.is-hit{border-color:color-mix(in srgb,var(--danger) 45%,var(--line-strong))}
.advisory h3{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;margin:0 0 .5rem}
.advisory table.kv{margin:.2rem 0 .6rem}
.adv-meta{margin:.35rem 0 .7rem}
.sev{font-family:var(--font-mono);font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;padding:.12rem .5rem;border-radius:999px;border:1px solid var(--line-strong);color:var(--text-1)}
.sev-critical,.sev-high{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 45%,var(--line-strong));background:color-mix(in srgb,var(--danger) 12%,transparent)}
.sev-medium{color:var(--syn-number);border-color:color-mix(in srgb,var(--syn-number) 40%,var(--line-strong))}
/* package list */
ul.pkglist{list-style:none;padding:0;margin:.6rem 0 0}
ul.pkglist li{display:flex;align-items:baseline;flex-wrap:wrap;gap:.55rem;padding:.6rem .2rem;border-bottom:1px solid var(--line)}
ul.pkglist li:hover{background:color-mix(in srgb,var(--surface-1) 55%,transparent)}
.page ul.pkglist a{color:var(--text-0);font-weight:500}.page ul.pkglist a:hover{color:var(--accent-bright);text-decoration:none}
/* tables */
table{border-collapse:collapse;width:100%}
table.kv td{padding:.35rem .6rem .35rem 0;vertical-align:top;border-bottom:1px solid var(--line)}
table.kv td:first-child{font-family:var(--font-mono);color:var(--text-2);width:8rem;font-size:.85rem}
table.versions td{padding:.45rem .6rem;border-bottom:1px solid var(--line)}
table.versions tr.here{background:var(--accent-dim)}
/* deps + nav */
ul.deps,.modnav ul{list-style:none;padding:0}
ul.deps li{padding:.3rem 0;border-bottom:1px solid var(--line)}
.modnav{background:color-mix(in srgb,var(--surface-1) 75%,transparent);border:1px solid var(--line);border-radius:var(--radius);padding:.8rem 1.1rem;margin:1.2rem 0}
.modnav strong{font-family:var(--font-mono);font-size:.78rem;letter-spacing:.08em;text-transform:uppercase;color:var(--accent)}
.modnav ul{margin:.5rem 0 0;display:flex;flex-wrap:wrap;gap:.3rem 1rem}
ul.toc{list-style:none;padding:0;margin:.4rem 0 1.3rem;display:flex;flex-wrap:wrap;gap:.35rem .55rem}
ul.toc li{padding:0}
.page ul.toc a{display:inline-block;padding:.1rem .55rem;border:1px solid var(--line);border-radius:999px;background:color-mix(in srgb,var(--surface-2) 55%,transparent);color:var(--text-1);font-size:.82rem}
.page ul.toc a:hover{border-color:var(--accent);color:var(--accent-bright);text-decoration:none}
/* code */
pre{background:color-mix(in srgb,var(--surface-1) 88%,transparent);border:1px solid var(--line-strong);border-radius:var(--radius);padding:.9rem 1.05rem;overflow:auto}
pre code,code{font-family:var(--font-mono);font-size:.86em}
:not(pre)>code{background:var(--surface-3);border:1px solid var(--line);padding:.08em .38em;border-radius:5px;color:var(--text-0)}
pre.sig code{color:var(--text-0)}
/* declarations + prose */
.decl{margin:1.4rem 0}
.kind{font-family:var(--font-mono);color:var(--accent-2);font-weight:500;font-size:.72em;letter-spacing:.06em;text-transform:uppercase}
.prose{max-width:65ch;color:var(--text-1)}.prose p{margin:.6rem 0}
.prose.readme{margin-top:.6rem}
.module{margin:1.8rem 0 2.8rem}
/* footer */
.site-foot{border-top:1px solid var(--line);padding-block:2.6rem 3rem}
.site-foot .wrap{display:flex;flex-wrap:wrap;gap:1.2rem 2.4rem;align-items:baseline;justify-content:space-between}
.site-foot .tagline{font-family:var(--font-body);font-weight:600;font-size:1.05rem;letter-spacing:-.015em}
.site-foot .tagline em{color:var(--accent);font-style:normal}
.foot-nav{display:flex;flex-wrap:wrap;gap:1.4rem;font-family:var(--font-mono);font-size:.84rem}
.foot-nav a{color:var(--text-2);transition:color 160ms ease}.foot-nav a:hover{color:var(--accent-bright)}
.foot-meta{width:100%;margin-top:.4rem;font-size:.84rem;color:var(--text-2)}
/* light mode — follows the browser preference */
@media (prefers-color-scheme:light){
:root{--bg:#f6f8fb;--surface-1:#fff;--surface-2:#eceff5;--surface-3:#e4e8f0;--text-0:#14181f;--text-1:#47515f;--text-2:#6c7686;--accent:#2767d6;--accent-bright:#1a55c0;--accent-dim:rgba(39,103,214,.1);--accent-2:#0c8a66;--accent-2-bright:#097053;--danger:#cf3b2f;--syn-string:#3f8f4f;--syn-number:#b5651d;--line:rgba(20,24,31,.1);--line-strong:rgba(20,24,31,.16);color-scheme:light}
.field{background:radial-gradient(58rem 40rem at 84% -12%,rgba(39,103,214,.07),transparent 60%),radial-gradient(52rem 40rem at -6% 108%,rgba(12,138,102,.05),transparent 58%),var(--bg)}
.field::after{opacity:.012}
::selection{background:rgba(39,103,214,.18);color:var(--text-0)}
}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}.button{transition:none}}
</style>
</head>
<body>
<div class="field" aria-hidden="true"></div>
<header class="site-head">
<div class="wrap">
<a class="wordmark" href="/">noeta<span class="tld">.dev/registry</span></a>
<nav class="site-nav" aria-label="Site">
<a href="https://noeta.dev">noeta.dev</a>
<a href="https://docs.noeta.dev">docs</a>
<a href="https://play.noeta.dev">playground</a>
<a href="https://github.com/noeta-lang/noeta">github</a>
</nav>
</div>
</header>
<main class="page${variant ? ` ${variant}` : ""}">
${body}
</main>
<footer class="site-foot">
<div class="wrap">
<span class="tagline">AI-native, <em>human-first.</em></span>
<nav class="foot-nav" aria-label="Footer">
<a href="https://noeta.dev">noeta.dev</a>
<a href="https://docs.noeta.dev">docs</a>
<a href="https://play.noeta.dev">playground</a>
<a href="https://github.com/noeta-lang/noeta">github</a>
</nav>
<p class="foot-meta">Noeta is pre-alpha and built in the open — anything may change without notice.</p>
</div>
</footer>
</body>
</html>`;
}

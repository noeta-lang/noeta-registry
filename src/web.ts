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

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;

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
  // `/{company}/{package}[/{version}[/docs]]`
  const [company, pkg, version, sub] = parts;
  if (
    parts.length >= 2 &&
    parts.length <= 4 &&
    IDENT.test(company) &&
    IDENT.test(pkg) &&
    (version === undefined || SEMVER.test(version)) &&
    (sub === undefined || sub === "docs")
  ) {
    const name = `${company}/${pkg}`;
    if (parts.length === 4 && sub === "docs") return docsPage(env, name, version);
    return packagePage(env, name, version);
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
     <p class="lead">The package index for <a href="https://noeta.dev">Noeta</a>. An index, not a code
     store: each release maps to the git coordinates its source lives at, with pinned commit and
     optional provenance. Browse published packages and their documentation below.</p>
     <h2>Recently published</h2>
     ${list}`,
  );
}

async function packagePage(env: Env, name: string, version?: string): Promise<Page> {
  const rows = await packageRows(env, name);
  if (rows.length === 0) {
    return { status: 404, body: notFoundPage(`No package \`${name}\` is published.`) };
  }
  const selected = version ? rows.find((r) => r.version === version) : rows[0];
  if (!selected) {
    return { status: 404, body: notFoundPage(`${name} has no version ${version}.`) };
  }

  const deps = parseDeps(selected.deps);
  const depsHtml = deps.length
    ? `<ul class="deps">${deps
        .map(
          (d) =>
            `<li><a href="/${esc(d.package)}">${esc(d.package)}</a> <span class="muted">${esc(d.req)}</span></li>`,
        )
        .join("")}</ul>`
    : `<p class="muted">No dependencies.</p>`;

  const hasDocs = await docsExist(env, name, selected.version);
  const docsLink = hasDocs
    ? `<a class="button" href="/${esc(name)}/${esc(selected.version)}/docs">Documentation →</a>`
    : `<span class="muted">No documentation published.</span>`;

  // The publisher-uploaded README (npm/crates.io model), rendered through the same escape-first
  // markdown renderer as doc prose — publisher markdown is untrusted input.
  const readme = await readmeMd(env, name, selected.version);
  const readmeHtml = readme ? `<h2>README</h2><div class="prose readme">${md(readme)}</div>` : "";

  const versionRows = rows
    .map((r) => {
      const here = r.version === selected.version;
      const badges = `${provenanceBadge(r)}${r.yanked ? `<span class="badge yanked">yanked</span>` : ""}`;
      return `<tr${here ? ' class="here"' : ""}>
        <td><a href="/${esc(name)}/${esc(r.version)}">${esc(r.version)}</a></td>
        <td>${badges}</td>
        <td class="muted mono">${esc(r.published_at.slice(0, 10))}</td>
      </tr>`;
    })
    .join("");

  return {
    status: 200,
    body: layout(
    `${name} — Noeta registry`,
    `<nav class="crumb"><a href="/">registry</a> / <span>${esc(name)}</span></nav>
     <h1>${esc(name)} <span class="version">${esc(selected.version)}</span></h1>
     <p>${provenanceBadge(selected)}${licenseBadge(selected)}${selected.yanked ? `<span class="badge yanked">yanked</span>` : ""}</p>
     <p class="actions">${docsLink}</p>
     ${readmeHtml}

     <h2>Source</h2>
     <table class="kv">
       <tr><td>repository</td><td>${repoLink(selected.url)}</td></tr>
       <tr><td>tag</td><td class="mono">${esc(selected.tag)}</td></tr>
       <tr><td>commit</td><td class="mono">${esc(selected.sha)}</td></tr>
     </table>

     <h2>Dependencies</h2>
     ${depsHtml}

     <h2>Versions</h2>
     <table class="versions"><tbody>${versionRows}</tbody></table>`,
    ),
  };
}

async function docsPage(env: Env, name: string, version: string): Promise<Page> {
  const raw = await docsJson(env, name, version);
  if (raw === null) {
    return { status: 404, body: notFoundPage(`No documentation stored for ${name}@${version}.`) };
  }
  let doc: DocsArtifact;
  try {
    doc = JSON.parse(raw) as DocsArtifact;
  } catch {
    return { status: 500, body: notFoundPage("The stored documentation for this release is unreadable.") };
  }

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

  return {
    status: 200,
    body: layout(
      `${name} ${version} — documentation`,
      `<nav class="crumb"><a href="/">registry</a> / <a href="/${esc(name)}">${esc(name)}</a> / <span>${esc(version)} docs</span></nav>
       <h1>${esc(name)} <span class="version">${esc(version)}</span></h1>
       ${nav}
       ${body}`,
    ),
  };
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

/** A git URL becomes a link only for http(s); anything else renders as escaped text. */
function repoLink(url: string): string {
  if (/^https?:\/\//i.test(url)) return `<a href="${esc(url)}" class="mono">${esc(url)}</a>`;
  return `<span class="mono">${esc(url)}</span>`;
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
      // so the registry can wear the shared "Ink & Signal" typography without bundling font binaries.
      "content-security-policy":
        "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src https://fonts.gstatic.com; img-src https:",
    },
  });
}

/**
 * The shared page shell. The registry has no build step (it is a dependency-free Worker), so rather
 * than importing `@noeta/theme` the way the Astro sites do, its tokens + chrome are inlined here —
 * the same "Ink & Signal" design language as noeta.dev, docs, and the playground: a warm near-black
 * editorial dark theme, one amber `--signal` accent, the atmospheric `.field` backdrop, and the
 * Instrument Serif / Hanken Grotesk / Spline Sans Mono type trio pulled from Google Fonts.
 */
function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#131110">
<title>${esc(title)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Hanken+Grotesk:wght@300..700&family=Spline+Sans+Mono:ital,wght@0,300..600;1,400&display=swap');
:root{
--ink-0:#131110;--ink-1:#191715;--ink-2:#211e1b;--ink-3:#2b2723;
--paper-0:#ece7da;--paper-1:#b9b2a1;--paper-2:#837d6f;
--signal:#e69f37;--signal-bright:#ffc46b;--signal-dim:rgba(230,159,55,.14);
--syn-string:#a9c181;--syn-number:#e6836a;
--line:rgba(236,231,218,.1);--line-strong:rgba(236,231,218,.18);
--font-display:"Instrument Serif","Georgia",serif;
--font-body:"Hanken Grotesk","Segoe UI",system-ui,sans-serif;
--font-mono:"Spline Sans Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
--max:60rem;--radius:10px;color-scheme:dark;
}
*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--ink-0);color:var(--paper-0);font-family:var(--font-body);font-size:1.0313rem;line-height:1.65;font-weight:380;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:inherit;text-decoration:none}
::selection{background:rgba(230,159,55,.28);color:var(--paper-0)}
/* atmosphere */
.field{position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(90rem 44rem at 78% -18%,rgba(230,159,55,.09),transparent 62%),radial-gradient(70rem 40rem at -12% 112%,rgba(127,187,179,.05),transparent 60%),var(--ink-0)}
.field::before{content:"";position:absolute;inset:0;background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);background-size:72px 72px;mask-image:radial-gradient(100rem 60rem at 70% -10%,rgba(0,0,0,.55),transparent 70%)}
.field::after{content:"";position:absolute;inset:0;opacity:.05;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2'/%3E%3C/filter%3E%3Crect width='140' height='140' filter='url(%23n)' opacity='0.6'/%3E%3C/svg%3E")}
/* header */
.wrap{max-width:var(--max);margin-inline:auto;padding-inline:clamp(1.25rem,4vw,2.5rem)}
.site-head{position:sticky;top:0;z-index:10;backdrop-filter:blur(14px);background:color-mix(in srgb,var(--ink-0) 72%,transparent);border-bottom:1px solid var(--line)}
.site-head .wrap{display:flex;align-items:center;justify-content:space-between;height:3.75rem}
.wordmark{font-family:var(--font-display);font-size:1.55rem;letter-spacing:.01em;color:var(--paper-0)}
.wordmark .tld{color:var(--paper-2);font-style:italic}
.site-nav{display:flex;gap:clamp(1rem,3vw,2rem);align-items:center;font-family:var(--font-mono);font-size:.875rem}
.site-nav a{color:var(--paper-1);transition:color 160ms ease}.site-nav a:hover{color:var(--signal-bright)}
@media (max-width:38rem){.site-head .wrap{height:auto;flex-wrap:wrap;gap:.1rem 1rem;padding-block:.65rem}}
/* main */
.page{max-width:var(--max);margin-inline:auto;padding:clamp(2rem,5vh,3.25rem) clamp(1.25rem,4vw,2.5rem) 5rem}
.eyebrow{font-family:var(--font-mono);font-size:.8125rem;letter-spacing:.14em;text-transform:uppercase;color:var(--signal);font-weight:500;margin-bottom:.4rem}
.eyebrow::before{content:"// ";color:var(--paper-2)}
h1{font-family:var(--font-display);font-weight:400;font-size:clamp(2.3rem,5vw,3.2rem);line-height:1.04;letter-spacing:-.01em;margin:.1rem 0 .6rem}
h2{font-family:var(--font-display);font-weight:400;font-size:clamp(1.45rem,3vw,1.9rem);line-height:1.1;margin:2.4rem 0 .7rem;padding-bottom:.35rem;border-bottom:1px solid var(--line)}
h3{font-family:var(--font-body);font-weight:600;font-size:1.08rem;margin:1.4rem 0 .4rem}
.lead{color:var(--paper-1);max-width:60ch;font-size:1.08rem}
.version{font-family:var(--font-mono);color:var(--signal);font-weight:400;font-size:.95em}
.crumb{font-family:var(--font-mono);color:var(--paper-2);font-size:.82rem;letter-spacing:.02em;margin-bottom:1.4rem}
.crumb a{color:var(--paper-1)}.crumb a:hover{color:var(--signal-bright)}
.muted{color:var(--paper-2)}
.mono{font-family:var(--font-mono);font-size:.88em}
.page a{color:var(--signal-bright)}.page a:hover{color:var(--signal);text-decoration:underline}
/* badges */
.badge{display:inline-block;font-family:var(--font-mono);font-size:.72rem;letter-spacing:.02em;padding:.14rem .6rem;border-radius:999px;border:1px solid var(--line-strong);background:color-mix(in srgb,var(--ink-2) 70%,transparent);color:var(--paper-1);margin-right:.35rem;vertical-align:middle}
.badge.signed{color:var(--syn-string);border-color:color-mix(in srgb,var(--syn-string) 40%,var(--line-strong))}
.badge.unsigned{color:var(--paper-2)}
.badge.yanked{color:var(--syn-number);border-color:color-mix(in srgb,var(--syn-number) 45%,var(--line-strong))}
.badge.license{color:var(--paper-0)}
/* buttons */
.button{display:inline-flex;align-items:center;gap:.5rem;font-family:var(--font-mono);font-size:.9rem;font-weight:500;padding:.6rem 1.2rem;border-radius:999px;border:1px solid var(--line-strong);color:var(--paper-0);transition:border-color 180ms ease,background 180ms ease,transform 180ms ease}
.page a.button{color:var(--paper-0)}
.button:hover{border-color:var(--signal);background:var(--signal-dim);transform:translateY(-1px);text-decoration:none}
.actions{margin:1.4rem 0}
/* package list */
ul.pkglist{list-style:none;padding:0;margin:.6rem 0 0}
ul.pkglist li{display:flex;align-items:baseline;flex-wrap:wrap;gap:.55rem;padding:.6rem .2rem;border-bottom:1px solid var(--line)}
ul.pkglist li:hover{background:color-mix(in srgb,var(--ink-1) 55%,transparent)}
.page ul.pkglist a{color:var(--paper-0);font-weight:500}.page ul.pkglist a:hover{color:var(--signal-bright);text-decoration:none}
/* tables */
table{border-collapse:collapse;width:100%}
table.kv td{padding:.35rem .6rem .35rem 0;vertical-align:top;border-bottom:1px solid var(--line)}
table.kv td:first-child{font-family:var(--font-mono);color:var(--paper-2);width:8rem;font-size:.85rem}
table.versions td{padding:.45rem .6rem;border-bottom:1px solid var(--line)}
table.versions tr.here{background:var(--signal-dim)}
/* deps + nav */
ul.deps,.modnav ul{list-style:none;padding:0}
ul.deps li{padding:.3rem 0;border-bottom:1px solid var(--line)}
.modnav{background:color-mix(in srgb,var(--ink-1) 75%,transparent);border:1px solid var(--line);border-radius:var(--radius);padding:.8rem 1.1rem;margin:1.2rem 0}
.modnav strong{font-family:var(--font-mono);font-size:.78rem;letter-spacing:.08em;text-transform:uppercase;color:var(--signal)}
.modnav ul{margin:.5rem 0 0;display:flex;flex-wrap:wrap;gap:.3rem 1rem}
ul.toc{list-style:none;padding:0;margin:.4rem 0 1.3rem;display:flex;flex-wrap:wrap;gap:.35rem .55rem}
ul.toc li{padding:0}
.page ul.toc a{display:inline-block;padding:.1rem .55rem;border:1px solid var(--line);border-radius:999px;background:color-mix(in srgb,var(--ink-2) 55%,transparent);color:var(--paper-1);font-size:.82rem}
.page ul.toc a:hover{border-color:var(--signal);color:var(--signal-bright);text-decoration:none}
/* code */
pre{background:color-mix(in srgb,var(--ink-1) 88%,transparent);border:1px solid var(--line-strong);border-radius:var(--radius);padding:.9rem 1.05rem;overflow:auto}
pre code,code{font-family:var(--font-mono);font-size:.86em}
:not(pre)>code{background:var(--ink-3);border:1px solid var(--line);padding:.08em .38em;border-radius:5px;color:var(--paper-0)}
pre.sig code{color:var(--paper-0)}
/* declarations + prose */
.decl{margin:1.4rem 0}
.kind{font-family:var(--font-mono);color:var(--signal);font-weight:400;font-size:.72em;letter-spacing:.06em;text-transform:uppercase}
.prose{max-width:65ch;color:var(--paper-1)}.prose p{margin:.6rem 0}
.prose.readme{margin-top:.6rem}
.module{margin:1.8rem 0 2.8rem}
/* footer */
.site-foot{border-top:1px solid var(--line);padding-block:2.6rem 3rem}
.site-foot .wrap{display:flex;flex-wrap:wrap;gap:1.2rem 2.4rem;align-items:baseline;justify-content:space-between}
.site-foot .tagline{font-family:var(--font-display);font-size:1.25rem}
.site-foot .tagline em{color:var(--signal);font-style:italic}
.foot-nav{display:flex;flex-wrap:wrap;gap:1.4rem;font-family:var(--font-mono);font-size:.84rem}
.foot-nav a{color:var(--paper-2);transition:color 160ms ease}.foot-nav a:hover{color:var(--signal-bright)}
.foot-meta{width:100%;margin-top:.4rem;font-size:.84rem;color:var(--paper-2)}
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
<main class="page">
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
<p class="foot-meta">An index, not a code store — releases map to git coordinates; docs are advisory metadata. Noeta is pre-alpha and built in the open.</p>
</div>
</footer>
</body>
</html>`;
}

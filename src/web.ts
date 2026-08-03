// Noeta registry — the public, read-only **web browser** (docs-ingestion follow-up).
//
// Everything under a path that is not `/v1` is the human surface: a package/version browser and a
// docs.rs-style renderer of the `docs.json` artifacts `noeta publish` stores. It is entirely
// **public and read-only** — it renders already-public index data (listings, versions, deps,
// provenance) and stored docs, so it needs no auth, no sessions, and no account model. The JSON
// API under `/v1` is untouched.
//
// Markdown rendering is delegated to markdown-it (bundled at build time), configured **escape-first**:
// `html: false` means publisher-supplied HTML is always rendered as escaped text, and markdown-it's
// default link validation refuses `javascript:` and friends — so a malicious `docs.json` or README
// cannot inject script. The page CSP (default-src 'none', hash-pinned scripts) backs this as defense
// in depth, and the XSS suite in web.test.ts pins the behavior.

import MarkdownIt from "markdown-it";
import { renderHeader, renderFooter, DRAWER_SCRIPT } from "@noeta/theme/chrome";
import { COPY_SCRIPT, COPY_CSS, snippetHtml } from "@noeta/theme/copy";
import type { Env } from "./index";
import { type Inclusion, inclusionData, signatureFor } from "./log";
import { ensureHighlighter, highlightHtml, resolveLang } from "./shiki";
import { cachedRender } from "./render-cache";
import { satisfies } from "./semver";

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;
/** Mirrors the publish-side KEYWORD in index.ts — the browse route validates before it queries. */
const KEYWORD = /^[a-z0-9][a-z0-9-]{0,19}$/;

/** SHA-256 of @noeta/theme's COPY_SCRIPT, as a CSP `script-src` hash source. The script moved to
 *  the theme so docs and the registry share one button; edit it there → recompute here (the hash
 *  check in web.test.ts hashes the served bytes and fails until the two agree). */
const COPY_SCRIPT_HASH = "sha256-L52abVqoXoQfYO26hzh/Ug1xCbeQSKbI7aVVnnMTHg4=";

/**
 * Progressive enhancement for the docs tab's search: filters the already-rendered declarations live
 * as you type, so a search needs no page reload. Without it the `<form>` still submits `?q=` and the
 * server filters — this only makes it instant. Emitted only on the docs tab, pinned by hash like
 * COPY_SCRIPT. Edit → recompute the hash (the web.test.ts hash check fails until they match).
 */
const DOCSEARCH_SCRIPT =
  `(function(){var i=document.getElementById("docsearch");var r=document.getElementById("docs-results");if(!i||!r)return;var c=document.getElementById("docsearch-count");var s=r.querySelector(".docsearch-summary");if(s)s.hidden=true;if(i.form)i.form.addEventListener("submit",function(e){e.preventDefault()});function run(){var q=i.value.trim().toLowerCase();r.classList.toggle("searching",q.length>0);var n=0;r.querySelectorAll(".module").forEach(function(m){var v=0;m.querySelectorAll(".decl").forEach(function(d){var hit=!q||(d.getAttribute("data-text")||"").indexOf(q)>=0;d.hidden=!hit;if(hit)v++});m.hidden=q.length>0&&v===0;n+=v});if(c)c.textContent=q?n+" match"+(n===1?"":"es"):""}i.addEventListener("input",run);run()})();`;
/** SHA-256 of DOCSEARCH_SCRIPT, as a CSP `script-src` hash source. */
const DOCSEARCH_SCRIPT_HASH = "sha256-SQJFu6r3AoXLtZBO+fqEnWeBG/t+1UiIifug/+Z1xM0=";

/**
 * Progressive enhancement for the sidebar's transparency-log link. Without it the link is an ordinary
 * navigation to `/{package}/{version}/log`, the server-rendered proof page; with it, the click fetches
 * that same page's `?fragment=1` card and shows it in a `<dialog>` instead — so checking a release's
 * log entry never costs you your place on the package page. Any failure (offline, 404, a browser
 * without `<dialog>`) falls back to following the link, which is why the href is a real page and not
 * a `#` handle. Pinned by hash like COPY_SCRIPT — edit → recompute (web.test.ts fails until they
 * match). Written readably rather than minified: it has real control flow, and the hash covers bytes
 * either way.
 */
const PROOF_SCRIPT = `(() => {
  const dialog = document.getElementById("proof-modal");
  if (!(dialog instanceof HTMLDialogElement) || typeof dialog.showModal !== "function") return;
  const body = dialog.querySelector(".modal-body");
  if (!body) return;

  document.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a.log-link") : null;
    if (!link) return;
    // A modified click means "open elsewhere" — leave the real navigation alone.
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    body.innerHTML = '<p class="muted">Loading the log entry…</p>';
    dialog.showModal();
    fetch(link.href + "?fragment=1", { headers: { accept: "text/html" } })
      .then((response) => (response.ok ? response.text() : Promise.reject(new Error(String(response.status)))))
      .then((fragment) => {
        body.innerHTML = fragment;
        body.scrollTop = 0;
      })
      .catch(() => {
        dialog.close();
        window.location.href = link.href;
      });
  });

  // Backdrop click (the target is the dialog itself, outside the panel) and the close button.
  dialog.addEventListener("click", (event) => {
    const inClose = event.target instanceof Element && event.target.closest(".modal-close");
    if (event.target === dialog || inClose) dialog.close();
  });
  dialog.addEventListener("close", () => {
    body.innerHTML = "";
  });
})();`;
/** SHA-256 of PROOF_SCRIPT, as a CSP `script-src` hash source. */
const PROOF_SCRIPT_HASH = "sha256-rpN/Gx9gv9sN6XFeWMplRRFrn97f1KPB9wERR4a0+Wg=";

/**
 * SHA-256 of @noeta/theme's DRAWER_SCRIPT, which folds the header nav into a modal drawer on
 * phones. Unlike the two above, the source lives in another repo — so editing the drawer in
 * noeta-theme breaks this hash and the web.test.ts check fails here, blocking the deploy until the
 * hash is refreshed. That is the intended failure mode: fail closed rather than ship a CSP that
 * silently blocks the menu.
 */
const DRAWER_SCRIPT_HASH = "sha256-8LHOGhNhtkMhCvhddIF3ai4uvhOjhKx7WeE1Y+6lHmc=";

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
export async function handleWeb(env: Env, parts: string[], params?: URLSearchParams): Promise<Response> {
  const page = await routeWeb(env, parts, params);
  return html(page.body, page.status);
}

async function routeWeb(env: Env, parts: string[], params?: URLSearchParams): Promise<Page> {
  // `/`
  if (parts.length === 0) return { status: 200, body: await homePage(env) };
  // `/search?q=` — global package search. (`search` is a reserved scope, so no package shadows it.)
  if (parts.length === 1 && parts[0] === "search") {
    return searchPage(env, params?.get("q") ?? "");
  }
  // `/keywords/{keyword}` — every package tagged with it.
  if (parts.length === 2 && parts[0] === "keywords") {
    return keywordPage(env, parts[1]);
  }
  const [company, pkg, version, sub] = parts;
  // `/{company}/{package}/{version}/log` — the release's transparency-log entry, rendered. Not a tab:
  // it is one leaf page about one release, and the sidebar link opens this same card in a modal
  // (`?fragment=1` serves the card alone, which is what PROOF_SCRIPT fetches).
  if (parts.length === 4 && sub === "log" && IDENT.test(company) && IDENT.test(pkg) && SEMVER.test(version)) {
    return logProofPage(env, `${company}/${pkg}`, version, params?.get("fragment") === "1");
  }
  // `/{company}/{package}[/{version}[/{tab}]]`. The readme is the bare version URL, so `/readme`
  // is not a route — one canonical address per section.
  const tab = sub !== undefined && sub !== "readme" && (TABS as readonly string[]).includes(sub) ? (sub as Tab) : null;
  if (
    parts.length >= 2 &&
    parts.length <= 4 &&
    IDENT.test(company) &&
    IDENT.test(pkg) &&
    (version === undefined || SEMVER.test(version)) &&
    (sub === undefined || tab !== null)
  ) {
    // Only the docs tab reads a query (`?q=` — its search); other tabs ignore it.
    const query = tab === "docs" ? (params?.get("q") ?? "") : "";
    return packagePage(env, `${company}/${pkg}`, version, tab ?? "readme", query);
  }
  return { status: 404, body: notFoundPage() };
}

// --- pages ---------------------------------------------------------------------------------------

async function homePage(env: Env): Promise<string> {
  // One row per package — its most recent release, with the description and keywords a listing
  // card shows. `package_fts` is maintained by the publish path (and backfilled by migration 0012)
  // as exactly that projection, so the home page reads it instead of deduping a `packages` scan.
  const { results } = await env.DB.prepare(
    "SELECT name, description, keywords, version, license, published_at FROM package_fts " +
      "ORDER BY published_at DESC LIMIT 40",
  ).all<SearchRow>();
  const recent = results ?? [];
  const list = recent.length
    ? `<ul class="results">${recent.map(renderResult).join("")}</ul>`
    : `<p class="muted">No packages published yet.</p>`;
  return layout(
    "Noeta registry",
    `<p class="eyebrow">Package registry</p>
     <h1>The Noeta registry</h1>
     <p class="lead">The package index for <a href="https://noeta.dev">Noeta</a>. Search for a package,
     or browse what's been published below.</p>
     ${searchForm("", true)}
     <div class="home-grid">
       <section class="home-main">
         <h2>Recently published</h2>
         ${list}
       </section>
       <aside class="start-card">
         <h3>New to Noeta?</h3>
         <p>Install the toolchain, write your first package, and publish it to the registry.</p>
         <a class="button" href="https://docs.noeta.dev/getting-started">Getting started →</a>
         <ul class="start-links">
           <li><a href="https://docs.noeta.dev/language-tour">Language tour</a></li>
           <li><a href="https://docs.noeta.dev/the-cli">Publishing a package</a></li>
           <li><a href="https://docs.noeta.dev">All documentation</a></li>
         </ul>
       </aside>
     </div>`,
    "wide",
  );
}

/**
 * One release, in five sections. Every tab renders the same shell — header, tab bar, and the
 * metadata sidebar — around a different main column, so a reader never loses the release's identity
 * (or its install line) by navigating within it.
 */
async function packagePage(
  env: Env,
  name: string,
  version?: string,
  tab: Tab = "readme",
  query = "",
): Promise<Page> {
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

  // The sidebar's install/manifest snippets are shiki-highlighted and derive from (name, version)
  // alone, so they come from the render cache too (kind "side") — they show on EVERY tab, and a
  // cache hit here is what keeps plain versions/deps/security views off the highlighter entirely.
  const sideSnippets =
    (await cachedRender(env, name, v, "side", async () => {
      await ensureHighlighter();
      return sidebarSnippets(name, v);
    })) ?? "";

  let main: string;
  switch (tab) {
    case "readme": {
      // The publisher-uploaded README (npm/crates.io model), rendered through the same escape-first
      // markdown renderer as doc prose — publisher markdown is untrusted input. Cached per version:
      // the fragment derives only from the stored readme_md (last-wins uploads invalidate it).
      const rendered = await cachedRender(env, name, v, "readme", async () => {
        const readme = await readmeMd(env, name, v);
        if (readme === null) return null;
        await ensureHighlighter();
        return `<div class="prose readme">${md(readme)}</div>`;
      });
      main = rendered ?? `<p class="muted">This release has no README.</p>`;
      break;
    }
    case "docs": {
      // Only the unqueried render is cached — a ?q= search bakes hidden-attribute filtering for
      // that query into the markup, so it renders live.
      const rendered =
        query === ""
          ? await cachedRender(env, name, v, "docs", () => renderedDocs(env, name, v, ""))
          : await renderedDocs(env, name, v, query);
      if (rendered === null) {
        // Distinguish the two failure shapes: no stored artifact vs an unreadable one.
        const raw = await docsJson(env, name, v);
        if (raw === null) {
          return { status: 404, body: notFoundPage(`No documentation stored for ${name}@${v}.`) };
        }
        return { status: 500, body: notFoundPage("The stored documentation for this release is unreadable.") };
      }
      main = rendered;
      break;
    }
    case "versions":
      main = versionsMain(name, rows, v);
      break;
    case "deps":
      main = depsMain(deps);
      break;
    case "security":
      // Advisory details are markdown and may carry fenced code; they are MUTABLE (edits,
      // withdrawals), so this tab renders live — the highlighter is ensured up front because
      // markdown-it's fence rule is synchronous.
      if (live.some((a) => a.details)) await ensureHighlighter();
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
         ${sidebar(name, selected, logIndex, sideSnippets)}
       </div>
       ${logIndex !== null ? proofModal() : ""}`,
      "wide",
      [...(logIndex !== null ? [PROOF_SCRIPT] : []), ...(tab === "docs" ? [DOCSEARCH_SCRIPT] : [])],
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

/**
 * The sidebar's install-and-manifest block — the render-cached (kind "side") fragment. Derives
 * from (name, version) ONLY: nothing mutable may ever land in here (see render-cache.ts).
 * Requires the highlighter (the cache-miss producer awaits ensureHighlighter first).
 */
function sidebarSnippets(name: string, version: string): string {
  // The import root `noeta add` derives when the key is omitted: the `package` half of `company/pkg`.
  const key = name.split("/")[1];
  const req = `^${version}`;
  // Split across shell continuations rather than one long line: the rail is too narrow to show the
  // whole command, and neither truncating it (the version scrolls out of sight) nor letting it wrap
  // (line-breaking is allowed after a hyphen, so `--version` splits) is honest. This pastes as-is.
  const install = `noeta add \\\n  --package ${name} \\\n  --version ${req}`;
  // Stays a one-line inline table: TOML 1.0 inline tables may not span lines or carry a trailing
  // comma, so the pretty multi-line form would be a snippet that doesn't parse.
  const manifest = `${key} = { version = "${req}", package = "${name}" }`;
  return `<p class="side-note">Run this in your project directory:</p>
    ${snippetHtml(highlightHtml(install, "shellscript"))}
    <p class="side-note">Or add it to your <code>noeta.toml</code>:</p>
    ${snippetHtml(highlightHtml(manifest, "toml"))}`;
}

/** The metadata rail: what the release *is*, and how to depend on it. `snippets` is the
 *  render-cached install/manifest block from sidebarSnippets. */
function sidebar(name: string, r: Row, logIndex: number | null, snippets: string): string {
  const provenance = r.sig ? "signed (key)" : r.bundle ? "signed (keyless)" : "unsigned";
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
      <!-- The rendered proof page, not the raw /v1/log/proof JSON: a reader clicking "#18" wants to
           see what was logged, and PROOF_SCRIPT upgrades this click into a modal so they keep their
           place. Both surfaces render the same card. -->
      ${
        logIndex !== null
          ? `<tr><td>log entry</td><td class="mono"><a class="log-link" href="/${esc(name)}/${esc(r.version)}/log">#${logIndex}</a></td></tr>`
          : ""
      }
    </table>

    <h3>Install</h3>
    ${snippets}

    <h3>Repository</h3>
    ${
      /^https?:\/\//i.test(r.url)
        ? `<p><a class="button side-button" href="${esc(r.url)}" title="${esc(r.url)}">${repoLabelHtml(r.url)}<span class="side-button-go" aria-hidden="true">→</span></a></p>`
        : `<p class="mono muted">${esc(r.url)}</p>`
    }
  </aside>`;
}

/** The proof modal's dismiss glyph — same stroke language as the theme's drawer close. */
const CLOSE_ICON =
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>`;

/** The empty shell PROOF_SCRIPT fills with the fetched proof card. Server-rendered (so the dialog is
 *  in the DOM before any script runs) and inert without JS — the sidebar link is a real page. */
function proofModal(): string {
  return `<dialog id="proof-modal" class="modal" aria-label="Transparency-log entry">
    <button class="modal-close" type="button" aria-label="Close">${CLOSE_ICON}</button>
    <div class="modal-body"></div>
  </dialog>`;
}

/**
 * `https://github.com/acme/imgfx` → `github.com/acme/` + `imgfx`, so the button reads as a
 * destination. The two halves are separate spans because the repo name is the part that identifies
 * the destination: the CSS shrinks the host/owner prefix first and only elides the name once even an
 * empty prefix would not fit. Fitting is left to the CSS rather than a character cap here — the
 * sidebar is 17.5rem on desktop but full-width when the layout stacks, so no single cap is right for
 * both, and the cap that used to live here truncated a label that had room and still let the arrow
 * wrap to its own line.
 */
function repoLabelHtml(url: string): string {
  const label = url.replace(/^https?:\/\//i, "").replace(/\.git$/i, "").replace(/\/$/, "");
  const cut = label.lastIndexOf("/");
  const path = cut === -1 ? "" : label.slice(0, cut + 1);
  const name = cut === -1 ? label : label.slice(cut + 1);
  return `<span class="side-button-label"><span class="repo-path">${esc(path)}</span><span class="repo-name">${esc(name)}</span></span>`;
}

/**
 * The documentation tab. A search box filters the release's declarations. It works two ways from one
 * markup: without JS the form submits `?q=` and the server renders only the matches below; with JS,
 * DOCSEARCH_SCRIPT filters the already-rendered declarations live as you type (no reload). The
 * `data-text` on each `.decl` is what the client filter reads.
 */
function docsMain(doc: DocsArtifact, name: string, version: string, query: string): string {
  const modules = Array.isArray(doc.modules) ? doc.modules : [];
  if (modules.length === 0) return `<p class="muted">This release has no documented items.</p>`;

  const q = query.trim().toLowerCase();
  const action = `/${esc(name)}/${esc(version)}/docs`;
  const form = `<form class="docsearch" method="get" action="${action}" role="search">
    <input type="search" id="docsearch" name="q" value="${esc(query)}" placeholder="Search this package's API…"
           aria-label="Search documentation" autocomplete="off" spellcheck="false">
    <span class="docsearch-count" id="docsearch-count" aria-live="polite"></span>
  </form>`;

  // A search summary only when the query came from the server (no-JS path); JS updates the inline
  // count instead. Sits inside the container so `.searching` styling covers it.
  const hits = q
    ? modules.reduce(
        (n, m) => n + (Array.isArray(m.items) ? m.items.filter((i) => isDecl(i) && declText(i).includes(q)).length : 0),
        0,
      )
    : 0;
  const summary = q
    ? `<p class="docsearch-summary">${hits} match${hits === 1 ? "" : "es"} for <code>${esc(
        query,
      )}</code> · <a href="${action}">clear</a></p>`
    : "";

  const nav =
    modules.length > 1
      ? `<nav class="modnav"><strong>Modules</strong><ul>${modules
          .map((m) => {
            const title = m.namespace || m.file || "module";
            return `<li><a href="#mod-${slug(title)}">${esc(title)}</a></li>`;
          })
          .join("")}</ul></nav>`
      : "";
  const body = modules.map((m) => renderModule(m, q)).join("\n");
  return `${form}<div class="docs-results${q ? " searching" : ""}" id="docs-results">${summary}${nav}${body}</div>`;
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

// --- transparency log ----------------------------------------------------------------------------

/**
 * `/{company}/{package}/{version}/log` — the release's transparency-log entry, rendered. The same
 * proof `/v1/log/proof/…` serves as JSON (that endpoint is still the machine surface, linked from
 * the card); this is the human one. `?fragment=1` returns the bare card, which is what the sidebar's
 * modal fetches — one renderer, so the page and the modal can never disagree.
 *
 * The proof is computed on demand rather than baked into every package view: it folds every leaf in
 * the log, and it changes whenever anything is published, so it belongs behind the click.
 */
async function logProofPage(env: Env, name: string, version: string, fragment: boolean): Promise<Page> {
  const proof = await inclusionData(env, name, version);
  if (proof === null) {
    // Same verdict as the JSON endpoint: an unpublished release and an unlogged one are both "no
    // entry". The fragment path returns nothing — the modal's fetch sees the 404 and falls back to
    // navigating here, where the reader gets the full 404 page.
    return {
      status: 404,
      body: fragment ? "" : notFoundPage(`${name}@${version} is not in the transparency log.`),
    };
  }
  // The signature over this exact tree head — the same bytes /v1/log/checkpoint signs, taken from the
  // head we just computed rather than a second pass over the leaves. Null when signing is unconfigured.
  const signature = await signatureFor(env, proof.tree_size, proof.root_hash);
  const card = proofCard(name, version, proof, signature, env.LOG_PUBLIC_KEY ?? null);
  if (fragment) return { status: 200, body: card };
  return {
    status: 200,
    body: layout(
      `${name} ${version} — transparency log`,
      `<nav class="crumb"><a href="/">registry</a> / <a href="/${esc(name)}">${esc(name)}</a> /
         <a href="/${esc(name)}/${esc(version)}">${esc(version)}</a></nav>
       <h1>${esc(name)} <span class="version">${esc(version)}</span></h1>
       ${card}
       <p class="proof-back"><a href="/${esc(name)}/${esc(version)}">← back to the package</a></p>`,
    ),
  };
}

/**
 * The log entry as a card: what was logged, the tree head it is proven against, and the audit path
 * that ties them together. Shared by the standalone page and the modal.
 */
function proofCard(
  name: string,
  version: string,
  p: Inclusion,
  signature: string | null,
  publicKey: string | null,
): string {
  const f = recordFields(p.record);
  const repo = sanitizeUrl(f.url);
  const path = p.proof.length
    ? `<p class="side-note">Hash the record above into a leaf, fold in these ${p.proof.length} sibling
         hash${p.proof.length === 1 ? "" : "es"} bottom-up, and you get the root hash above. That is the proof.</p>
       <ol class="audit">${p.proof.map((h) => `<li class="mono">${esc(h)}</li>`).join("")}</ol>`
    : `<p class="side-note">The log holds a single entry, so this leaf's hash <em>is</em> the root — no
         audit path is needed.</p>`;
  return `<section class="proof">
    <h2 class="proof-head">Transparency-log entry <span class="version">#${p.index}</span></h2>
    <p class="lead">Every published release is appended to an append-only Merkle log. This proof lets
      anyone check that <span class="mono">${esc(name)} ${esc(version)}</span> is in it — and that the
      log was only ever appended to — without trusting the registry.</p>

    <h3>Proven against</h3>
    <table class="kv proof-kv">
      <tr><td>leaf index</td><td class="mono">#${p.index}</td></tr>
      <tr><td>tree size</td><td class="mono">${p.tree_size} entr${p.tree_size === 1 ? "y" : "ies"}</td></tr>
      <tr><td>root hash</td><td class="mono sha">${esc(p.root_hash)}</td></tr>
      ${signature ? `<tr><td>signature</td><td class="mono sha">${esc(signature)}</td></tr>` : ""}
      ${publicKey ? `<tr><td>log key</td><td class="mono sha">${esc(publicKey)}</td></tr>` : ""}
    </table>

    <h3>What was logged</h3>
    <table class="kv proof-kv">
      <tr><td>package</td><td class="mono">${esc(f.name)}</td></tr>
      <tr><td>version</td><td class="mono">${esc(f.version)}</td></tr>
      <tr><td>repository</td><td class="mono sha">${
        repo ? `<a href="${esc(repo)}" rel="nofollow noopener">${esc(f.url)}</a>` : esc(f.url)
      }</td></tr>
      <tr><td>tag</td><td class="mono">${esc(f.tag)}</td></tr>
      <tr><td>commit</td><td class="mono sha">${esc(f.sha)}</td></tr>
      <tr><td>provenance</td><td>${provenanceCell(f.provenance)}</td></tr>
      <tr><td>license</td><td class="mono">${
        f.license ? esc(f.license) : `<span class="muted">not declared</span>`
      }</td></tr>
    </table>
    <p class="side-note">The canonical bytes the leaf hashes — reproduce these exactly to recompute it:</p>
    ${snippetHtml(esc(p.record))}

    <h3>Audit path</h3>
    ${path}

    <p class="side-note"><code>noeta add</code> verifies this proof against a signed checkpoint on every
      install, so you rarely have to. Machine-readable:
      <a href="/v1/log/proof/${esc(name)}/${esc(version)}">this proof as JSON</a> ·
      <a href="/v1/log/checkpoint">the signed tree head</a> ·
      <a href="/v1/log/key">the log's public key</a>.</p>
  </section>`;
}

/** The canonical record's fields (PROTOCOL.md), parsed exactly as a client parses them: fields are
 *  only ever *appended*, so a short record pre-dates the missing ones rather than being malformed —
 *  `license` was appended after the original six. Field 0 is the format prefix. */
function recordFields(record: string): {
  name: string;
  version: string;
  url: string;
  tag: string;
  sha: string;
  provenance: string;
  license: string;
} {
  const l = record.split("\n");
  const at = (i: number) => l[i] ?? "";
  return {
    name: at(1),
    version: at(2),
    url: at(3),
    tag: at(4),
    sha: at(5),
    provenance: at(6),
    license: at(7),
  };
}

/** `key:{sig}` / `keyless:{sha256(bundle)}` / `unsigned` — named, with the bound value beside it. */
function provenanceCell(provenance: string): string {
  if (provenance.startsWith("key:")) {
    return `signed with the scope's key <span class="mono sha">${esc(provenance.slice(4))}</span>`;
  }
  if (provenance.startsWith("keyless:")) {
    return `keyless (Sigstore) bundle <span class="mono sha">${esc(provenance.slice(8))}</span>`;
  }
  return `<span class="muted">unsigned</span>`;
}

const isDecl = (i: DocsSection | DocsDecl): i is DocsDecl =>
  typeof (i as DocsSection).section !== "string" && !!(i as DocsDecl).name && !!(i as DocsDecl).kind;

/** The plain-text a declaration matches against — its kind, name, signature, and doc, lowercased. */
function declText(d: DocsDecl): string {
  return `${d.kind} ${d.name} ${d.signature ?? ""} ${d.doc ?? ""}`.toLowerCase();
}

/** One declaration as a `.decl` section, carrying `data-text` so the client filter can match it.
 *  A `query` that this declaration misses adds the native `hidden` attribute — so a no-JS search
 *  hides it too, while it stays in the DOM for the client filter to reveal again. */
function renderDecl(modId: string, d: DocsDecl, query: string): string {
  const hidden = query && !declText(d).includes(query) ? " hidden" : "";
  // Anchor scoped by module: two modules may each expose a `new`, so a bare `decl-new` would
  // collide across the by-module API reference.
  return `<section class="decl" id="${modId}--${slug(d.name!)}" data-text="${esc(declText(d))}"${hidden}>
    <h3><span class="kind">${esc(d.kind!)}</span> <code>${esc(d.name!)}</code></h3>
    ${d.signature ? snippetHtml(highlightHtml(d.signature, "noeta"), "sig") : ""}
    ${d.doc ? `<div class="prose">${md(d.doc)}</div>` : ""}
  </section>`;
}

/**
 * A module's rendered block — always the *full* module (every `.decl` tagged with `data-text`), so
 * the client filter has the whole set to work over. A `query` marks non-matching declarations, and
 * an all-miss module, with the native `hidden` attribute: a no-JS search hides them server-side,
 * and JS can reveal them again without a reload. The `.searching` container class (CSS) hides the
 * jump-list and prose during a search.
 */
function renderModule(m: DocsModule, query = ""): string {
  const title = m.namespace || m.file || "module";
  const modId = slug(title);
  const items = Array.isArray(m.items) ? m.items : [];
  const decls = items.filter(isDecl);
  const noMatch = query && !decls.some((d) => declText(d).includes(query));
  const heading = `<h2>${esc(title)}${m.file && m.namespace ? ` <span class="muted mono">${esc(m.file)}</span>` : ""}</h2>`;

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
      return renderDecl(modId, d, query);
    })
    .join("\n");
  return `<section class="module" id="mod-${modId}"${noMatch ? " hidden" : ""}>
    ${heading}
    ${m.doc ? `<div class="prose">${md(m.doc)}</div>` : ""}
    ${toc}
    ${itemsHtml}
  </section>`;
}

/** A search hit — the FTS index's one row per package (its most-recently-published release). */
interface SearchRow {
  name: string;
  description: string;
  keywords: string;
  version: string;
  license: string;
  published_at: string;
}

/** The package-search box. Posts a plain GET to `/search`, so it needs no script and its results
 *  are a real, shareable URL. `big` is the front-page hero variant. */
function searchForm(query: string, big = false): string {
  return `<form class="pkgsearch${big ? " pkgsearch-hero" : ""}" method="get" action="/search" role="search">
    <input type="search" name="q" value="${esc(query)}" placeholder="Search packages…"
           aria-label="Search packages" autocomplete="off" spellcheck="false"${big ? " autofocus" : ""}>
    <button type="submit">Search</button>
  </form>`;
}

/** One search result card. The name links the package; keyword chips link their listings (so the
 *  card is not itself an anchor — that would nest links). */
function renderResult(r: SearchRow): string {
  const kws = r.keywords ? r.keywords.split(" ").filter(Boolean) : [];
  const chips = kws
    .map((k) => `<a class="result-tag" href="/keywords/${esc(k)}">#${esc(k)}</a>`)
    .join("");
  return `<li class="result">
    <div class="result-head">
      <a class="result-name" href="/${esc(r.name)}">${esc(r.name)}</a>
      <span class="version">${esc(r.version)}</span>
      ${r.license ? `<span class="badge license">${esc(r.license)}</span>` : ""}
    </div>
    ${r.description ? `<p class="result-desc">${esc(r.description)}</p>` : ""}
    <div class="result-meta">${chips}<span class="muted">published ${esc(r.published_at.slice(0, 10))}</span></div>
  </li>`;
}

/**
 * `/search?q=` — global package search over the FTS index (name, description, keywords), BM25-ranked
 * with the name weighted highest. A `#tag` token *requires* the keyword (an FTS column filter on
 * `keywords`); everything else is a free prefix term; all constraints AND together. The query is
 * reduced to charset-restricted tokens before it reaches FTS `MATCH`, so no user input can be a
 * MATCH operator or a syntax error.
 *
 * `search` is a reserved scope (RESERVED_WEB_SCOPES in index.ts), so no package shadows this route.
 */
async function searchPage(env: Env, rawQuery: string): Promise<Page> {
  // `#tag` uses the keyword charset (`[a-z0-9-]+`, the shape publishes validate), rendered as a
  // quoted phrase with `-` split into words — unicode61 tokenizes a stored `foo-bar` as two
  // adjacent tokens, so the phrase matches exactly the stored keyword. Free terms are reduced to
  // `[a-z0-9]+` prefix stars. Both constructions admit only barewords, quotes we emit ourselves,
  // and a `keywords:` column filter we spell ourselves — never a user-supplied MATCH operator.
  const lower = rawQuery.toLowerCase();
  const tags = (lower.match(/#[a-z0-9-]+/g) ?? [])
    .map((t) => t.slice(1).replace(/^-+|-+$/g, ""))
    .filter(Boolean)
    .slice(0, 4);
  const freeText = lower.replace(/#[a-z0-9-]+/g, " ");
  const terms = (freeText.match(/[a-z0-9]+/g) ?? []).slice(0, 8);
  const tagFilters = tags.map((t) => `keywords:"${t.split(/-+/).join(" ")}"`);
  const match = [...terms.map((t) => `${t}*`), ...tagFilters].join(" ");

  const LIMIT = 50;
  let results: SearchRow[] = [];
  let total = 0;
  if (match) {
    const q = await env.DB.prepare(
      "SELECT name, description, keywords, version, license, published_at FROM package_fts " +
        `WHERE package_fts MATCH ? ORDER BY bm25(package_fts, 10.0, 2.0, 5.0) LIMIT ${LIMIT}`,
    )
      .bind(match)
      .all<SearchRow>();
    results = q.results ?? [];
    // A full page might have more behind it; a partial page is its own count — no second query needed.
    total =
      results.length < LIMIT
        ? results.length
        : (
            await env.DB.prepare("SELECT COUNT(*) AS n FROM package_fts WHERE package_fts MATCH ?")
              .bind(match)
              .first<{ n: number }>()
          )?.n ?? results.length;
  }

  let body: string;
  if (!match) {
    body = `<p class="muted">Type a package name, keyword, or a word from a description. <code>#tag</code> requires a keyword — e.g. <code>client #http</code>.</p>`;
  } else if (results.length === 0) {
    body = `<p class="muted">No packages match <code>${esc(rawQuery.trim())}</code>.</p>`;
  } else {
    const more = total > results.length ? `<p class="muted">Showing the top ${results.length} of ${total}.</p>` : "";
    body = `<ul class="results">${results.map(renderResult).join("")}</ul>${more}`;
  }

  const heading = match
    ? `<p class="lead">${total} result${total === 1 ? "" : "s"} for <code>${esc(rawQuery.trim())}</code>.</p>`
    : "";
  const titleQ = rawQuery.trim();
  return {
    status: 200,
    body: layout(
      titleQ ? `${titleQ} — Noeta registry search` : "Search — Noeta registry",
      `<nav class="crumb"><a href="/">registry</a> / <span>search</span></nav>
       <p class="eyebrow">Package search</p>
       <h1>Search</h1>
       ${searchForm(rawQuery)}
       ${heading}
       ${body}`,
      "wide",
    ),
  };
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
      "wide",
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
    "wide",
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

/** The docs tab's main column, rendered from the stored artifact — or null when the artifact is
 *  missing or unreadable (the caller re-checks which to pick the status). The `query === ""`
 *  render is the cacheable one (see packagePage). */
async function renderedDocs(env: Env, name: string, version: string, query: string): Promise<string | null> {
  const raw = await docsJson(env, name, version);
  if (raw === null) return null;
  let doc: DocsArtifact;
  try {
    doc = JSON.parse(raw) as DocsArtifact;
  } catch {
    return null;
  }
  await ensureHighlighter();
  return docsMain(doc, name, version, query);
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
 * The one markdown-it instance — configured ONCE, module-level, and shared by every `md()` call.
 *
 * The security posture the old hand-rolled renderer carried now rests entirely on this config plus
 * the XSS suite in web.test.ts:
 * - `html: false` is THE invariant: raw HTML in publisher content (READMEs, docs.json prose) is
 *   rendered as escaped text, never parsed — `<script>` and `<img onerror>` land inert.
 * - markdown-it's default `validateLink` refuses `javascript:`, `vbscript:`, `file:`, and non-image
 *   `data:` schemes, so a hostile link renders as plain text (the suite pins this).
 * - `linkify` and `typographer` stay off: no autolinking of bare text, no punctuation rewriting.
 *
 * The default preset brings what the hand-rolled renderer could not: GFM tables (the para/p2p
 * README bug), ordered/nested lists, and blockquotes.
 *
 * CPU: markdown-it parses README-sized input on a sub-ms-to-ms scale, well inside the Worker CPU
 * budget — no render caching is needed today.
 */
const markdown = new MarkdownIt({ html: false, linkify: false, typographer: false });

/**
 * Fenced code (and, below, indented code): any info-string naming a language shiki knows
 * (src/shiki.ts — the canonical noeta grammar, toml, rust, sql, yaml, shell, …) routes the RAW
 * body through the highlighter; an unknown info-string keeps the plain escaped rendering. ALL of
 * them land in the `.snippet` wrapper, so every code block gets the copy button — whose payload
 * is the `<code>` element's textContent, which shiki's markup preserves verbatim (the source
 * rides in text nodes; the spans only add inline colors), so a highlighted block still copies as
 * its exact raw source (see snippetHtml).
 *
 * Synchronous, so the highlighter must already exist — every render path that can reach a fence
 * awaits ensureHighlighter() first (see packagePage / cachedRender producers).
 */
markdown.renderer.rules.fence = (tokens, idx) => {
  const token = tokens[idx];
  const info = token.info.trim().split(/\s+/)[0] ?? "";
  const raw = token.content.replace(/\n$/, "");
  const lang = info ? resolveLang(info) : null;
  if (lang === null) return snippetHtml(esc(raw));
  // The pre class is the RESOLVED name (a value from our own registration table, never the raw
  // info string — which is publisher input and must not reach an attribute unvetted).
  return snippetHtml(highlightHtml(raw, lang), `${lang}-code`);
};
markdown.renderer.rules.code_block = (tokens, idx) => snippetHtml(esc(tokens[idx].content.replace(/\n$/, "")));

// ATX headings — offset by +2 (clamped at h6) so a doc `#` nests under the page's h1/h2 as an h3.
const offsetHeading = (tag: string): string => `h${Math.min(6, Number(tag.slice(1)) + 2)}`;
markdown.renderer.rules.heading_open = (tokens, idx) => `<${offsetHeading(tokens[idx].tag)}>`;
markdown.renderer.rules.heading_close = (tokens, idx) => `</${offsetHeading(tokens[idx].tag)}>\n`;

// Links carry the same rel the old renderer emitted (no target — same-tab navigation, as before).
markdown.renderer.rules.link_open = (tokens, idx, options, _env, self) => {
  tokens[idx].attrSet("rel", "nofollow noopener");
  return self.renderToken(tokens, idx, options);
};

/** Render publisher-supplied Markdown (README, docs.json prose) to HTML — see `markdown` above. */
function md(input: string): string {
  return markdown.render(input);
}

/**
 * Allow only http(s), root-relative, anchor, and mailto URLs — everything else (notably
 * `javascript:`) is rejected so an advisory's reference link can't run script. Markdown links
 * are gated separately, by markdown-it's default `validateLink`. The input is HTML-escaped, so
 * it is already safe to place in an attribute; this gates the *scheme*.
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
      // Strict CSP as defense in depth over the escape-first renderer. Scripts are still forbidden
      // *except* one pinned by its SHA-256 hash — the copy-to-clipboard helper (COPY_SCRIPT). A hash
      // source keeps the anti-XSS property intact: only that exact byte sequence runs, so a script a
      // malicious README tried to inject still can't (its hash wouldn't match). The two Google Fonts
      // hosts are the only other concession, so the registry can wear the shared "Signal" typography
      // without bundling font binaries.
      // `data:` in img-src is for the `.field` grain texture (an inline SVG background) — without it
      // the atmospheric noise is silently blocked.
      // `connect-src 'self'` is what lets PROOF_SCRIPT fetch the log-entry fragment. It widens
      // nothing an attacker can reach: no injected script can execute in the first place (script-src
      // is hash-pinned), so the only code that can open a connection is ours, to our own origin.
      "content-security-policy":
        `default-src 'none'; script-src '${COPY_SCRIPT_HASH}' '${DOCSEARCH_SCRIPT_HASH}' ` +
        `'${DRAWER_SCRIPT_HASH}' '${PROOF_SCRIPT_HASH}'; connect-src 'self'; ` +
        "style-src 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src https://fonts.gstatic.com; img-src https: data:",
    },
  });
}

/**
 * The shared page shell — the same "Signal" design language as noeta.dev, docs, and the playground:
 * a cool slate theme with a blue human accent and a mint machine accent, the atmospheric `.field`
 * backdrop, a paper light mode that follows the browser preference, and the Inter / JetBrains Mono
 * pair from Google Fonts.
 *
 * The header and footer *markup* comes from `@noeta/theme/chrome`, so the registry cannot drift
 * from the other three properties the way it had (it was missing the version pill and the .brand
 * wrapper entirely). The *stylesheet* is still inlined below: the Worker serves one self-contained
 * HTML document with no asset pipeline to emit a .css file from, so the chrome CSS is duplicated
 * here and has to be kept in lockstep with noeta-theme/css/theme.css by hand.
 */
function layout(title: string, body: string, variant: "" | "wide" = "", extraScripts: string[] = []): string {
  // `--page-max` drives the header, footer, AND page container together, so the chrome always spans
  // the same width as the content. A wide page (the tabbed package view + its sidebar) sets it on
  // <body>, which the header/footer wraps read too — otherwise they'd stay pinned to the narrow
  // default and sit inset from the body.
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- The shared @noeta/theme favicon, inlined (the Worker has no build step to import it); the
     CSP's img-src allows data:. Keep in sync with noeta-theme/assets/favicon.svg. -->
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230b0d10'/%3E%3Ctext x='32' y='45' text-anchor='middle' font-family='Inter, system-ui, sans-serif' font-weight='700' font-size='40' fill='%234f8ff7'%3En%3C/text%3E%3C/svg%3E">
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
--syn-string:#8fd6a0;--syn-number:#e0a878;--syn-keyword:#5fe0b0;--syn-type:#8fb8f5;--syn-fn:#cdd6e0;--syn-comment:#69727e;--syn-tag:#5fe0b0;--syn-hole:#7defc0;
--line:rgba(233,237,243,.08);--line-strong:rgba(233,237,243,.14);
--font-body:"Inter","Segoe UI",system-ui,sans-serif;
--font-mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
--max:60rem;--page-max:60rem;--radius:12px;color-scheme:dark;
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
.wrap{max-width:var(--page-max);margin-inline:auto;padding-inline:clamp(1.25rem,4vw,2.5rem)}
/* a wide page widens its chrome too, so the header/footer never sit inset from the body */
body.wide{--page-max:76rem}
.site-head{position:sticky;top:0;z-index:10;backdrop-filter:blur(16px);background:color-mix(in srgb,var(--bg) 72%,transparent);border-bottom:1px solid var(--line)}
.site-head .wrap{display:flex;align-items:center;justify-content:space-between;height:3.75rem}
.wordmark{font-family:var(--font-body);font-size:1.2rem;font-weight:620;letter-spacing:-.02em;color:var(--text-0)}
.wordmark .tld{color:var(--text-2);font-weight:500}
/* flex-wrap: the header .wrap wraps at 38rem, but the nav itself is one flex
 * line and its links overrun a 320px viewport. Kept in lockstep with
 * noeta-theme/css/theme.css. */
.site-nav{display:flex;flex-wrap:wrap;gap:.35rem clamp(1rem,3vw,1.9rem);align-items:center;font-family:var(--font-mono);font-size:.82rem}
.site-nav a{color:var(--text-1);transition:color 160ms ease;padding-block:.6rem}.site-nav a:hover{color:var(--accent-bright)}
@media (max-width:38rem){.site-head .wrap{height:auto;flex-wrap:wrap;gap:.1rem 1rem;padding-block:.7rem}}
/* header drawer — below 38rem the nav folds into a modal drawer. The toggle stays hidden until
   DRAWER_SCRIPT marks the document enhanced, so with JS off the nav simply wraps. Lockstep with
   noeta-theme/css/theme.css. */
.drawer-toggle{display:none;width:44px;height:44px;align-items:center;justify-content:center;margin-right:-.6rem;padding:0;border:0;border-radius:8px;background:none;color:var(--text-1);cursor:pointer}
.drawer-toggle svg{width:22px;height:22px;stroke-width:1.7}
.drawer-toggle:hover{color:var(--accent-bright)}
/* scoped through .wrap so it cannot reach the nav copy inside the drawer, which is a sibling of
   .wrap in the same <header> */
@media (max-width:38rem){:root[data-chrome-enhanced] .site-head .wrap .site-nav{display:none}:root[data-chrome-enhanced] .drawer-toggle{display:inline-flex}}
.site-drawer{width:min(20rem,86vw);max-width:none;height:100%;max-height:none;margin:0 0 0 auto;padding:0;border:0;border-left:1px solid var(--line-strong);background:var(--surface-1);color:var(--text-0)}
.site-drawer::backdrop{background:rgba(6,8,11,.62);backdrop-filter:blur(3px)}
.drawer-head{display:flex;align-items:center;justify-content:space-between;padding:.85rem .85rem .85rem 1.15rem;border-bottom:1px solid var(--line)}
.drawer-title{font-family:var(--font-mono);font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--text-2)}
.drawer-close{display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;padding:0;border:0;border-radius:8px;background:none;color:var(--text-1);cursor:pointer}
.drawer-close svg{width:20px;height:20px;stroke-width:1.7}
.drawer-body{height:calc(100% - 3.9rem);padding:.6rem .75rem 1.5rem;overflow-y:auto;overscroll-behavior:contain}
.drawer-nav{display:flex;flex-direction:column;gap:0;font-family:var(--font-mono);font-size:.9rem}
.drawer-nav a{display:flex;align-items:center;min-height:44px;padding:0 .5rem;border-radius:7px;color:var(--text-0)}
.drawer-nav a:hover{background:var(--surface-2);color:var(--accent-bright)}
/* main */
.page{max-width:var(--page-max);margin-inline:auto;padding:clamp(2rem,5vh,3.25rem) clamp(1.25rem,4vw,2.5rem) 5rem}
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
/* copy button — the shared control from @noeta/theme, injected verbatim so docs and the registry
   cannot drift; the two rules below are this site's own placement of it. */
${COPY_CSS}
.snippet{margin:1rem 0}
.pkg-side .snippet{margin:0}
.side-button{width:100%;justify-content:center;font-size:.78rem;padding:.5rem .7rem;gap:.4rem}
/* A repo label is one unbreakable "word" that routinely outgrows the 17.5rem rail. Left as flowing
   text it wrapped, dropping the arrow onto a line of its own. So: the arrow never shrinks, and the
   label elides — the host/owner prefix is the only shrinkable item, so "github.com/acme/" gives up
   its characters first and "imgfx", the half that says where the button goes, stays whole. The name
   only elides when it alone overruns the rail, which max-width (not shrinking, which would nibble a
   sub-pixel off it in every other case and show a spurious ellipsis) is what catches. */
.side-button-go{flex:none}
.side-button-label{display:flex;min-width:0}
.side-button-label>span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.side-button-label>.repo-path{flex:0 1 auto;min-width:0}
.side-button-label>.repo-name{flex:none;max-width:100%}
/* Single column below 56rem (the shared --bp-stack; this used to fold at 52rem, out of step with
 * the docs and playground layouts). The column must be minmax(0,1fr): a bare 1fr keeps
 * min-width:auto, so it floors at the sidebar's min-content — and .side-kv can't
 * shrink past its two columns, which pinned every package page ~379px wide and
 * bled past the viewport. min-width:0 plus a fixed table layout lets the
 * metadata values wrap instead of setting the floor. */
@media (max-width:56rem){.pkg-grid{grid-template-columns:minmax(0,1fr)}.pkg-side{position:static;order:-1;min-width:0}.side-kv{width:100%;table-layout:fixed}.side-kv td{overflow-wrap:anywhere}}
/* advisories */
.advisory{border:1px solid var(--line);border-radius:var(--radius);padding:1rem 1.15rem;margin:0 0 1rem;background:color-mix(in srgb,var(--surface-1) 55%,transparent)}
.advisory.is-hit{border-color:color-mix(in srgb,var(--danger) 45%,var(--line-strong))}
.advisory h3{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;margin:0 0 .5rem}
.advisory table.kv{margin:.2rem 0 .6rem}
.adv-meta{margin:.35rem 0 .7rem}
.sev{font-family:var(--font-mono);font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;padding:.12rem .5rem;border-radius:999px;border:1px solid var(--line-strong);color:var(--text-1)}
.sev-critical,.sev-high{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 45%,var(--line-strong));background:color-mix(in srgb,var(--danger) 12%,transparent)}
.sev-medium{color:var(--syn-number);border-color:color-mix(in srgb,var(--syn-number) 40%,var(--line-strong))}
/* package search — a plain GET form (no script); the hero variant is the front-page one */
.pkgsearch{display:flex;gap:.6rem;margin:1.4rem 0}
.pkgsearch input{flex:1;min-width:0;padding:.6rem .85rem;border:1px solid var(--line-strong);border-radius:8px;background:var(--surface-1);color:var(--text-0);font-family:var(--font-body);font-size:.95rem}
.pkgsearch input:focus{outline:none;border-color:var(--accent)}
.pkgsearch input::placeholder{color:var(--text-2)}
.pkgsearch button{padding:.6rem 1.2rem;border:1px solid var(--accent);border-radius:8px;background:var(--accent-dim);color:var(--accent-bright);font-family:var(--font-mono);font-size:.85rem;font-weight:500;cursor:pointer;transition:background 160ms ease,transform 160ms ease}
.pkgsearch button:hover{background:color-mix(in srgb,var(--accent) 22%,transparent);transform:translateY(-1px)}
.pkgsearch-hero{margin:1.8rem 0 2.4rem}
.pkgsearch-hero input{padding:.85rem 1.1rem;font-size:1.05rem}
/* search results */
ul.results{list-style:none;padding:0;margin:1.2rem 0 0}
.result{padding:1rem .2rem;border-bottom:1px solid var(--line)}
.result-head{display:flex;align-items:baseline;flex-wrap:wrap;gap:.6rem}
.page a.result-name{font-family:var(--font-mono);font-size:1.02rem;font-weight:500;color:var(--text-0)}
.page a.result-name:hover{color:var(--accent-bright);text-decoration:none}
.result-desc{margin:.4rem 0 .5rem;color:var(--text-1);max-width:70ch}
.result-meta{display:flex;align-items:center;flex-wrap:wrap;gap:.4rem .6rem;font-size:.82rem}
.page a.result-tag{font-family:var(--font-mono);font-size:.74rem;color:var(--text-2);border:1px solid var(--line);border-radius:999px;padding:.05rem .5rem}
.page a.result-tag:hover{border-color:var(--accent-2);color:var(--accent-2-bright);text-decoration:none}
/* home: recently-published beside a getting-started card, mirroring the package page's main+rail */
.home-grid{display:grid;grid-template-columns:minmax(0,1fr) 18rem;gap:clamp(1.5rem,4vw,3rem);align-items:start;margin-top:.5rem}
.home-main{min-width:0}
.home-main>:first-child{margin-top:0}
.start-card{border:1px solid var(--line);border-radius:var(--radius);background:color-mix(in srgb,var(--surface-1) 60%,transparent);padding:1.1rem 1.2rem}
.start-card h3{margin:0 0 .5rem;font-size:1.05rem}
.start-card p{color:var(--text-1);font-size:.9rem;margin:0 0 .9rem}
.start-card .button{width:100%;justify-content:center;font-size:.82rem}
ul.start-links{list-style:none;padding:0;margin:1rem 0 0;display:flex;flex-direction:column;gap:.5rem}
.page ul.start-links a{font-family:var(--font-mono);font-size:.82rem;color:var(--text-1)}
.page ul.start-links a:hover{color:var(--accent-bright)}
@media (max-width:56rem){.home-grid{grid-template-columns:minmax(0,1fr)}.start-card{order:-1}}
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
/* transparency-log entry — one card, rendered either as its own page or inside the modal, so the
   styling is deliberately container-agnostic (no .page-only selectors). */
.proof>:first-child{margin-top:0}
.proof-head{font-size:clamp(1.25rem,3vw,1.6rem)}
.proof .lead{font-size:.95rem}
.proof h3{margin:1.9rem 0 .5rem;font-family:var(--font-mono);font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--text-2);font-weight:500}
/* qualified with a leading table. so these out-specify the shared table.kv td rules above */
table.proof-kv td{font-size:.88rem;padding:.3rem .9rem .3rem 0;vertical-align:top}
table.proof-kv td:first-child{width:8.5rem;color:var(--text-2);white-space:nowrap}
/* hex hashes are one unbroken "word": wrap them rather than truncate — the value a reader verifies
   against has to be on the page in full, and selectable */
table.proof-kv td.sha{overflow-wrap:anywhere;line-height:1.5}
/* on a phone the label column would leave a 64-hex hash wrapping in a ~12ch gutter, so stack:
   label on its own line, value full width */
@media (max-width:34rem){
table.proof-kv,table.proof-kv tbody,table.proof-kv tr,table.proof-kv td{display:block;width:auto}
table.proof-kv tr{border-bottom:1px solid var(--line);padding:.3rem 0}
table.proof-kv td{border:0;padding:0}
table.proof-kv td:first-child{width:auto;font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;white-space:normal}
}
ol.audit{margin:.7rem 0;padding-left:1.7rem;color:var(--text-1)}
ol.audit li{margin:.18rem 0;font-size:.8rem;overflow-wrap:anywhere}
ol.audit li::marker{color:var(--text-2);font-family:var(--font-mono);font-size:.78rem}
.proof-back{margin-top:2rem}
/* the modal PROOF_SCRIPT opens over the package page; with JS off it is never shown and the sidebar
   link is a plain navigation to the same card's page */
.modal{width:min(46rem,92vw);max-width:none;padding:0;border:1px solid var(--line-strong);border-radius:var(--radius);background:var(--surface-1);color:var(--text-0)}
.modal::backdrop{background:rgba(6,8,11,.62);backdrop-filter:blur(3px)}
.modal-body{max-height:82vh;overflow-y:auto;overscroll-behavior:contain;padding:1.5rem clamp(1.1rem,3vw,1.9rem) 1.8rem}
.modal-body a{color:var(--accent-bright)}.modal-body a:hover{color:var(--accent);text-decoration:underline}
.modal-close{position:absolute;top:.4rem;right:.4rem;display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;padding:0;border:0;border-radius:8px;background:none;color:var(--text-2);cursor:pointer}
.modal-close:hover{color:var(--accent-bright)}
.modal-close svg{width:20px;height:20px}
/* deps + nav */
ul.deps,.modnav ul{list-style:none;padding:0}
ul.deps li{padding:.3rem 0;border-bottom:1px solid var(--line)}
/* docs search: an input-styled box; a live count sits to its right */
.docsearch{display:flex;align-items:center;gap:.7rem;margin:0 0 1.4rem}
.docsearch input{flex:1;min-width:0;padding:.55rem .8rem;border:1px solid var(--line-strong);border-radius:8px;background:var(--surface-1);color:var(--text-0);font-family:var(--font-mono);font-size:.85rem}
.docsearch input:focus{outline:none;border-color:var(--accent)}
.docsearch input::placeholder{color:var(--text-2)}
.docsearch-count{font-family:var(--font-mono);font-size:.78rem;color:var(--text-2);white-space:nowrap}
.docsearch-summary{font-size:.85rem;color:var(--text-1);margin:0 0 1.2rem}
/* during a search — server-set "searching", or toggled by DOCSEARCH_SCRIPT — the browsing chrome
   (module jump-list, prose, per-module contents) gives way to just the matching declarations */
.docs-results.searching .modnav,.docs-results.searching .toc,.docs-results.searching .module>.prose{display:none}
.docs-results.searching .decl{margin:0 0 1.1rem}
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
/* Code is typed, so it must render as typed — JetBrains Mono's default ligatures fuse
 * |> and -> and != into single glyphs nobody has a key for. Mirrors theme.css.
 * (No backticks here: this stylesheet is a template literal.) */
code,pre,kbd,samp,.mono{font-variant-ligatures:none;font-feature-settings:"calt" 0,"liga" 0}
:not(pre)>code{background:var(--surface-3);border:1px solid var(--line);padding:.08em .38em;border-radius:5px;color:var(--text-0)}
pre.sig code{color:var(--text-0)}
/* Syntax colors ride inline style="color:var(--syn-*)" on shiki's token spans (src/shiki.ts);
   the --syn-* variable values above mirror noeta-theme/css/theme.css so registry and docs color
   code identically, and they flip with prefers-color-scheme below. */
/* declarations + prose */
.decl{margin:1.4rem 0}
.kind{font-family:var(--font-mono);color:var(--accent-2);font-weight:500;font-size:.72em;letter-spacing:.06em;text-transform:uppercase}
.prose{max-width:65ch;color:var(--text-1)}.prose p{margin:.6rem 0}
.prose.readme{margin-top:.6rem}
.prose ul,.prose ol{margin:.6rem 0;padding-left:1.4rem}
.prose li{margin:.2rem 0}
/* READMEs routinely carry bare URLs (license links, badges). Without this they
 * form one unbreakable box that outruns a narrow viewport. */
.prose a,.prose code{overflow-wrap:anywhere}
/* markdown tables (GFM) — subtle bordered cells in the registry's line/surface tokens; sized to
   content, and a too-wide table scrolls inside itself rather than breaking the column */
.prose table{display:block;width:max-content;max-width:100%;overflow-x:auto;margin:1rem 0;font-size:.9rem}
.prose th,.prose td{padding:.4rem .75rem;border:1px solid var(--line-strong);text-align:left}
.prose th{font-weight:600;color:var(--text-0);background:color-mix(in srgb,var(--surface-2) 70%,transparent)}
.prose tr:nth-child(even) td{background:color-mix(in srgb,var(--surface-1) 55%,transparent)}
.prose blockquote{margin:1rem 0;padding:.05rem 1rem;border-left:3px solid var(--line-strong);background:color-mix(in srgb,var(--surface-1) 55%,transparent);border-radius:0 8px 8px 0;color:var(--text-1)}
.module{margin:1.8rem 0 2.8rem}
/* footer */
.site-foot{border-top:1px solid var(--line);padding-block:2.6rem 3rem}
.site-foot .wrap{display:flex;flex-wrap:wrap;gap:1.2rem 2.4rem;align-items:baseline;justify-content:space-between}
.site-foot .tagline{font-family:var(--font-body);font-weight:600;font-size:1.05rem;letter-spacing:-.015em}
.site-foot .tagline em{color:var(--accent);font-style:normal}
.foot-nav{display:flex;flex-wrap:wrap;gap:1.4rem;font-family:var(--font-mono);font-size:.84rem}
.foot-nav a{color:var(--text-2);transition:color 160ms ease;padding-block:.5rem}.foot-nav a:hover{color:var(--accent-bright)}
.foot-meta{width:100%;margin-top:.4rem;font-size:.84rem;color:var(--text-2)}
/* light mode — follows the browser preference */
@media (prefers-color-scheme:light){
:root{--bg:#f6f8fb;--surface-1:#fff;--surface-2:#eceff5;--surface-3:#e4e8f0;--text-0:#14181f;--text-1:#47515f;--text-2:#6c7686;--accent:#2767d6;--accent-bright:#1a55c0;--accent-dim:rgba(39,103,214,.1);--accent-2:#0c8a66;--accent-2-bright:#097053;--danger:#cf3b2f;--syn-string:#3f8f4f;--syn-number:#b5651d;--syn-keyword:#0c8a66;--syn-type:#2767d6;--syn-fn:#384657;--syn-comment:#8a94a4;--syn-tag:#0c8a66;--syn-hole:#097053;--line:rgba(20,24,31,.1);--line-strong:rgba(20,24,31,.16);color-scheme:light}
.field{background:radial-gradient(58rem 40rem at 84% -12%,rgba(39,103,214,.07),transparent 60%),radial-gradient(52rem 40rem at -6% 108%,rgba(12,138,102,.05),transparent 58%),var(--bg)}
.field::after{opacity:.012}
::selection{background:rgba(39,103,214,.18);color:var(--text-0)}
}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}.button{transition:none}}
</style>
</head>
<body${variant ? ` class="${variant}"` : ""}>
<div class="field" aria-hidden="true"></div>
${renderHeader({ site: "registry" })}
<main class="page${variant ? ` ${variant}` : ""}">
${body}
</main>
${renderFooter({ site: "registry" })}
<script>${COPY_SCRIPT}</script>
<script>${DRAWER_SCRIPT}</script>
${extraScripts.map((s) => `<script>${s}</script>`).join("\n")}
</body>
</html>`;
}

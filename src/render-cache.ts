// Noeta registry — the D1 render cache for shiki-highlighted page fragments.
//
// Why: shiki renders through real TextMate grammars, whose cold cost (grammar compilation +
// tokenization) is far past a Worker request's ~10ms free-tier CPU budget. The neutralizer is
// that package versions are IMMUTABLE: a fragment derived purely from a release's stored
// artifacts can be rendered once and served from D1 forever after. Only fragments with that
// property are cached — anything mutable (yanked badges, tab counts, advisory verdicts, the
// metadata rail's log link) is composed around the cached HTML at request time, never inside it.
//
// One caveat to "immutable": the readme and docs artifacts themselves are last-wins
// (PUT …/readme/{v} and …/docs/{v} may overwrite; see index.ts) — so those handlers call
// `invalidateRendered` for the matching kind. The `side` fragment derives from (name, version)
// alone and can never go stale.
//
// Rows for a superseded RENDERER_REV are deleted opportunistically whenever a fresh render is
// written for the same (name, version, kind) — no sweep job needed; dead rows for never-again
// -visited fragments just sit inert until their page is next rendered.

import type { Env } from "./index";

/**
 * The renderer's revision, part of every cache key. Bump this string BY HAND whenever the
 * rendered fragment shape changes for the same inputs — a grammar resync that changes
 * tokenization, a theme/scope-mapping edit in src/shiki.ts, or a change to the fragment
 * composition in web.ts (fence rule, snippetHtml, docsMain, the sidebar snippets). A manual
 * constant beats hashing the inputs: the failure mode of forgetting a bump is stale-but-valid
 * styling, while hashing would drag grammar files into the runtime for marginal benefit.
 */
export const RENDERER_REV = "shiki-1";

/** The cacheable fragments of a package page. `readme` and `docs` are the rendered main
 *  columns; `side` is the sidebar's install + manifest snippet block (shown on every tab). */
export type RenderKind = "readme" | "docs" | "side";

/**
 * Serve `(name, version, kind)` from the render cache, or produce, store, and serve it.
 * `produce` runs only on a miss — it is where `ensureHighlighter()` gets awaited, so cache
 * hits never touch shiki. A `null` from `produce` (nothing to render, e.g. no README stored)
 * is passed through uncached.
 */
export async function cachedRender(
  env: Env,
  name: string,
  version: string,
  kind: RenderKind,
  produce: () => Promise<string | null>,
): Promise<string | null> {
  const hit = await env.DB.prepare(
    "SELECT html FROM rendered_pages WHERE name = ? AND version = ? AND kind = ? AND renderer_rev = ?",
  )
    .bind(name, version, kind, RENDERER_REV)
    .first<{ html: string }>();
  if (hit) return hit.html;

  const html = await produce();
  if (html === null) return null;

  await env.DB.batch([
    // Opportunistic cleanup: a fresh write retires every stale-rev row for this fragment.
    env.DB.prepare(
      "DELETE FROM rendered_pages WHERE name = ? AND version = ? AND kind = ? AND renderer_rev <> ?",
    ).bind(name, version, kind, RENDERER_REV),
    // OR IGNORE: two concurrent misses may race to insert; the first write wins and both
    // rendered the same bytes anyway.
    env.DB.prepare(
      "INSERT OR IGNORE INTO rendered_pages (name, version, kind, renderer_rev, html, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).bind(name, version, kind, RENDERER_REV, html, new Date().toISOString()),
  ]);
  return html;
}

/** Drop the cached fragment for one (name, version, kind) — called by the last-wins readme/docs
 *  PUT handlers so an overwrite is visible on the next page view. Every rev is dropped: a stale
 *  rev's row is just as wrong about new content as the current one's. */
export async function invalidateRendered(
  env: Env,
  name: string,
  version: string,
  kind: RenderKind,
): Promise<void> {
  await env.DB.prepare("DELETE FROM rendered_pages WHERE name = ? AND version = ? AND kind = ?")
    .bind(name, version, kind)
    .run();
}

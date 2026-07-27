-- Render cache for the web UI's shiki-highlighted page fragments (src/render-cache.ts).
--
-- key   = (name, version, kind, renderer_rev)
--   kind         ∈ {readme, docs, side} — the rendered README main column, the rendered docs
--                  main column (unqueried), and the sidebar's install/manifest snippet block.
--   renderer_rev = the RENDERER_REV constant in src/render-cache.ts, bumped by hand when the
--                  theme, grammars, or fragment composition change; a mismatch is a cache miss,
--                  and stale-rev rows are deleted opportunistically when a fresh render lands.
-- value = the rendered HTML fragment, exactly as web.ts embeds it.
--
-- Fragments cached here must derive ONLY from the release's immutable/last-wins artifacts —
-- never from mutable state (yank flags, advisory matches, version counts). The last-wins
-- readme/docs uploads invalidate their kind's rows on overwrite (index.ts).
CREATE TABLE rendered_pages (
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  kind         TEXT NOT NULL,
  renderer_rev TEXT NOT NULL,
  html         TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (name, version, kind, renderer_rev)
);

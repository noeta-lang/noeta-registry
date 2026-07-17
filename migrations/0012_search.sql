-- Global package search (crates.io / npm style). Two parts: a per-release `description` — the
-- short blurb a search result shows — and an FTS5 index over the fields worth searching.
--
-- `description` is a per-release fact like `license` and `keywords`: publisher-declared, part of the
-- immutable release record, but NOT bound into the transparency-log leaf. The leaf binds what a
-- consumer must trust at resolve time; a description is discovery prose, so tampering with one only
-- mis-describes a package in a listing — it can't redirect a build.
ALTER TABLE packages ADD COLUMN description TEXT;

-- The search index: one row per package, holding its most-recently-published release. `name`,
-- `description`, and `keywords` are the searched columns; `version`/`license`/`published_at` ride
-- along UNINDEXED so a result card renders from the search hit alone, with no second query.
--
-- Maintained by the publish path (src/index.ts), not by triggers: publishing is the only write, so
-- an app-level upsert (delete-by-name + insert the just-published release) is clearer than a trigger,
-- and it keeps this index consistent with the home page, which likewise shows the most recent
-- publish per package.
CREATE VIRTUAL TABLE IF NOT EXISTS package_fts USING fts5(
  name,
  description,
  keywords,
  version UNINDEXED,
  license UNINDEXED,
  published_at UNINDEXED,
  tokenize = 'unicode61'
);

-- Backfill packages published before this migration: the most-recently-published release of each,
-- with its keywords joined into the searchable text. `MAX(published_at)` picks the same release the
-- home page shows (ISO-8601 UTC strings sort chronologically).
INSERT INTO package_fts (name, description, keywords, version, license, published_at)
SELECT
  p.name,
  COALESCE(p.description, ''),
  COALESCE((SELECT group_concat(k.keyword, ' ') FROM package_keywords k WHERE k.name = p.name AND k.version = p.version), ''),
  p.version,
  COALESCE(p.license, ''),
  p.published_at
FROM packages p
JOIN (SELECT name, MAX(published_at) AS mx FROM packages GROUP BY name) latest
  ON p.name = latest.name AND p.published_at = latest.mx
-- One row per package even in the impossible case of two releases sharing a published_at: the
-- publish path keeps a single FTS row per name, and the backfill must not seed a duplicate.
GROUP BY p.name;

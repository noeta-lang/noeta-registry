-- Discovery keywords (registry browse): a release's publisher-declared topic tags, e.g.
-- `para`, `aether`, `image`. The point is the question the index could not answer before —
-- "what builds on top of para?" — which neither the name nor the README reliably tells you.
--
-- A join table rather than a JSON column on `packages`, for one reason: the lookup that matters is
-- *by keyword* ("every package tagged `aether`"), and a JSON column can only answer it with a full
-- scan and a parse per row. Here it is one index probe. The table is the single source of truth —
-- there is no denormalized copy to drift.
--
-- Keyed per (name, version) like every other release fact: a release is immutable, so its keywords
-- are fixed at publish and the rows are written in the same batch as the package row.
--
-- Deliberately NOT bound into the transparency-log leaf, unlike `license`. The leaf binds what a
-- consumer must be able to trust at resolve time — identity, coordinates, provenance, license. A
-- keyword is discovery metadata: tampering with one mis-files a package in a listing, it cannot
-- redirect a build or misrepresent a legal claim. Binding it would grow the leaf's record format
-- (and every client's parse of it) for no security gain.

CREATE TABLE IF NOT EXISTS package_keywords (
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  keyword TEXT NOT NULL,
  PRIMARY KEY (name, version, keyword)
);

-- The reason this table exists: keyword → packages.
CREATE INDEX IF NOT EXISTS idx_package_keywords_keyword ON package_keywords (keyword);

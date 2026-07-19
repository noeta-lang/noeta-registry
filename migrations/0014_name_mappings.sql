-- External-ecosystem name mappings (advisory-intake arc, imported tier). An imported advisory names a
-- package in *its own* ecosystem's namespace (`crates.io`'s `tokio`, a GHSA's `npm:express`); this
-- table maps that external identity to a Noeta package identity (`company/package`) so an imported
-- advisory can be filed against the right Noeta package.
--
-- The mappings are themselves **operator-curated data** — a mapping is a human judgment ("this Noeta
-- package is the same software as that crate"), never inferred. Only the admin bootstrap token writes
-- here. The import job reads them: an OSV/GHSA/RUSTSEC record whose (ecosystem, external_name) has no
-- mapping is skipped (never guessed).
--
-- Keyed by (ecosystem, external_name): one ecosystem may name a package one way and another differently
-- (a crate `foo` and an npm `foo` are unrelated), so the ecosystem is part of the identity. A single
-- external package maps to exactly one Noeta package.
CREATE TABLE IF NOT EXISTS name_mappings (
  ecosystem     TEXT NOT NULL,          -- upstream ecosystem: "crates.io" | "npm" | "PyPI" | "Go" | …
  external_name TEXT NOT NULL,          -- the package's name in that ecosystem
  noeta_package TEXT NOT NULL,          -- the Noeta identity "company/package"
  created_at    TEXT NOT NULL,
  PRIMARY KEY (ecosystem, external_name)
);

-- The reason this table exists: (ecosystem, external_name) → noeta_package during import.
CREATE INDEX IF NOT EXISTS idx_name_mappings_noeta ON name_mappings (noeta_package);

-- Noeta registry — D1 schema (Cloudflare SQLite at the edge).
--
-- The index stores git *coordinates*, never source. A published (name, version) is immutable: the
-- primary key gives atomic immutability and safe concurrent publishes (a second INSERT of the same
-- version fails at the DB, not in application logic that could race).

CREATE TABLE IF NOT EXISTS packages (
  name         TEXT    NOT NULL,           -- package identity: "company/package"
  version      TEXT    NOT NULL,           -- SemVer
  url          TEXT    NOT NULL,           -- git repository URL
  tag          TEXT    NOT NULL,           -- released tag
  sha          TEXT    NOT NULL,           -- commit SHA the tag resolved to at publish time (pinned)
  deps         TEXT    NOT NULL DEFAULT '[]', -- JSON array of {package, req} — this version's registry deps
  yanked       INTEGER NOT NULL DEFAULT 0, -- 1 = still resolvable by existing pins, not newly selected
  published_by TEXT,                       -- the scope/token identity that published (provenance)
  published_at TEXT    NOT NULL,           -- ISO-8601 UTC
  PRIMARY KEY (name, version)
);

CREATE INDEX IF NOT EXISTS idx_packages_name ON packages (name);

-- Scope ownership: a publish token is bound to a company scope. Only the owner of `acme` publishes
-- `acme/*`. Tokens are stored hashed (SHA-256 hex); the raw token is presented on publish.
CREATE TABLE IF NOT EXISTS scopes (
  scope      TEXT PRIMARY KEY,             -- the "company" segment
  token_sha  TEXT NOT NULL,               -- SHA-256 hex of the publish token
  created_at TEXT NOT NULL
);

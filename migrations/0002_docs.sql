-- Noeta registry — per-release documentation artifacts (docs-ingestion follow-up).
--
-- A release's `docs.json` (the `noeta doc --out` artifact) is stored here, keyed by the same
-- (name, version) as the release it documents. Docs are **advisory metadata**, not provenance:
--   • unsigned — a compromised docs blob can at worst mislead a reader, never affect resolution or
--     the SHA pin, so it is not part of the immutable release record;
--   • last-wins — re-uploading docs for an already-published (immutable) release overwrites, so a
--     regenerated artifact (or a registry that regenerates from source, docs.rs-style) can refresh
--     them without touching the release;
--   • separate table — the blob is large and rarely read, so it never rides along on the hot
--     version-list query.

CREATE TABLE IF NOT EXISTS docs (
  name       TEXT NOT NULL,   -- package identity: "company/package"
  version    TEXT NOT NULL,   -- SemVer, references a published packages(name, version)
  docs_json  TEXT NOT NULL,   -- the verbatim docs.json artifact (schema-versioned by the client)
  updated_at TEXT NOT NULL,   -- ISO-8601 UTC of the last upload (last-wins)
  PRIMARY KEY (name, version)
);

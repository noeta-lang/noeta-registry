-- Noeta registry — per-release README artifacts (readme-on-package-page follow-up).
--
-- A release's README.md, uploaded by `noeta publish` and rendered on the package's browser page
-- (the npm/crates.io model). Same posture as `docs` (0002): the registry never fetches source, so
-- a README is only ever what the publisher explicitly uploads. **Advisory metadata**, not
-- provenance:
--   • unsigned — a compromised README can at worst mislead a reader (and the web renderer is
--     escape-first under a strict CSP), never affect resolution or the SHA pin;
--   • last-wins — re-uploading for an already-published (immutable) release overwrites, so a
--     corrected README can be refreshed without touching the release;
--   • separate table — prose never rides along on the hot version-list query.

CREATE TABLE IF NOT EXISTS readmes (
  name       TEXT NOT NULL,   -- package identity: "company/package"
  version    TEXT NOT NULL,   -- SemVer, references a published packages(name, version)
  readme_md  TEXT NOT NULL,   -- the verbatim README markdown
  updated_at TEXT NOT NULL,   -- ISO-8601 UTC of the last upload (last-wins)
  PRIMARY KEY (name, version)
);

-- Security advisories (namespace-protection #1, advisory feed) — a signed, RUSTSEC-style database of
-- known-bad releases. Each row is one advisory: a package, the affected SemVer range(s), a severity,
-- and a one-line summary, individually Ed25519-signed so a client can verify it without trusting the
-- transport. `withdrawn` retracts a false alarm (advisories are corrected, never deleted, so the feed
-- head's count is monotonic). `seq` is a monotonic feed cursor (assigned on every insert *or* update)
-- so `GET /v1/advisories?since=` can serve just the delta.
CREATE TABLE IF NOT EXISTS advisories (
  id            TEXT    PRIMARY KEY,       -- advisory id, e.g. "NOETA-2026-0001"
  package       TEXT    NOT NULL,          -- affected package identity "company/package"
  ranges        TEXT    NOT NULL,          -- affected versions, a SemVer requirement (e.g. ">=1.0.0, <1.2.3")
  patched       TEXT,                      -- first fixed version(s), informational (nullable)
  severity      TEXT    NOT NULL,          -- "low" | "medium" | "high" | "critical"
  summary       TEXT    NOT NULL,          -- one-line headline (no newlines)
  details       TEXT    NOT NULL DEFAULT '', -- longer description (may be multi-line); hashed into the signature
  url           TEXT    NOT NULL DEFAULT '', -- link to the full advisory (no newlines)
  withdrawn     INTEGER NOT NULL DEFAULT 0, -- 1 = retracted (was a false alarm)
  seq           INTEGER NOT NULL,          -- monotonic feed cursor (bumped on insert and every update)
  signature     TEXT    NOT NULL,          -- hex Ed25519 signature over the advisory's canonical bytes
  created_at    TEXT    NOT NULL,
  updated_at    TEXT    NOT NULL
);

-- Serve the feed and the per-package lookup efficiently.
CREATE INDEX IF NOT EXISTS idx_advisories_seq ON advisories (seq);
CREATE INDEX IF NOT EXISTS idx_advisories_package ON advisories (package);

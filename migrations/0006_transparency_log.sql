-- Transparency log (namespace-protection #1) — an append-only, tamper-evident record of every
-- published release. Each row is one Merkle-tree leaf; `idx` is its 0-based append position. The row
-- stores the canonical `record` (the exact bytes the leaf hashes) so a client can recompute the leaf
-- and verify inclusion, and its `leaf_hash` (hex) so the server builds proofs without re-hashing.
-- A release is appended exactly once, together with its `packages` row (a genuinely new version).
CREATE TABLE IF NOT EXISTS log (
  idx        INTEGER PRIMARY KEY,        -- append position (0-based, contiguous)
  leaf_hash  TEXT    NOT NULL,           -- hex RFC-6962 leaf hash of `record`
  name       TEXT    NOT NULL,           -- package identity "company/package"
  version    TEXT    NOT NULL,
  record     TEXT    NOT NULL,           -- the canonical log record (client recomputes the leaf from it)
  created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_log_name_version ON log (name, version);

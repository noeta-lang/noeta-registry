-- Public report queue (advisory-intake arc, tier 4 — intake ONLY). Anyone may *file* a report that a
-- package looks vulnerable or malicious; a report is never an advisory and never appears in the signed
-- advisory feed. A report becomes an advisory only by an explicit **promote** (operator, or the scope's
-- own owner) — the arc's rule: automate provenance, never judgment. This separates the open,
-- unauthenticated intake surface from the trusted, signed output surface.
--
-- Reports are rate-limited by a hash of the reporter's IP (no account model) — `ip_hash` + `created_at`
-- feed a per-window cap so the queue can't be flooded. `status` tracks triage; a promoted report records
-- the advisory id it produced.
CREATE TABLE IF NOT EXISTS reports (
  id           TEXT    PRIMARY KEY,      -- opaque report id (a random token, not guessable/enumerable)
  package      TEXT    NOT NULL,         -- the package the report is against, "company/package"
  ranges       TEXT    NOT NULL DEFAULT '', -- optional affected SemVer range the reporter believes (may be "")
  summary      TEXT    NOT NULL,         -- one-line headline (no newlines)
  details      TEXT    NOT NULL DEFAULT '', -- the reporter's description (may be multi-line)
  url          TEXT    NOT NULL DEFAULT '', -- optional link the reporter provides (no newlines)
  reporter     TEXT    NOT NULL DEFAULT '', -- optional self-identification (no newlines); intake is anonymous by default
  status       TEXT    NOT NULL DEFAULT 'pending', -- "pending" | "promoted" | "dismissed"
  advisory_id  TEXT,                     -- the advisory this report was promoted into (NULL until promoted)
  ip_hash      TEXT    NOT NULL DEFAULT '', -- SHA-256 of the reporter IP (rate-limit only; never served)
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL
);

-- Triage lists the pending queue oldest-first; the rate limiter counts recent rows per ip_hash.
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports (status, created_at);
CREATE INDEX IF NOT EXISTS idx_reports_ip ON reports (ip_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_reports_package ON reports (package);

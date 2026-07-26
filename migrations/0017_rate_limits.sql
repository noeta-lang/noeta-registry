-- Per-IP rate limiting for the write surface an attacker can hammer without credentials doing any
-- work: claim (drives OIDC/JWKS and GitHub API traffic), publish (drives log appends), and rotate
-- (mints tokens). Same mechanism as the report queue's flood valve (0015): count a hash of the
-- caller's IP over a sliding window in D1 — no dashboard-configured binding, works purely from code,
-- and one Worker instance's view is the database's view. The raw IP is never stored — only its
-- SHA-256, used solely to count recent attempts; rows expire out of the window and are purged
-- opportunistically on each new attempt. Reads are never rate-limited.
CREATE TABLE IF NOT EXISTS rate_limits (
  endpoint   TEXT NOT NULL,  -- "claim" | "publish" | "rotate" (the limiter's bucket, not a URL)
  ip_hash    TEXT NOT NULL,  -- SHA-256 of the caller IP (never served, never the raw address)
  created_at TEXT NOT NULL   -- ISO-8601 UTC of the attempt
);

-- The limiter counts one (endpoint, ip) pair's recent rows on every gated attempt.
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits (endpoint, ip_hash, created_at);

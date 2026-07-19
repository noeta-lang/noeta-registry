-- Advisory intake tiers (advisory-intake arc). An advisory now records *how it entered the feed* —
-- its trust tier — plus the provenance that tier carries. This is the schema half of the three-tier
-- intake model (automate provenance, never judgment):
--   • operator  — operator-curated, admin-issued (the existing anchor tier; the default).
--   • publisher — issued by a scope's own owner for their own scope, carrying a keyless Sigstore
--                 `bundle` a consumer verifies offline against the scope's pinned identity.
--   • imported  — mirrored from an external ecosystem feed (OSV/GHSA/RUSTSEC) via an operator-curated
--                 name-mapping table, carrying the upstream advisory's id + url as provenance links.
--
-- `tier` is appended to the advisory's canonical signing bytes (and thus its transparency-log leaf),
-- so a client can trust *which* tier the registry served — reproduced identically by the Rust client's
-- `advisory::canonical_bytes`. `bundle`/`upstream_id`/`upstream_url` are echoed in the feed but NOT in
-- the signed canonical bytes (the bundle is self-attesting — the consumer verifies it offline; the
-- upstream links are discovery metadata).
ALTER TABLE advisories ADD COLUMN tier TEXT NOT NULL DEFAULT 'operator';
-- The keyless Sigstore bundle (JSON) for a `publisher`-tier advisory — the scope owner's offline-
-- verifiable attestation over the advisory's canonical bytes. NULL for operator/imported tiers.
ALTER TABLE advisories ADD COLUMN bundle TEXT;
-- The upstream advisory id (e.g. `GHSA-xxxx-xxxx-xxxx`, `RUSTSEC-2026-0001`) for an `imported`-tier
-- advisory, and a link to it. NULL for operator/publisher tiers. The import is idempotent per
-- upstream id (the advisory's own `id` is derived from it), so a re-import updates in place.
ALTER TABLE advisories ADD COLUMN upstream_id TEXT;
ALTER TABLE advisories ADD COLUMN upstream_url TEXT;

CREATE INDEX IF NOT EXISTS idx_advisories_tier ON advisories (tier);
CREATE INDEX IF NOT EXISTS idx_advisories_upstream ON advisories (upstream_id);

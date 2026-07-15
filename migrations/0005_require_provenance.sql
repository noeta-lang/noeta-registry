-- Per-scope publishing policy (namespace-protection #1, Phase 1: require-provenance).
--
-- A scope owner can require that every release under the scope carry provenance, so a leaked publish
-- token alone can no longer push a release — the attacker also needs the signing key (key root) or the
-- OIDC identity (keyless root). `require_provenance = 1` turns it on; `provenance_root` narrows *which*
-- root is required ('key' | 'keyless'), or NULL = either is accepted. Default 0 (unsigned allowed) so
-- the existing ecosystem keeps working; this is opt-in per scope.
--
-- Kept as scope-level columns (not a separate table) because scope policy is 1:1 with the scope and
-- small. This is the natural home for further scope config as the ownership model grows (e.g. a future
-- DNS / rel="me" domain-proof owner_kind, or an explicitly pinned keyless identity).
ALTER TABLE scopes ADD COLUMN require_provenance INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scopes ADD COLUMN provenance_root TEXT;

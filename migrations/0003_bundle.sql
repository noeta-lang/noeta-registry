-- Noeta registry — keyless provenance bundles (Phase 5, second trust root).
--
-- A release carries **at most one** trust root: the key-based Ed25519 `sig` (verified server-side
-- against the scope's registered public key) or a keyless Sigstore `bundle` (a DSSE envelope +
-- Fulcio certificate + Rekor inclusion proof). The client already accepts and serves both; this
-- column lets the index store and serve the keyless one too.
--
-- Unlike `sig`, the bundle is stored **verbatim without server-side verification**: its trust root
-- is Sigstore's public infrastructure (Fulcio/Rekor roots), not a per-scope key, so verifying it
-- would need those roots bundled into the Worker and full cert-chain + inclusion-proof checking —
-- heavy and dependency-bearing. And it is not the security boundary: a keyless consumer verifies the
-- bundle **offline** against its own pinned trust policy, so the registry never has to be trusted for
-- it (the whole point of keyless provenance).

ALTER TABLE packages ADD COLUMN bundle TEXT; -- JSON Sigstore bundle (keyless provenance); NULL = none

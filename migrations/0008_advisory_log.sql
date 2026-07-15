-- Bind advisory issuance into the transparency log (namespace-protection #1, advisory-log follow-on).
-- Every advisory publish/update appends a leaf to the `log` table whose record is the advisory's exact
-- canonical bytes — so an advisory's issuance (and each later state, e.g. a withdrawal) is permanent,
-- append-only, and covered by the log's signed checkpoints and consistency proofs, exactly like a
-- release. `log_index` is the index of the advisory's *current* leaf, echoed in the feed so a client
-- can fetch its inclusion proof.
ALTER TABLE advisories ADD COLUMN log_index INTEGER;

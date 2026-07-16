-- Noeta registry — per-release license metadata.
--
-- The SPDX license expression the publisher declared in the package manifest ([package] license),
-- e.g. "MIT OR Apache-2.0". Unlike docs/READMEs this is **part of the immutable release record**:
-- consumers (and license-audit tooling) must be able to trust that what the registry said at
-- resolve time is what the release carried, so it is set at publish and never re-pointed — and it
-- is bound into the release's transparency-log leaf. NULL for releases that declared none.
--
-- The registry never fetches source, so the value is publisher-asserted; the SHA pin means a
-- consumer can always check the actual LICENSE file in the release's tree.

ALTER TABLE packages ADD COLUMN license TEXT;

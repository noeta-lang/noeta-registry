-- CVSS vector on an advisory (advisory-intake residual b). When an imported upstream record carries a
-- CVSS v3.x vector (OSV `severity[]` of type CVSS_V3, or GHSA `cvss.vectorString`), the import derives
-- the canonical severity *band* from the honestly-computed base score and keeps the vector here so a
-- consumer can see (and re-derive) the score behind the band.
--
-- Like `bundle`/`upstream_*`, `cvss` is discovery/display metadata — echoed in the feed but NOT folded
-- into the advisory's signed canonical bytes: the security-relevant decision is the `severity` band
-- (which IS signed), so the score is informational. NULL when no vector was available (text severity).
ALTER TABLE advisories ADD COLUMN cvss TEXT;

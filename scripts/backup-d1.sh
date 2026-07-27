#!/usr/bin/env bash
# Export the remote noeta-registry D1 database to timestamped per-table SQL dumps (see DEPLOY.md).
#
#   ./scripts/backup-d1.sh [output-dir]     # default: ./backups
#
# Whole-database `wrangler d1 export` fails on this database ("cannot export databases with
# Virtual Tables (fts5)" — package_fts and its shadow tables), so this exports DATA ONLY,
# table by table, for every real table. Schema is not exported at all: on restore, apply
# `migrations/` first (recreates all tables including the FTS index), import these dumps, then
# rebuild the search index:  INSERT INTO package_fts(package_fts) VALUES('rebuild');
#
# Cadence: before every `migrate:remote`, and weekly otherwise. D1 Time Travel (30-day
# point-in-time restore) is the first-line recovery; these dumps are the offline complement.
# Dumps are operator artifacts — `backups/` is gitignored, never committed.
set -euo pipefail

cd "$(dirname "$0")/.."

DB_NAME="noeta-registry" # must match d1_databases[0].database_name in wrangler.jsonc
OUT_DIR="${1:-backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$OUT_DIR/$DB_NAME-$STAMP"

# Every real (non-virtual, non-shadow) table, d1_migrations included so a restore knows its
# migration state. Keep in sync with migrations/ when adding a table, AND with BACKUP_TABLES in
# src/backup.ts — the nightly automated R2 snapshot dumps the same list, and its completeness
# test fails when a table is neither backed up nor deliberately excluded. Deliberately absent:
# rendered_pages (a pure render cache, re-derivable from readmes+docs — see BACKUP_EXCLUDED).
TABLES=(d1_migrations scopes packages docs readmes package_keywords name_mappings log advisories reports rate_limits)

mkdir -p "$DEST"
for t in "${TABLES[@]}"; do
  npx wrangler d1 export "$DB_NAME" --remote --no-schema --table "$t" --output "$DEST/$t.sql"
done
echo "backup written: $DEST/ (${#TABLES[@]} tables, data only — schema comes from migrations/)"

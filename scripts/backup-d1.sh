#!/usr/bin/env bash
# Export the remote noeta-registry D1 database to a timestamped SQL dump (see DEPLOY.md).
#
#   ./scripts/backup-d1.sh [output-dir]     # default: ./backups
#
# Cadence: before every `migrate:remote`, and weekly otherwise. Dumps are operator artifacts —
# `backups/` is gitignored, never committed.
set -euo pipefail

cd "$(dirname "$0")/.."

DB_NAME="noeta-registry" # must match d1_databases[0].database_name in wrangler.jsonc
OUT_DIR="${1:-backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_DIR/$DB_NAME-$STAMP.sql"

mkdir -p "$OUT_DIR"
npx wrangler d1 export "$DB_NAME" --remote --output "$OUT"
echo "backup written: $OUT"

// Nightly automated D1 backups → R2 (the automated sibling of scripts/backup-d1.sh).
//
// Whole-database `wrangler d1 export` refuses this database (FTS5 virtual tables — package_fts and
// its shadow tables), so a backup is **data-only, per-table** SQL dumps; schema always comes from
// migrations/ (see DEPLOY.md "D1 backup"). Each dump is emitted in the SAME format
// `wrangler d1 export --no-schema --table <t>` produces —
//
//   PRAGMA defer_foreign_keys=TRUE;
//   INSERT INTO "t" ("c1","c2") VALUES(v1,v2);
//
// — so DEPLOY.md's restore ritual (fresh DB → apply migrations → `wrangler d1 execute --file` per
// table → rebuild package_fts) works unchanged on these objects. The only liberty taken is batching
// several rows into one INSERT's VALUES list (still plain SQLite, still executes verbatim).
//
// Layout in the bucket:  nightly/<UTC YYYYMMDDTHHMMSSZ>/<table>.sql  + manifest.json, written LAST —
// a manifest's presence marks a complete snapshot. A run that dies mid-way leaves a manifest-less
// partial prefix, which is harmless (restores pick a prefix WITH a manifest) and is eventually
// swept out by retention. Retention keeps the newest RETAIN_SNAPSHOTS dated prefixes.
//
// CPU-budget honesty: the D1 reads and R2 writes are I/O and don't count against Worker CPU time;
// the SQL serialization (escaping, joining) is CPU. Each table is serialized and uploaded
// independently — no whole-database string is ever built — so the peak cost is one table's dump.
// The database is kilobytes today; if a table ever outgrows the free-tier CPU budget (10 ms), the
// paid plan raises the ceiling (30 s default, configurable) long before this design does.

/** Every real (non-virtual, non-shadow) table, d1_migrations included so a restore knows its
 *  migration state. KEEP IN SYNC with `TABLES=(…)` in scripts/backup-d1.sh (the manual pre-migration
 *  tool) and with migrations/ when a migration adds a table — the completeness test in
 *  test/backup.test.ts fails if a table is neither listed here nor in BACKUP_EXCLUDED. */
export const BACKUP_TABLES = [
  "d1_migrations",
  "scopes",
  "packages",
  "docs",
  "readmes",
  "package_keywords",
  "name_mappings",
  "log",
  "advisories",
  "reports",
  "rate_limits",
] as const;

/** Tables DELIBERATELY absent from the dumps, each with its reason. The FTS family is excluded
 *  structurally (virtual/shadow tables — the reason dumps are per-table at all); everything named
 *  here is a conscious call, enforced by the completeness test so a new table can't silently miss
 *  the backups without someone deciding it should. */
export const BACKUP_EXCLUDED = [
  // Pure render cache: re-derivable from `readmes` + `docs` on demand. A restore recreates it
  // empty (migrations) and pages refill it on first view; dumping rendered HTML would only
  // bloat every snapshot.
  "rendered_pages",
] as const;

/** The backup job's cron expression — scheduled() branches on `event.cron`, so this MUST match one
 *  of `triggers.crons` in wrangler.jsonc (the other one is the advisory import's). */
export const BACKUP_CRON = "30 6 * * *";

/** Dated snapshot prefixes to keep (~90 nightly snapshots ≈ 90 days). */
const RETAIN_SNAPSHOTS = 90;

/** Rows fetched from D1 per page while dumping a table (bounds one query's result size). */
const PAGE_ROWS = 500;

/** Rows batched into one INSERT's VALUES list. Kept well under SQLite's compound-term limit (500)
 *  while still cutting statement count ~50× versus wrangler's one-row-per-INSERT. */
const ROWS_PER_INSERT = 50;

const PREFIX = "nightly/";

export interface BackupEnv {
  DB: D1Database;
  BACKUPS: R2Bucket;
}

export interface TableDumpStat {
  name: string;
  rows: number;
  bytes: number;
}

export interface BackupResult {
  prefix: string;
  tables: TableDumpStat[];
  durationMs: number;
  deletedPrefixes: string[];
}

/** One value → one SQLite literal, exactly as `wrangler d1 export` renders it: NULL, integer/real
 *  literals, single-quote-doubled TEXT, X'hex' BLOBs. All current columns are TEXT/INTEGER
 *  (see migrations/), but blobs are handled so a future BLOB column can't silently corrupt dumps. */
export function sqlLiteral(v: unknown): string {
  if (v === null || v === undefined) return "NULL";
  if (typeof v === "number") return String(v); // integers and reals; SQLite accepts JS's rendering
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string") return `'${v.replaceAll("'", "''")}'`;
  if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) {
    const bytes = v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return `X'${hex}'`;
  }
  throw new Error(`unserializable D1 value of type ${typeof v}`);
}

/** Dump one table to data-only SQL (the wrangler-export format described above). Pages through the
 *  table so no unbounded result set is ever held; `ORDER BY rowid` makes the paging stable (every
 *  table here is an ordinary rowid table). */
async function dumpTable(db: D1Database, table: string): Promise<{ sql: string; rows: number }> {
  const statements: string[] = ["PRAGMA defer_foreign_keys=TRUE;"];
  let columns: string | null = null; // `"c1","c2",…` — from the first page's column names
  let rows = 0;

  for (let offset = 0; ; offset += PAGE_ROWS) {
    // `table` comes from the compile-time BACKUP_TABLES list, never user input.
    const raw = await db
      .prepare(`SELECT * FROM "${table}" ORDER BY rowid LIMIT ? OFFSET ?`)
      .bind(PAGE_ROWS, offset)
      .raw({ columnNames: true });
    const [names, ...page] = raw as [string[] | undefined, ...unknown[][]];
    if (columns === null && names !== undefined) columns = names.map((c) => `"${c}"`).join(",");

    for (let i = 0; i < page.length; i += ROWS_PER_INSERT) {
      const values = page
        .slice(i, i + ROWS_PER_INSERT)
        .map((row) => `(${row.map(sqlLiteral).join(",")})`)
        .join(",");
      statements.push(`INSERT INTO "${table}" (${columns}) VALUES${values};`);
    }
    rows += page.length;
    if (page.length < PAGE_ROWS) break;
  }

  return { sql: statements.join("\n") + "\n", rows };
}

/** UTC stamp in the exact shape scripts/backup-d1.sh uses (`date -u +%Y%m%dT%H%M%SZ`), so nightly
 *  prefixes and manual dump directories read the same and sort chronologically. */
function utcStamp(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

/** Run one nightly snapshot: dump every real table to `nightly/<stamp>/<table>.sql`, then write
 *  `manifest.json` LAST (its presence = the snapshot is complete), then apply retention. */
export async function runBackup(env: BackupEnv, now: Date = new Date()): Promise<BackupResult> {
  const started = Date.now();
  const prefix = `${PREFIX}${utcStamp(now)}/`;
  const tables: TableDumpStat[] = [];

  // Each table independently: serialize, upload, drop the string — never a whole-DB concatenation.
  for (const table of BACKUP_TABLES) {
    const { sql, rows } = await dumpTable(env.DB, table);
    const bytes = new TextEncoder().encode(sql).byteLength;
    await env.BACKUPS.put(`${prefix}${table}.sql`, sql, {
      httpMetadata: { contentType: "application/sql" },
    });
    tables.push({ name: table, rows, bytes });
  }

  const durationMs = Date.now() - started;
  const manifest = {
    database: "noeta-registry",
    snapshot: prefix,
    startedAt: new Date(started).toISOString(),
    finishedAt: new Date().toISOString(),
    durationMs,
    tables,
  };
  await env.BACKUPS.put(`${prefix}manifest.json`, JSON.stringify(manifest, null, 2) + "\n", {
    httpMetadata: { contentType: "application/json" },
  });

  const deletedPrefixes = await applyRetention(env.BACKUPS);
  return { prefix, tables, durationMs, deletedPrefixes };
}

/** Delete snapshot prefixes beyond the newest `keep`. Stamps are fixed-width UTC, so lexicographic
 *  order IS chronological order. Listing uses delimiter-grouped pages with cursor continuation, so
 *  both >1000 snapshots and >1000 objects under one snapshot are handled. `pageLimit` exists so
 *  tests can force multi-page listings; production uses R2's default (1000). */
export async function applyRetention(
  bucket: R2Bucket,
  opts: { keep?: number; pageLimit?: number } = {},
): Promise<string[]> {
  const keep = opts.keep ?? RETAIN_SNAPSHOTS;

  // 1. Every dated prefix under nightly/ (deduped — a prefix's objects can span list pages).
  const seen = new Set<string>();
  let cursor: string | undefined;
  do {
    const page = await bucket.list({
      prefix: PREFIX,
      delimiter: "/",
      cursor,
      ...(opts.pageLimit !== undefined ? { limit: opts.pageLimit } : {}),
    });
    for (const p of page.delimitedPrefixes) seen.add(p);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor !== undefined);

  // 2. Newest `keep` survive; everything older goes (including manifest-less partials, once they
  //    age past the window).
  const victims = [...seen].sort().reverse().slice(keep);

  // 3. Delete each victim prefix's objects, batched at R2's 1000-key delete ceiling.
  for (const victim of victims) {
    let keys: string[] = [];
    let vcursor: string | undefined;
    do {
      const page = await bucket.list({
        prefix: victim,
        cursor: vcursor,
        ...(opts.pageLimit !== undefined ? { limit: opts.pageLimit } : {}),
      });
      keys.push(...page.objects.map((o) => o.key));
      vcursor = page.truncated ? page.cursor : undefined;
      while (keys.length >= 1000) {
        await bucket.delete(keys.slice(0, 1000));
        keys = keys.slice(1000);
      }
    } while (vcursor !== undefined);
    if (keys.length > 0) await bucket.delete(keys);
  }
  return victims;
}

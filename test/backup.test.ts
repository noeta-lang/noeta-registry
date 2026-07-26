import { applyD1Migrations, createExecutionContext, env, fetchMock, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";
import { applyRetention, BACKUP_CRON, BACKUP_TABLES, runBackup } from "../src/backup";

// Nightly automated D1→R2 backups (src/backup.ts). Miniflare simulates the BACKUPS R2 bucket; the
// dumps are proven restorable by executing them verbatim into RESTORE_DB — a second, fresh local D1
// carrying only the migrations' schema — exactly DEPLOY.md's restore ritual.

const workerEnv = env as unknown as Env;

/** Fire the Worker's scheduled() as the platform would, for the given trigger's cron expression. */
async function triggerCron(cron: string): Promise<void> {
  const controller = { scheduledTime: Date.now(), cron, noRetry() {} } as ScheduledController;
  const ctx = createExecutionContext();
  await worker.scheduled(controller, workerEnv, ctx);
  await waitOnExecutionContext(ctx); // drains waitUntil — the jobs run entirely inside it
}

/** Every key in the bucket under `prefix`, following cursors (a list page caps at 1000). */
async function listAllKeys(prefix: string): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.BACKUPS.list({ prefix, cursor });
    keys.push(...page.objects.map((o) => o.key));
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor !== undefined);
  return keys.sort();
}

/** Split a dump into statements, respecting single-quoted literals (which may contain `;` and
 *  newlines — that's the point of the hostile-string test). Doubling (`''`) stays inside a literal. */
function splitSql(sql: string): string[] {
  const out: string[] = [];
  let current = "";
  let inString = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    current += ch;
    if (inString) {
      if (ch === "'") {
        if (sql[i + 1] === "'") {
          current += "'";
          i++;
        } else {
          inString = false;
        }
      }
    } else if (ch === "'") {
      inString = true;
    } else if (ch === ";") {
      const stmt = current.trim();
      if (stmt.length > 0) out.push(stmt);
      current = "";
    }
  }
  const tail = current.trim();
  if (tail.length > 0) out.push(tail);
  return out;
}

async function allRows(db: D1Database, table: string): Promise<Record<string, unknown>[]> {
  return (await db.prepare(`SELECT * FROM "${table}" ORDER BY rowid`).all()).results;
}

/** Rows an adversarial publisher could plant: SQL-injection bait, quote storms, newlines, unicode. */
const HOSTILE_README = "'; DROP TABLE readmes;--\n''double-doubled'' \"quoted\"\r\nline with\ttab\nπανδαιμόνιον 🎉  končí";

async function seedHostileRows(): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO packages (name, version, url, tag, sha, deps, sig, yanked, published_by, published_at, bundle, license, description) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      "acme/hostile",
      "1.0.0",
      "https://git.test/acme/hostile",
      "v1.0.0",
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      '[{"package":"acme/dep","req":"^1"}]',
      null, // sig NULL
      1, // yanked integer
      null,
      "2026-07-26T00:00:00.000Z",
      null,
      "MIT OR Apache-2.0",
      "it's got 'quotes',\nnewlines; and -- comment bait",
    )
    .run();
  await env.DB.prepare("INSERT INTO readmes (name, version, readme_md, updated_at) VALUES (?, ?, ?, ?)")
    .bind("acme/hostile", "1.0.0", HOSTILE_README, "2026-07-26T00:00:00.000Z")
    .run();
  await env.DB.prepare("INSERT INTO scopes (scope, token_sha, public_key, created_at) VALUES (?, ?, ?, ?)")
    .bind("acme", "ab".repeat(32), null, "2026-07-26T00:00:00.000Z")
    .run();
}

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect(); // R2/D1 bindings don't route through fetch; only real egress is caught
});

describe("nightly backup cron", () => {
  it("snapshots every real table plus a manifest under one dated prefix, in the wrangler dump format", async () => {
    await seedHostileRows();
    await triggerCron(BACKUP_CRON);

    const keys = await listAllKeys("nightly/");
    // Exactly one snapshot: nightly/<stamp>/<table>.sql × 11 + manifest.json.
    const prefixes = new Set(keys.map((k) => k.split("/").slice(0, 2).join("/") + "/"));
    expect(prefixes.size).toBe(1);
    const prefix = [...prefixes][0];
    expect(prefix).toMatch(/^nightly\/\d{8}T\d{6}Z\/$/);
    expect(keys).toEqual([...BACKUP_TABLES.map((t) => `${prefix}${t}.sql`), `${prefix}manifest.json`].sort());

    // The exact wrangler `d1 export --no-schema` shape: PRAGMA header, quoted table + column list,
    // `VALUES(` with no space — so DEPLOY.md's `wrangler d1 execute --file` ritual applies unchanged.
    const scopes = await (await env.BACKUPS.get(`${prefix}scopes.sql`))!.text();
    expect(scopes.startsWith("PRAGMA defer_foreign_keys=TRUE;\n")).toBe(true);
    expect(scopes).toContain(
      'INSERT INTO "scopes" ("scope","token_sha","public_key","created_at","owner_kind","owner_id","require_provenance","provenance_root") VALUES(',
    );
    // An empty table is just the PRAGMA header, like wrangler emits.
    const rateLimits = await (await env.BACKUPS.get(`${prefix}rate_limits.sql`))!.text();
    expect(rateLimits).toBe("PRAGMA defer_foreign_keys=TRUE;\n");
  });

  it("round-trips hostile strings: the emitted SQL restores byte-identical rows into a fresh D1", async () => {
    await seedHostileRows();
    // Migrations only — the restore target starts as DEPLOY.md's "fresh database, apply migrations/".
    await applyD1Migrations(env.RESTORE_DB, env.TEST_MIGRATIONS);

    const { prefix } = await runBackup(workerEnv);

    for (const table of BACKUP_TABLES) {
      const dump = await (await env.BACKUPS.get(`${prefix}${table}.sql`))!.text();
      // d1_migrations: applying migrations populated the restore target's copy; the dump carries the
      // source's authoritative rows, so clear before importing (same for every table — all empty).
      await env.RESTORE_DB.prepare(`DELETE FROM "${table}"`).run();
      for (const stmt of splitSql(dump)) {
        await env.RESTORE_DB.prepare(stmt).run();
      }
      expect(await allRows(env.RESTORE_DB, table), table).toEqual(await allRows(env.DB, table));
    }

    // The hostile README specifically survived the round trip.
    const restored = await env.RESTORE_DB.prepare("SELECT readme_md FROM readmes WHERE name = 'acme/hostile'").first<{
      readme_md: string;
    }>();
    expect(restored?.readme_md).toBe(HOSTILE_README);
    // …and the FTS rebuild step of the ritual works on the restored database.
    await env.RESTORE_DB.prepare("INSERT INTO package_fts(package_fts) VALUES('rebuild')").run();
  });

  it("writes the manifest last, with correct per-table row counts and byte sizes", async () => {
    await seedHostileRows();
    const result = await runBackup(workerEnv);

    const manifestObj = await env.BACKUPS.get(`${result.prefix}manifest.json`);
    expect(manifestObj).not.toBeNull();
    const manifest = JSON.parse(await manifestObj!.text());
    expect(manifest.tables.map((t: { name: string }) => t.name)).toEqual([...BACKUP_TABLES]);

    for (const entry of manifest.tables as { name: string; rows: number; bytes: number }[]) {
      const count = await env.DB.prepare(`SELECT COUNT(*) AS n FROM "${entry.name}"`).first<{ n: number }>();
      expect(entry.rows, entry.name).toBe(count!.n);
      const head = await env.BACKUPS.head(`${result.prefix}${entry.name}.sql`);
      expect(head!.size, entry.name).toBe(entry.bytes);
      // Manifest-last is the completeness marker: every dump was uploaded before it.
      expect(head!.uploaded.getTime()).toBeLessThanOrEqual(manifestObj!.uploaded.getTime());
    }
    expect(manifest.tables.find((t: { name: string }) => t.name === "readmes")!.rows).toBe(1);
    expect(manifest.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("retention deletes only snapshot prefixes beyond the newest 90, across paginated listings", async () => {
    // 95 fake dated snapshots, oldest first (fixed-width stamps sort chronologically).
    const stamps: string[] = [];
    for (let i = 0; i < 95; i++) {
      const d = new Date(Date.UTC(2020, 0, 1 + i, 6, 30, 0));
      stamps.push(d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, ""));
    }
    for (const s of stamps) {
      await env.BACKUPS.put(`nightly/${s}/log.sql`, "PRAGMA defer_foreign_keys=TRUE;\n");
      await env.BACKUPS.put(`nightly/${s}/manifest.json`, "{}");
    }

    // A tiny page limit forces cursor continuation in both the prefix listing and per-victim listing.
    const deleted = await applyRetention(env.BACKUPS, { keep: 90, pageLimit: 7 });

    expect(deleted.sort()).toEqual(stamps.slice(0, 5).map((s) => `nightly/${s}/`));
    const remaining = await listAllKeys("nightly/");
    expect(remaining.length).toBe(90 * 2);
    // The oldest five are gone; the 90 newest are intact.
    for (const s of stamps.slice(0, 5)) expect(remaining.some((k) => k.startsWith(`nightly/${s}/`))).toBe(false);
    for (const s of stamps.slice(5)) {
      expect(remaining).toContain(`nightly/${s}/log.sql`);
      expect(remaining).toContain(`nightly/${s}/manifest.json`);
    }
  });

  it("a full backup run retains its own fresh snapshot and sweeps the excess", async () => {
    for (let i = 0; i < 92; i++) {
      const d = new Date(Date.UTC(2020, 0, 1 + i, 6, 30, 0));
      const s = d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
      await env.BACKUPS.put(`nightly/${s}/manifest.json`, "{}");
    }
    const result = await runBackup(workerEnv);
    // 92 old + 1 new = 93 → the 3 oldest go; the just-written snapshot survives.
    expect(result.deletedPrefixes.length).toBe(3);
    expect(await env.BACKUPS.head(`${result.prefix}manifest.json`)).not.toBeNull();
  });

  it("the advisory cron branch still runs the import, and never touches the backup bucket", async () => {
    // A mapped package + a stubbed api.osv.dev (the source the import queries by default).
    await env.DB.prepare("INSERT INTO name_mappings (ecosystem, external_name, noeta_package, created_at) VALUES (?, ?, ?, ?)")
      .bind("crates.io", "tokio", "acme/tokio", "2026-07-26T00:00:00.000Z")
      .run();
    fetchMock
      .get("https://api.osv.dev")
      .intercept({ path: "/v1/query", method: "POST" })
      .reply(
        200,
        JSON.stringify({
          vulns: [
            {
              id: "OSV-BACKUP-BRANCH-1",
              summary: "advisory branch still wired",
              affected: [
                {
                  package: { ecosystem: "crates.io", name: "tokio" },
                  ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }],
                },
              ],
            },
          ],
        }),
      );

    await triggerCron("0 6 * * *");

    const imported = await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories WHERE upstream_id = 'OSV-BACKUP-BRANCH-1'").first<{
      n: number;
    }>();
    expect(imported!.n).toBe(1);
    expect(await listAllKeys("nightly/")).toEqual([]); // the advisory branch wrote no backups
  });
});

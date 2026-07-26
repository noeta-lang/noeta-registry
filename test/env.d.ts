import type { D1Migration } from "@cloudflare/vitest-pool-workers/config";

// The test env: the Worker's own bindings plus the migrations list and an admin token the suite sets.
declare module "cloudflare:test" {
  interface ProvidedEnv {
    DB: D1Database;
    /** Nightly-backup destination (wrangler.jsonc r2_buckets; simulated by Miniflare in tests). */
    BACKUPS: R2Bucket;
    /** A fresh D1 the backup tests restore emitted dumps into (vitest.config.ts, tests only). */
    RESTORE_DB: D1Database;
    ADMIN_TOKEN: string;
    TEST_MIGRATIONS: D1Migration[];
    /** The golden wire fixtures (test/fixtures/wire), raw text keyed by filename. */
    WIRE_FIXTURES: Record<string, string>;
  }
}

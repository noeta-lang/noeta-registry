import type { D1Migration } from "@cloudflare/vitest-pool-workers/config";

// The test env: the Worker's own bindings plus the migrations list and an admin token the suite sets.
declare module "cloudflare:test" {
  interface ProvidedEnv {
    DB: D1Database;
    ADMIN_TOKEN: string;
    TEST_MIGRATIONS: D1Migration[];
    /** The golden wire fixtures (test/fixtures/wire), raw text keyed by filename. */
    WIRE_FIXTURES: Record<string, string>;
  }
}

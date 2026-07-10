import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll } from "vitest";

// Apply the D1 schema to the per-suite local database before any test runs.
beforeAll(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});

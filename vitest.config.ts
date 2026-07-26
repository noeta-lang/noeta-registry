import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";
import fs from "node:fs";
import path from "node:path";

// The golden wire fixtures (test/fixtures/wire) — a VERBATIM copy of the canonical set in the
// language repo (crates/noeta-pm/test_data/wire; see the fixtures' README for the sync rule).
// Read at config time (workerd has no fs) and bound as raw text, name → bytes, so the tests can
// both parse them and hash them against MANIFEST.sha256.
function readWireFixtures(): Record<string, string> {
  const dir = path.join(__dirname, "test", "fixtures", "wire");
  const out: Record<string, string> = {};
  for (const name of fs.readdirSync(dir)) {
    if (name.endsWith(".json") || name === "MANIFEST.sha256") {
      out[name] = fs.readFileSync(path.join(dir, name), "utf8");
    }
  }
  return out;
}

// Run the Worker inside Miniflare with a real local D1, migrations applied per-suite.
export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));
  return {
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
      poolOptions: {
        workers: {
          singleWorker: true,
          wrangler: { configPath: "./wrangler.jsonc" },
          miniflare: {
            // A second, initially-empty D1 the backup tests restore emitted dumps into — proving a
            // dump executes verbatim against a fresh database (DEPLOY.md's restore ritual).
            d1Databases: { RESTORE_DB: { id: "restore-db" } },
            bindings: {
              TEST_MIGRATIONS: migrations,
              WIRE_FIXTURES: readWireFixtures(),
              ADMIN_TOKEN: "test-admin-token",
              // Self-service claim OIDC config — a hermetic test issuer whose JWKS the claim tests
              // serve via fetchMock (namespace-protection #1).
              OIDC_ISSUER: "https://oidc.test",
              OIDC_AUDIENCE: "noeta-registry",
              OIDC_JWKS_URL: "https://oidc.test/jwks",
              GITHUB_API_URL: "https://gh-api.test",
              // A fixed Ed25519 keypair for the transparency-log checkpoint signature (test only).
              LOG_PRIVATE_KEY: "MC4CAQAwBQYDK2VwBCIEIF7tVhZn1Nzi0DL/WfLAuN6AhBpBJbvYb3kT/17l/yqV",
              LOG_PUBLIC_KEY: "687d518f510ddd9bc55cdde06bd455bc13aa8793ca244f0f55df4cf70c30ecdb",
              // A distinct fixed Ed25519 keypair for the advisory feed's signatures (test only).
              ADVISORY_PRIVATE_KEY: "MC4CAQAwBQYDK2VwBCIEIJmzO//7nVhe4N5KM/SqhjrCTx1y0fOavs1mnc7BbVth",
              ADVISORY_PUBLIC_KEY: "96985fcd2e6cef8ef8fc8c28351d27b83e0593462016b48e9fa8c4dd10736df4",
            },
          },
        },
      },
    },
  };
});

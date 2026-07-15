import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";
import path from "node:path";

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
            bindings: {
              TEST_MIGRATIONS: migrations,
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
            },
          },
        },
      },
    },
  };
});

import { env, fetchMock } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { importRecords, runScheduledImport, type ImportEnv } from "../src/imports";
import { ghsaSource, osvApiSource, rustsecSource, collectFromSources } from "../src/sources";

// Per-ecosystem source adapters (advisory-intake residual c). Every upstream fetch is stubbed with the
// cloudflare:test fetchMock (undici MockAgent) — nothing here touches a real network. We seed the
// operator-curated name map directly in D1, then drive the adapters and the scheduled-cron entry.

const jsonReply = (body: unknown) => JSON.stringify(body);

/** A test env with the upstream endpoints pointed at mock hosts. `over` toggles per-source config. */
function testEnv(over: Partial<ImportEnv> = {}): ImportEnv {
  return {
    ...(env as unknown as ImportEnv),
    OSV_API_URL: "https://osv.test",
    GITHUB_GRAPHQL_URL: "https://ghsa.test/graphql",
    ...over,
  };
}

async function mapPackage(ecosystem: string, external: string, noeta: string) {
  await env.DB.prepare(
    "INSERT INTO name_mappings (ecosystem, external_name, noeta_package, created_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(ecosystem, external_name) DO UPDATE SET noeta_package = excluded.noeta_package",
  )
    .bind(ecosystem, external, noeta, new Date().toISOString())
    .run();
}

async function advisory(id: string): Promise<any> {
  return env.DB.prepare("SELECT * FROM advisories WHERE id = ?").bind(id).first();
}

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});
beforeEach(() => {
  // A fresh, empty interceptor set per test — each test declares exactly the upstream pages it expects.
  fetchMock.assertNoPendingInterceptors?.();
});

describe("OSV api.osv.dev adapter", () => {
  it("queries only the mapped package, follows page_token pagination, and imports as tier=imported", async () => {
    await mapPackage("crates.io", "tokio", "acme/tokio");
    // Page 1 → a vuln + a next_page_token; page 2 → a second vuln, no token.
    fetchMock
      .get("https://osv.test")
      .intercept({ path: "/v1/query", method: "POST" })
      .reply(
        200,
        jsonReply({
          vulns: [
            {
              id: "OSV-TOKIO-1",
              summary: "first",
              severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
              affected: [{ package: { ecosystem: "crates.io", name: "tokio" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.0" }] }] }],
            },
          ],
          next_page_token: "PAGE2",
        }),
      );
    fetchMock
      .get("https://osv.test")
      .intercept({ path: "/v1/query", method: "POST" })
      .reply(
        200,
        jsonReply({
          vulns: [
            {
              id: "OSV-TOKIO-2",
              summary: "second",
              database_specific: { severity: "MODERATE" },
              affected: [{ package: { ecosystem: "crates.io", name: "tokio" }, ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.0" }] }] }],
            },
          ],
        }),
      );

    const records = await osvApiSource(testEnv(), [{ ecosystem: "crates.io", external_name: "tokio", noeta_package: "acme/tokio" }]);
    expect(records.map((r) => r.id)).toEqual(["OSV-TOKIO-1", "OSV-TOKIO-2"]);

    const result = await importRecords(testEnv(), records);
    expect(result.imported).toBe(2);
    const a1 = await advisory("OSV-TOKIO-1");
    expect(a1.tier).toBe("imported");
    expect(a1.severity).toBe("critical"); // derived from the CVSS vector, not text
    expect(a1.cvss).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    const a2 = await advisory("OSV-TOKIO-2");
    expect(a2.severity).toBe("medium"); // MODERATE → medium (text fallback, no CVSS)
    expect(a2.cvss).toBeNull();
  });

  it("is disabled by OSV_API=off", async () => {
    const records = await osvApiSource(testEnv({ OSV_API: "off" }), [
      { ecosystem: "crates.io", external_name: "tokio", noeta_package: "acme/tokio" },
    ]);
    expect(records).toEqual([]);
  });
});

describe("GHSA GitHub GraphQL adapter", () => {
  it("skips entirely without a GITHUB_TOKEN", async () => {
    const records = await ghsaSource(testEnv(), [{ ecosystem: "npm", external_name: "left-pad", noeta_package: "acme/pad" }]);
    expect(records).toEqual([]);
  });

  it("queries per package, paginates, and carries the CVSS vector into the derived band", async () => {
    await mapPackage("npm", "left-pad", "acme/pad");
    const page = (hasNext: boolean, ghsaId: string) =>
      jsonReply({
        data: {
          securityVulnerabilities: {
            pageInfo: { hasNextPage: hasNext, endCursor: hasNext ? "CUR" : null },
            nodes: [
              {
                vulnerableVersionRange: ">= 1.0.0, < 1.3.0",
                firstPatchedVersion: { identifier: "1.3.0" },
                package: { name: "left-pad" },
                advisory: {
                  ghsaId,
                  summary: "prototype pollution",
                  description: "details here",
                  permalink: "https://github.com/advisories/" + ghsaId,
                  references: [{ url: "https://example.test/ref" }],
                  cvss: { vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" },
                },
              },
            ],
          },
        },
      });
    fetchMock.get("https://ghsa.test").intercept({ path: "/graphql", method: "POST" }).reply(200, page(true, "GHSA-aaaa-bbbb-cccc"));
    fetchMock.get("https://ghsa.test").intercept({ path: "/graphql", method: "POST" }).reply(200, page(false, "GHSA-dddd-eeee-ffff"));

    const records = await ghsaSource(testEnv({ GITHUB_TOKEN: "ghtok" }), [
      { ecosystem: "npm", external_name: "left-pad", noeta_package: "acme/pad" },
    ]);
    expect(records.map((r) => r.id)).toEqual(["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]);
    // The GHSA range maps into OSV events → the same derived range string.
    const result = await importRecords(testEnv({ GITHUB_TOKEN: "ghtok" }), records);
    expect(result.imported).toBe(2);
    const a = await advisory("GHSA-aaaa-bbbb-cccc");
    expect(a.package).toBe("acme/pad");
    expect(a.ranges).toBe(">=1.0.0, <1.3.0");
    expect(a.severity).toBe("medium"); // 4.3 from the CVSS vector
    expect(a.cvss).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
    expect(a.upstream_url).toBe("https://github.com/advisories/GHSA-aaaa-bbbb-cccc");
  });
});

describe("RUSTSEC OSV-feed adapter", () => {
  it("streams a paginated feed via next_page_token", async () => {
    fetchMock
      .get("https://rustsec.test")
      .intercept({ path: "/osv", method: "GET" })
      .reply(200, jsonReply({ advisories: [{ id: "RUSTSEC-2026-0001" }], next_page_token: "P2" }));
    fetchMock
      .get("https://rustsec.test")
      .intercept({ path: "/osv?page_token=P2", method: "GET" })
      .reply(200, jsonReply({ advisories: [{ id: "RUSTSEC-2026-0002" }] }));

    const records = await rustsecSource(testEnv({ RUSTSEC_IMPORT_URL: "https://rustsec.test/osv" }));
    expect(records.map((r) => r.id)).toEqual(["RUSTSEC-2026-0001", "RUSTSEC-2026-0002"]);
  });

  it("skips without a RUSTSEC_IMPORT_URL", async () => {
    expect(await rustsecSource(testEnv())).toEqual([]);
  });
});

describe("collectFromSources / runScheduledImport", () => {
  it("de-duplicates a record present in two sources by upstream id", async () => {
    await mapPackage("crates.io", "shared", "acme/shared");
    const rec = {
      id: "OSV-SHARED-1",
      summary: "shared vuln",
      affected: [{ package: { ecosystem: "crates.io", name: "shared" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] }],
    };
    // OSV api returns it (one page); RUSTSEC feed returns the same id.
    fetchMock.get("https://osv.test").intercept({ path: "/v1/query", method: "POST" }).reply(200, jsonReply({ vulns: [rec] }));
    fetchMock.get("https://rustsec.test").intercept({ path: "/osv", method: "GET" }).reply(200, jsonReply({ advisories: [rec] }));

    const merged = await collectFromSources(testEnv({ RUSTSEC_IMPORT_URL: "https://rustsec.test/osv" }));
    expect(merged.filter((r) => r.id === "OSV-SHARED-1")).toHaveLength(1);
  });

  it("runs the cron end-to-end: mapped imports, unmapped skips, idempotent re-run", async () => {
    await mapPackage("crates.io", "mapped", "acme/mapped");
    const records = {
      vulns: [
        { id: "OSV-CRON-MAPPED", summary: "m", affected: [{ package: { ecosystem: "crates.io", name: "mapped" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }] },
        { id: "OSV-CRON-UNMAPPED", summary: "u", affected: [{ package: { ecosystem: "crates.io", name: "not-mapped" }, ranges: [] }] },
      ],
    };
    // Two mapped packages are queried once each; only "mapped" returns the pair (unmapped external name
    // yields nothing). Serve the same payload for whichever query lands (both consume one interceptor).
    fetchMock.get("https://osv.test").intercept({ path: "/v1/query", method: "POST" }).reply(200, jsonReply(records));

    const first = await runScheduledImport(testEnv());
    expect(first.imported).toBe(1);
    expect(first.skipped).toBe(1);

    // Re-run is idempotent: same upstream id upserts, the advisory count is unchanged.
    fetchMock.get("https://osv.test").intercept({ path: "/v1/query", method: "POST" }).reply(200, jsonReply(records));
    const before = (await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories").first<{ n: number }>())!.n;
    await runScheduledImport(testEnv());
    const after = (await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories").first<{ n: number }>())!.n;
    expect(after).toBe(before);
  });
});

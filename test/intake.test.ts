import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/merkle";

// Advisory-intake arc: publisher self-service (tier 2), OSV import (tier 3), public report queue (tier 4).

const ADMIN = "test-admin-token";
const PUB = "96985fcd2e6cef8ef8fc8c28351d27b83e0593462016b48e9fa8c4dd10736df4";
const ACME_TOKEN = "acme-publish-token-abcdef123456";

const post = (path: string, body: unknown, token?: string, headers: Record<string, string> = {}) =>
  SELF.fetch("https://registry.test/v1" + path, {
    method: "POST",
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: JSON.stringify(body),
  });
const get = (path: string, token?: string) =>
  SELF.fetch("https://registry.test/v1" + path, {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
const getJson = async (path: string, token?: string) => (await (await get(path, token)).json()) as any;

async function canonicalBytes(a: any): Promise<Uint8Array> {
  const detailsHash = toHex(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(a.details ?? ""))),
  );
  const state = a.withdrawn ? "withdrawn" : "active";
  return new TextEncoder().encode(
    `noeta-advisory-v1\n${a.id}\n${a.package}\n${a.ranges}\n${a.severity}\n` +
      `${state}\n${a.summary}\n${detailsHash}\n${a.url ?? ""}\n${a.tier ?? "operator"}\n`,
  );
}
async function verifySig(msg: Uint8Array, sigHex: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", fromHex(PUB), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, fromHex(sigHex), msg);
}

// A minimal but valid-JSON stand-in for a keyless Sigstore bundle (stored verbatim; the registry never
// verifies it — the consumer does, offline).
const BUNDLE = JSON.stringify({ mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3", dsseEnvelope: {} });

beforeAll(async () => {
  // A scope acme owns, for the publisher-advisory + scope-triage tests.
  expect((await post("/scopes", { scope: "acme", token: ACME_TOKEN }, ADMIN)).status).toBe(201);
});

describe("publisher advisories (tier 2)", () => {
  const ADV = {
    id: "ACME-2026-0001",
    package: "acme/imgfx",
    ranges: ">=1.0.0, <1.2.0",
    severity: "high",
    summary: "owner-issued: buffer overflow",
    bundle: BUNDLE,
  };

  it("lets a scope owner publish a publisher-tier advisory for their own package", async () => {
    const r = await post("/scopes/acme/advisories", ADV, ACME_TOKEN);
    expect(r.status).toBe(201);
    const body = (await r.json()) as any;
    expect(body.tier).toBe("publisher");

    const { advisories } = await getJson("/advisories");
    const a = advisories.find((x: any) => x.id === ADV.id);
    expect(a.tier).toBe("publisher");
    expect(a.bundle).toBe(BUNDLE);
    // The feed signature covers the tier (publisher is bound into the canonical bytes).
    expect(await verifySig(await canonicalBytes(a), a.signature)).toBe(true);
  });

  it("refuses a publisher advisory for a package outside the scope", async () => {
    const r = await post("/scopes/acme/advisories", { ...ADV, id: "ACME-2026-0002", package: "other/pkg" }, ACME_TOKEN);
    expect(r.status).toBe(403);
  });

  it("refuses a publisher advisory without a bundle", async () => {
    const { bundle, ...noBundle } = ADV;
    const r = await post("/scopes/acme/advisories", { ...noBundle, id: "ACME-2026-0003" }, ACME_TOKEN);
    expect(r.status).toBe(400);
  });

  it("refuses a publisher advisory without the scope token", async () => {
    expect((await post("/scopes/acme/advisories", { ...ADV, id: "ACME-2026-0004" }, "wrong")).status).toBe(403);
  });
});

describe("imported advisories (tier 3)", () => {
  const OSV = {
    id: "GHSA-xxxx-yyyy-zzzz",
    summary: "upstream: use-after-free",
    details: "See the upstream advisory.",
    database_specific: { severity: "CRITICAL" },
    affected: [
      {
        package: { ecosystem: "crates.io", name: "imgfx-rs" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
      },
    ],
    references: [{ url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz" }],
  };

  it("skips an unmapped upstream package", async () => {
    const r = await post("/advisories/import", { advisories: [OSV] }, ADMIN);
    expect(r.status).toBe(200);
    expect(((await r.json()) as any).skipped).toBe(1);
  });

  it("imports a mapped record as a tier=imported advisory with upstream provenance", async () => {
    // Operator maps the upstream crate to a Noeta package first (the curated judgment).
    expect(
      (await post("/name-mappings", { ecosystem: "crates.io", external_name: "imgfx-rs", noeta_package: "acme/imgfx" }, ADMIN))
        .status,
    ).toBe(201);
    const r = await post("/advisories/import", { advisories: [OSV] }, ADMIN);
    expect(r.status).toBe(200);
    expect(((await r.json()) as any).imported).toBe(1);

    const { advisories } = await getJson("/advisories");
    const a = advisories.find((x: any) => x.id === OSV.id);
    expect(a.tier).toBe("imported");
    expect(a.package).toBe("acme/imgfx");
    expect(a.severity).toBe("critical");
    expect(a.ranges).toBe("<2.0.0");
    expect(a.upstream_id).toBe(OSV.id);
    expect(a.upstream_url).toBe(OSV.references[0].url);
    expect(await verifySig(await canonicalBytes(a), a.signature)).toBe(true);
  });

  it("is idempotent — re-importing updates in place", async () => {
    expect(
      (await post("/name-mappings", { ecosystem: "crates.io", external_name: "imgfx-rs", noeta_package: "acme/imgfx" }, ADMIN))
        .status,
    ).toBe(201);
    await post("/advisories/import", { advisories: [OSV] }, ADMIN);
    const before = await getJson("/advisories/checkpoint");
    await post("/advisories/import", { advisories: [OSV] }, ADMIN);
    const after = await getJson("/advisories/checkpoint");
    expect(after.count).toBe(before.count); // same id → update, not a new row
  });

  it("requires the admin token to import or map", async () => {
    expect((await post("/advisories/import", { advisories: [] })).status).toBe(401);
    expect((await post("/name-mappings", { ecosystem: "x", external_name: "y", noeta_package: "a/b" })).status).toBe(401);
  });
});

describe("public report queue (tier 4)", () => {
  const REPORT = { package: "acme/imgfx", summary: "looks like it leaks memory", details: "repro attached" };

  it("accepts an anonymous report but never surfaces it in the advisory feed", async () => {
    const r = await post("/reports", REPORT, undefined, { "CF-Connecting-IP": "203.0.113.1" });
    expect(r.status).toBe(201);
    const body = (await r.json()) as any;
    expect(body.id).toBeTruthy();

    // It is queued, not an advisory.
    const { advisories } = await getJson("/advisories");
    expect(advisories.find((a: any) => a.summary === REPORT.summary)).toBeUndefined();
    // Listing requires admin.
    expect((await get("/reports")).status).toBe(401);
    const queue = await getJson("/reports?status=pending", ADMIN);
    expect(queue.reports.some((x: any) => x.id === body.id)).toBe(true);
    // ip_hash is never served.
    expect(queue.reports[0].ip_hash).toBeUndefined();
  });

  it("promotes a report into an operator advisory (admin)", async () => {
    const filed = (await (await post("/reports", REPORT, undefined, { "CF-Connecting-IP": "203.0.113.2" })).json()) as any;
    const adv = {
      id: "NOETA-2026-0100",
      package: "acme/imgfx",
      ranges: ">=1.0.0, <1.3.0",
      severity: "medium",
      summary: "confirmed memory leak in the decoder",
    };
    const p = await post(`/reports/${filed.id}/promote`, adv, ADMIN);
    expect(p.status).toBe(201);
    expect(((await p.json()) as any).tier).toBe("operator");

    const { advisories } = await getJson("/advisories");
    const a = advisories.find((x: any) => x.id === adv.id);
    expect(a.tier).toBe("operator");
    // The report is now marked promoted, pointing at the advisory.
    const queue = await getJson("/reports?status=promoted", ADMIN);
    const rep = queue.reports.find((x: any) => x.id === filed.id);
    expect(rep.advisory_id).toBe(adv.id);
  });

  it("promotes a report into a publisher advisory (scope owner, with a bundle)", async () => {
    const filed = (await (await post("/reports", REPORT, undefined, { "CF-Connecting-IP": "203.0.113.3" })).json()) as any;
    const adv = {
      id: "ACME-2026-0200",
      package: "acme/imgfx",
      ranges: ">=1.0.0",
      severity: "low",
      summary: "owner-confirmed leak",
      bundle: BUNDLE,
    };
    const p = await post(`/reports/${filed.id}/promote`, adv, ACME_TOKEN);
    expect(p.status).toBe(201);
    expect(((await p.json()) as any).tier).toBe("publisher");
  });

  it("lets a scope owner triage only their own scope's reports", async () => {
    await post("/reports", REPORT, undefined, { "CF-Connecting-IP": "203.0.113.4" });
    await post("/reports", { package: "other/thing", summary: "x" }, undefined, { "CF-Connecting-IP": "203.0.113.5" });
    const mine = await getJson("/scopes/acme/reports", ACME_TOKEN);
    expect(mine.reports.every((r: any) => r.package.startsWith("acme/"))).toBe(true);
    expect(mine.reports.some((r: any) => r.package === "other/thing")).toBe(false);
  });

  it("dismisses a report (admin) without issuing an advisory", async () => {
    const filed = (await (await post("/reports", REPORT, undefined, { "CF-Connecting-IP": "203.0.113.6" })).json()) as any;
    expect((await post(`/reports/${filed.id}/dismiss`, {}, ADMIN)).status).toBe(200);
    // A second dismiss/promote is a conflict (already dismissed).
    expect((await post(`/reports/${filed.id}/dismiss`, {}, ADMIN)).status).toBe(409);
  });

  it("rate-limits an IP flooding the queue", async () => {
    const ip = "198.51.100.9";
    let hit429 = false;
    for (let i = 0; i < 8; i++) {
      const r = await post("/reports", REPORT, undefined, { "CF-Connecting-IP": ip });
      if (r.status === 429) hit429 = true;
    }
    expect(hit429).toBe(true);
  });

  it("validates the report body", async () => {
    expect((await post("/reports", { package: "notslashed", summary: "x" })).status).toBe(400);
    expect((await post("/reports", { package: "acme/imgfx", summary: "line\nbreak" })).status).toBe(400);
    expect((await post("/reports", { package: "acme/imgfx" })).status).toBe(400);
  });
});

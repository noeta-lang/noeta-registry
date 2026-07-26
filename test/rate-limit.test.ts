import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

// Per-IP rate limiting on the unauthenticated-hammerable write surface (claim / publish / rotate) —
// a D1 sliding window keyed by a hash of the caller's IP (migrations/0017_rate_limits.sql). The
// other suites run with no client address, which the limiter deliberately does not count (the same
// carve-out as the report queue's flood valve), so these tests set CF-Connecting-IP explicitly.

const ADMIN = "test-admin-token"; // matches vitest.config.ts miniflare bindings
const TOKEN = "ratelimit-scope-token-abc123";

function post(path: string, body: unknown, token?: string, ip?: string): Promise<Response> {
  return SELF.fetch("https://registry.test/v1" + path, {
    method: "POST",
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(ip ? { "CF-Connecting-IP": ip } : {}),
    },
    body: JSON.stringify(body),
  });
}
const get = (path: string, ip?: string) =>
  SELF.fetch("https://registry.test/v1" + path, { headers: ip ? { "CF-Connecting-IP": ip } : {} });

beforeAll(async () => {
  expect((await post("/scopes", { scope: "ratelimited", token: TOKEN }, ADMIN)).status).toBe(201);
});

describe("per-IP rate limits", () => {
  it("publish: allows 10/minute per IP, then 429s with retry-after; other IPs are unaffected", async () => {
    const ip = "203.0.113.10";
    for (let i = 0; i < 10; i++) {
      const r = await post(
        `/packages/ratelimited/pub`,
        { version: `1.0.${i}`, url: "u", tag: "t", sha: "s" },
        TOKEN,
        ip,
      );
      expect(r.status, `publish #${i + 1}`).toBe(201);
    }
    const blocked = await post(
      "/packages/ratelimited/pub",
      { version: "1.0.10", url: "u", tag: "t", sha: "s" },
      TOKEN,
      ip,
    );
    expect(blocked.status).toBe(429);
    const retryAfter = Number(blocked.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
    expect(((await blocked.json()) as any).error).toContain("10/minute");

    // The window is per-IP: a different address publishes immediately.
    const other = await post(
      "/packages/ratelimited/pub",
      { version: "1.0.10", url: "u", tag: "t", sha: "s" },
      TOKEN,
      "203.0.113.11",
    );
    expect(other.status).toBe(201);
  });

  it("publish: failed attempts burn the same budget (auth probes can't hammer for free)", async () => {
    const ip = "203.0.113.12";
    for (let i = 0; i < 10; i++) {
      const r = await post(`/packages/ratelimited/probe`, { version: "1.0.0", url: "u", tag: "t", sha: "s" }, "wrong-token", ip);
      expect(r.status, `probe #${i + 1}`).toBe(403);
    }
    const blocked = await post("/packages/ratelimited/probe", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, TOKEN, ip);
    expect(blocked.status).toBe(429);
  });

  it("claim: allows 3/hour per IP, then 429s", async () => {
    const ip = "203.0.113.20";
    // Malformed claims (no proof) still count — the limiter gates the attempt, not its outcome.
    for (let i = 0; i < 3; i++) {
      const r = await post("/scopes/claim", { scope: `claimco${i}`, token: TOKEN }, undefined, ip);
      expect(r.status, `claim #${i + 1}`).toBe(400);
    }
    const blocked = await post("/scopes/claim", { scope: "claimco3", token: TOKEN }, undefined, ip);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(((await blocked.json()) as any).error).toContain("3/hour");
  });

  it("rotate: allows 5/hour per IP, then 429s", async () => {
    const ip = "203.0.113.30";
    let current = TOKEN;
    for (let i = 0; i < 5; i++) {
      const r = await post("/scopes/ratelimited/rotate", {}, current, ip);
      expect(r.status, `rotate #${i + 1}`).toBe(200);
      current = ((await r.json()) as any).token;
    }
    const blocked = await post("/scopes/ratelimited/rotate", {}, current, ip);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(((await blocked.json()) as any).error).toContain("5/hour");
  });

  it("never rate-limits reads, even from a heavily throttled IP", async () => {
    const ip = "203.0.113.10"; // already 429'd for publish above
    for (let i = 0; i < 15; i++) {
      expect((await get("/packages/ratelimited/pub", ip)).status).toBe(200);
    }
    expect((await get("/log/checkpoint", ip)).status).toBe(200);
  });

  it("does not count requests with no client address (the harness carve-out the other suites rely on)", async () => {
    for (let i = 0; i < 12; i++) {
      const r = await post(`/packages/ratelimited/noip`, { version: `2.0.${i}`, url: "u", tag: "t", sha: "s" }, TOKEN);
      expect(r.status, `publish #${i + 1}`).toBe(201);
    }
  });
});

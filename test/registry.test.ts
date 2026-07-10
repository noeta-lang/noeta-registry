import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

const ADMIN = "test-admin-token"; // matches vitest.config.ts miniflare bindings
const TOKEN = "acme-publish-token-abc123";

function post(path: string, body: unknown, token?: string): Promise<Response> {
  return SELF.fetch("https://registry.test/v1" + path, {
    method: "POST",
    headers: token ? { authorization: `Bearer ${token}` } : {},
    body: JSON.stringify(body),
  });
}
const get = (path: string) => SELF.fetch("https://registry.test/v1" + path);

// Bootstrap the `acme` scope so publishes under it are authorized.
beforeAll(async () => {
  const r = await post("/scopes", { scope: "acme", token: TOKEN }, ADMIN);
  expect(r.status).toBe(201);
});

describe("noeta registry", () => {
  it("publishes a release and lists it with its pinned SHA", async () => {
    const p = await post(
      "/packages/acme/imgfx",
      { version: "1.2.0", url: "https://github.com/acme/imgfx", tag: "v1.2.0", sha: "e3b0c44" },
      TOKEN,
    );
    expect(p.status).toBe(201);
    const body = (await (await get("/packages/acme/imgfx")).json()) as any;
    expect(body.name).toBe("acme/imgfx");
    expect(body.versions).toHaveLength(1);
    expect(body.versions[0]).toMatchObject({ version: "1.2.0", sha: "e3b0c44", yanked: false });
  });

  it("stores and serves per-version dependency metadata", async () => {
    const p = await post(
      "/packages/acme/http",
      {
        version: "1.0.0",
        url: "https://github.com/acme/http",
        tag: "v1.0.0",
        sha: "abc",
        deps: [{ package: "acme/bytes", req: "^1.2" }, { package: "acme/url", req: ">=2, <3" }],
      },
      TOKEN,
    );
    expect(p.status).toBe(201);
    const body = (await (await get("/packages/acme/http")).json()) as any;
    expect(body.versions[0].deps).toEqual([
      { package: "acme/bytes", req: "^1.2" },
      { package: "acme/url", req: ">=2, <3" },
    ]);
  });

  it("rejects a malformed dep", async () => {
    const bad = await post(
      "/packages/acme/d",
      { version: "1.0.0", url: "u", tag: "t", sha: "s", deps: [{ package: "not-an-identity", req: "^1" }] },
      TOKEN,
    );
    expect(bad.status).toBe(400);
  });

  it("returns an empty list for an unknown package", async () => {
    const body = (await (await get("/packages/who/dis")).json()) as any;
    expect(body.versions).toEqual([]);
  });

  it("makes a published version immutable (idempotent re-publish, 409 on re-point)", async () => {
    await post("/packages/acme/lib", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, TOKEN);
    const same = await post("/packages/acme/lib", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, TOKEN);
    expect(same.status).toBe(200); // idempotent
    const repoint = await post("/packages/acme/lib", { version: "1.0.0", url: "u", tag: "t", sha: "EVIL" }, TOKEN);
    expect(repoint.status).toBe(409); // immutable — cannot re-point to a new SHA
  });

  it("enforces scope ownership on publish", async () => {
    const noauth = await post("/packages/acme/x", { version: "1.0.0", url: "u", tag: "t", sha: "s" });
    expect(noauth.status).toBe(401);
    const wrong = await post("/packages/acme/x", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, "wrong");
    expect(wrong.status).toBe(403);
    // A token valid for `acme` cannot publish under an unregistered/other scope.
    const other = await post("/packages/evilcorp/x", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, TOKEN);
    expect(other.status).toBe(403);
  });

  it("yanks a version without deleting it", async () => {
    await post("/packages/acme/y", { version: "2.0.0", url: "u", tag: "t", sha: "s" }, TOKEN);
    const y = await post("/packages/acme/y/2.0.0/yank", { yanked: true }, TOKEN);
    expect(y.status).toBe(200);
    const body = (await (await get("/packages/acme/y")).json()) as any;
    expect(body.versions).toHaveLength(1); // still present
    expect(body.versions[0].yanked).toBe(true);
  });

  it("rejects a malformed publish body", async () => {
    const bad = await post("/packages/acme/z", { version: "not-semver", url: "u", tag: "t", sha: "s" }, TOKEN);
    expect(bad.status).toBe(400);
  });
});

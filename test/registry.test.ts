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

function putText(path: string, body: string, token?: string): Promise<Response> {
  return SELF.fetch("https://registry.test/v1" + path, {
    method: "PUT",
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      "content-type": "application/json",
    },
    body,
  });
}

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

  it("verifies an Ed25519 release signature against the scope's public key", async () => {
    // Generate a keypair (Web Crypto), register the scope with its public key, then publish a
    // release signed over the canonical attestation — the Worker must verify and store it.
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pubRaw = new Uint8Array(
      (await crypto.subtle.exportKey("raw", (kp as CryptoKeyPair).publicKey)) as ArrayBuffer,
    );
    const publicHex = [...pubRaw].map((b) => b.toString(16).padStart(2, "0")).join("");
    // A distinct scope with its own token + key.
    await post("/scopes", { scope: "signed", token: TOKEN + "signed", public_key: publicHex }, ADMIN);

    const msg = new TextEncoder().encode("noeta-attestation-v1\nsigned/pkg\n1.0.0\nabc\n");
    const sigRaw = new Uint8Array(await crypto.subtle.sign("Ed25519", (kp as CryptoKeyPair).privateKey, msg));
    const signature = [...sigRaw].map((b) => b.toString(16).padStart(2, "0")).join("");

    const ok = await post(
      "/packages/signed/pkg",
      { version: "1.0.0", url: "u", tag: "t", sha: "abc", signature },
      TOKEN + "signed",
    );
    expect(ok.status).toBe(201);
    // The signature is served back, and the scope key is fetchable for consumer verification.
    const body = (await (await get("/packages/signed/pkg")).json()) as any;
    expect(body.versions[0].signature).toBe(signature);
    const scope = (await (await get("/scopes/signed")).json()) as any;
    expect(scope.public_key).toBe(publicHex);

    // A signature over a *different* attestation (wrong sha) must be rejected.
    const badMsg = new TextEncoder().encode("noeta-attestation-v1\nsigned/pkg\n2.0.0\nEVIL\n");
    const badSigRaw = new Uint8Array(await crypto.subtle.sign("Ed25519", (kp as CryptoKeyPair).privateKey, badMsg));
    const badSig = [...badSigRaw].map((b) => b.toString(16).padStart(2, "0")).join("");
    const rejected = await post(
      "/packages/signed/pkg",
      { version: "2.0.0", url: "u", tag: "t", sha: "abc", signature: badSig },
      TOKEN + "signed",
    );
    expect(rejected.status).toBe(400);
  });

  it("stores and serves a release's documentation artifact (last-wins)", async () => {
    await post("/packages/acme/docd", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, TOKEN);
    // No docs yet.
    const none = await get("/packages/acme/docd/docs/1.0.0");
    expect(none.status).toBe(404);
    // Upload the artifact; it comes back verbatim as JSON.
    const artifact = JSON.stringify({ schema: 1, package: { name: "acme/docd", version: "1.0.0" }, modules: [] });
    const up = await putText("/packages/acme/docd/docs/1.0.0", artifact, TOKEN);
    expect(up.status).toBe(200);
    const got = await get("/packages/acme/docd/docs/1.0.0");
    expect(got.status).toBe(200);
    expect(got.headers.get("content-type")).toContain("application/json");
    expect(await got.json()).toEqual({ schema: 1, package: { name: "acme/docd", version: "1.0.0" }, modules: [] });
    // Re-upload overwrites (advisory, last-wins — unlike the immutable release).
    const artifact2 = JSON.stringify({ schema: 1, package: { name: "acme/docd", version: "1.0.0" }, modules: [{ file: "lib.noe" }] });
    const up2 = await putText("/packages/acme/docd/docs/1.0.0", artifact2, TOKEN);
    expect(up2.status).toBe(200);
    const got2 = (await (await get("/packages/acme/docd/docs/1.0.0")).json()) as any;
    expect(got2.modules).toHaveLength(1);
  });

  it("refuses docs for an unpublished release, and requires scope ownership", async () => {
    const orphan = await putText("/packages/acme/nope/docs/1.0.0", "{}", TOKEN);
    expect(orphan.status).toBe(404); // the release doesn't exist
    await post("/packages/acme/guarded", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, TOKEN);
    const noauth = await putText("/packages/acme/guarded/docs/1.0.0", "{}");
    expect(noauth.status).toBe(401);
    const wrong = await putText("/packages/acme/guarded/docs/1.0.0", "{}", "wrong");
    expect(wrong.status).toBe(403);
  });

  it("rejects a non-JSON docs body", async () => {
    await post("/packages/acme/badoc", { version: "1.0.0", url: "u", tag: "t", sha: "s" }, TOKEN);
    const bad = await putText("/packages/acme/badoc/docs/1.0.0", "not json at all", TOKEN);
    expect(bad.status).toBe(400);
  });

  it("stores and serves a keyless provenance bundle verbatim (no scope key needed)", async () => {
    // A keyless bundle is stored without server-side verification — its trust root is Sigstore's
    // public infrastructure, and the consumer verifies it offline. So `bundle` round-trips even for
    // a scope with no registered public key.
    const bundle = JSON.stringify({
      mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
      dsseEnvelope: { payload: "e30=", payloadType: "application/vnd.in-toto+json" },
    });
    const ok = await post(
      "/packages/acme/keyless",
      { version: "1.0.0", url: "u", tag: "t", sha: "abc", bundle },
      TOKEN,
    );
    expect(ok.status).toBe(201);
    const body = (await (await get("/packages/acme/keyless")).json()) as any;
    expect(body.versions[0].bundle).toBe(bundle);
    expect(body.versions[0].signature).toBeUndefined();
  });

  it("rejects a release carrying both a signature and a bundle", async () => {
    const both = await post(
      "/packages/acme/both",
      { version: "1.0.0", url: "u", tag: "t", sha: "s", signature: "a".repeat(128), bundle: "{}" },
      TOKEN,
    );
    expect(both.status).toBe(400);
  });

  it("rejects a non-JSON bundle", async () => {
    const bad = await post(
      "/packages/acme/badbundle",
      { version: "1.0.0", url: "u", tag: "t", sha: "s", bundle: "not json" },
      TOKEN,
    );
    expect(bad.status).toBe(400);
  });

  it("rejects a malformed publish body", async () => {
    const bad = await post("/packages/acme/z", { version: "not-semver", url: "u", tag: "t", sha: "s" }, TOKEN);
    expect(bad.status).toBe(400);
  });

  // namespace-protection #2 — built-in scopes (std/noeta/core) are toolchain-owned, never registry
  // packages: unregistrable and unpublishable, so no one can squat `std/extra` or shadow core.
  it("refuses to register or publish a built-in reserved scope", async () => {
    for (const scope of ["std", "noeta", "core"]) {
      // Even the admin cannot register a built-in scope.
      const reg = await post("/scopes", { scope, token: TOKEN + scope }, ADMIN);
      expect(reg.status).toBe(403);
      // And a publish under it is refused (403) regardless of token — the scope can never be owned.
      const pub = await post(
        `/packages/${scope}/extra`,
        { version: "1.0.0", url: "u", tag: "t", sha: "s" },
        TOKEN,
      );
      expect(pub.status).toBe(403);
    }
  });

  it("still lets the admin register a first-party scope (para) — reserved only against open claims", async () => {
    // `para` is a published first-party namespace: the admin bootstrap (the first party) may register
    // it, and its owner then publishes under it normally. Open self-service claims are guarded in #1.
    const reg = await post("/scopes", { scope: "para", token: TOKEN + "para" }, ADMIN);
    expect(reg.status).toBe(201);
    const pub = await post(
      "/packages/para/html",
      { version: "1.0.0", url: "u", tag: "t", sha: "s" },
      TOKEN + "para",
    );
    expect(pub.status).toBe(201);
  });
});

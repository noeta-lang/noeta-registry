import { env, fetchMock, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { WIRE_MANIFEST_SHA256 } from "../src/wire-manifest";

// Golden wire-fixture tests (audit-5 finding 9): `test/fixtures/wire/` is a VERBATIM copy of the
// canonical fixture set in the language repo (`crates/noeta-pm/test_data/wire/` — see the README
// there for the sync rule). These tests prove the Worker speaks exactly those bytes: fixture
// *requests* are fed to the real handlers unmodified and must be accepted, and the handlers'
// *responses* must strict-equal the fixture responses — including the deterministic Ed25519
// signatures (the checkpoint/advisory fixtures are signed with this suite's fixed test keys, and
// RFC 8032 signing is deterministic, so a fresh log of the same records reproduces them exactly).
// Dynamic publish timestamps are the one carve-out, asserted for internal consistency instead.
// The copy is pinned twice. MANIFEST.sha256 hashes every fixture, which catches a local hand-edit.
// The manifest's own hash is `WIRE_MANIFEST_SHA256` in src/wire-manifest.ts — a SOURCE constant,
// deliberately outside the copied directory — which catches the case the manifest alone cannot: the
// manifest travels with the fixtures, so each repo hashing its own copy against its own manifest
// stays green while the two protocols diverge. Copying fixtures across without moving the stamp now
// fails here, by name.

const ADMIN = "test-admin-token"; // matches vitest.config.ts miniflare bindings

function raw(name: string): string {
  const text = env.WIRE_FIXTURES[name];
  if (text === undefined) throw new Error(`no wire fixture \`${name}\` — re-copy test/fixtures/wire`);
  return text;
}
const fixture = (name: string) => JSON.parse(raw(name));

const ACME_TOKEN: string = fixture("scope-register-request.json").token;

function post(path: string, body: string, token?: string): Promise<Response> {
  return SELF.fetch("https://registry.test/v1" + path, {
    method: "POST",
    headers: token ? { authorization: `Bearer ${token}` } : {},
    body,
  });
}
const get = (path: string) => SELF.fetch("https://registry.test/v1" + path);

function putText(path: string, body: string, contentType: string): Promise<Response> {
  return SELF.fetch("https://registry.test/v1" + path, {
    method: "PUT",
    headers: { authorization: `Bearer ${ACME_TOKEN}`, "content-type": contentType },
    body,
  });
}

/** Register the `acme` scope from the fixture request (idempotent per test — storage is isolated),
 *  asserting the canonical response, and return the scope's publish token. */
async function registerAcme(): Promise<string> {
  const r = await post("/scopes", raw("scope-register-request.json"), ADMIN);
  expect(r.status).toBe(201);
  expect(await r.json()).toStrictEqual(fixture("scope-register-response.json"));
  return ACME_TOKEN;
}

/** Publish the release a fixture request describes, verbatim, expecting 201. */
async function publishFixture(name: string): Promise<Response> {
  const r = await post("/packages/acme/imgfx", raw(name), ACME_TOKEN);
  expect(r.status, name).toBe(201);
  return r;
}

// --- the copy pin ---------------------------------------------------------------------------------

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("wire fixtures — the verbatim-copy pin", () => {
  it("the manifest itself hashes to the cross-repo protocol stamp", async () => {
    expect(
      await sha256Hex(raw("MANIFEST.sha256")),
      "`MANIFEST.sha256` no longer hashes to WIRE_MANIFEST_SHA256 (src/wire-manifest.ts).\n\n" +
        "The wire fixtures changed in the language repo and were copied here, but the protocol stamp " +
        "did not move — or they changed here and were never propagated back. Either way the two repos " +
        "are one `cp` away from speaking different bytes with both suites green.\n\n" +
        "Run `scripts/sync-wire-fixtures.sh` in the language repo (it regenerates, re-stamps BOTH " +
        "repos and copies the set), then re-run both suites. Do not paste the new hash into the " +
        "constant by hand — that fixes this test and nothing else.",
    ).toBe(WIRE_MANIFEST_SHA256);
  });

  it("every fixture hashes to its MANIFEST.sha256 entry, and every fixture is listed", async () => {
    const listed = new Set<string>();
    for (const line of raw("MANIFEST.sha256").trimEnd().split("\n")) {
      const [hash, name] = line.split("  ");
      listed.add(name);
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw(name)));
      const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
      expect(hex, `\`${name}\` diverged from the canonical fixtures — re-copy from the language repo (crates/noeta-pm/test_data/wire)`).toBe(hash);
    }
    for (const name of Object.keys(env.WIRE_FIXTURES)) {
      if (name.endsWith(".json")) {
        expect(listed, `\`${name}\` is missing from MANIFEST.sha256`).toContain(name);
      }
    }
  });
});

// --- packages: publish / list / yank ---------------------------------------------------------------

describe("wire fixtures — the package index", () => {
  it("accepts all three canonical publish request shapes and echoes the canonical listing", async () => {
    await registerAcme();
    await publishFixture("publish-request-minimal.json"); // required fields only
    // Yank 1.0.0 with the canonical body; the response is the canonical ack.
    const y = await post("/packages/acme/imgfx/1.0.0/yank", raw("yank-request.json"), ACME_TOKEN);
    expect(y.status).toBe(200);
    expect(await y.json()).toStrictEqual(fixture("yank-response.json"));
    await publishFixture("publish-request-signed.json"); // deps + license + verified Ed25519 signature
    await publishFixture("publish-request-keyless.json"); // Sigstore bundle, stored verbatim

    const body = (await (await get("/packages/acme/imgfx")).json()) as any;
    const fix = fixture("versions-response.json");
    expect(body.name).toBe(fix.name);
    expect(body.versions).toHaveLength(fix.versions.length);
    for (let i = 0; i < fix.versions.length; i++) {
      // The publish timestamps are the only dynamic fields: assert the served pair is internally
      // consistent (unix == Date.parse(iso)), then compare everything else strictly — presence and
      // absence included (yanked flag, deps always [], signature/bundle/license omitted-not-null).
      const actual = { ...body.versions[i] };
      expect(typeof actual.published_at).toBe("string");
      expect(actual.published_at_unix).toBe(Date.parse(actual.published_at));
      delete actual.published_at;
      delete actual.published_at_unix;
      const expected = { ...fix.versions[i] };
      // The fixture's example timestamps must be internally consistent too.
      expect(expected.published_at_unix).toBe(Date.parse(expected.published_at));
      delete expected.published_at;
      delete expected.published_at_unix;
      expect(actual, `versions[${i}]`).toStrictEqual(expected);
    }
  });

  it("publishing the signed release into a fresh log returns the canonical publish response", async () => {
    await registerAcme();
    const r = await publishFixture("publish-request-signed.json");
    // log_index 0: this test's isolated storage starts with an empty transparency log.
    expect(await r.json()).toStrictEqual(fixture("publish-response.json"));
  });

  it("an unknown route returns the canonical error envelope", async () => {
    const r = await get("/nope");
    expect(r.status).toBe(404);
    expect(await r.json()).toStrictEqual(fixture("error-response.json"));
  });
});

// --- scopes: key / policy ---------------------------------------------------------------------------

describe("wire fixtures — scopes", () => {
  it("serves the canonical scope-key response", async () => {
    await registerAcme();
    const r = await get("/scopes/acme");
    expect(r.status).toBe(200);
    expect(await r.json()).toStrictEqual(fixture("scope-key-response.json"));
  });

  it("accepts the canonical policy request and returns the canonical response", async () => {
    await registerAcme();
    const r = await post("/scopes/acme/policy", raw("policy-request.json"), ACME_TOKEN);
    expect(r.status).toBe(200);
    expect(await r.json()).toStrictEqual(fixture("policy-response.json"));
  });
});

// --- docs / readme -----------------------------------------------------------------------------------

describe("wire fixtures — release artifacts", () => {
  it("storing docs and README returns the canonical acks", async () => {
    await registerAcme();
    await publishFixture("publish-request-signed.json");
    const d = await putText("/packages/acme/imgfx/docs/1.2.0", '{"schema":1}', "application/json");
    expect(d.status).toBe(200);
    expect(await d.json()).toStrictEqual(fixture("docs-put-response.json"));
    const m = await putText("/packages/acme/imgfx/readme/1.2.0", "# imgfx\n", "text/markdown");
    expect(m.status).toBe(200);
    expect(await m.json()).toStrictEqual(fixture("readme-put-response.json"));
  });
});

// --- transparency log ---------------------------------------------------------------------------------

describe("wire fixtures — transparency log", () => {
  it("a fresh log holding exactly the signed release reproduces the canonical key/checkpoint/proof", async () => {
    await registerAcme();
    await publishFixture("publish-request-signed.json");
    // Deterministic end to end: same record → same leaf → same root → same (RFC 8032) signature.
    const key = await get("/log/key");
    expect(key.status).toBe(200);
    expect(await key.json()).toStrictEqual(fixture("log-key-response.json"));
    const cp = await get("/log/checkpoint");
    expect(cp.status).toBe(200);
    expect(await cp.json()).toStrictEqual(fixture("log-checkpoint-response.json"));
    const proof = await get("/log/proof/acme/imgfx/1.2.0");
    expect(proof.status).toBe(200);
    expect(await proof.json()).toStrictEqual(fixture("log-proof-response.json"));
  });

  it("a two-release log reproduces the canonical consistency proof (1 → 2)", async () => {
    await registerAcme();
    await publishFixture("publish-request-minimal.json");
    await publishFixture("publish-request-signed.json");
    const r = await get("/log/consistency?from=1&to=2");
    expect(r.status).toBe(200);
    expect(await r.json()).toStrictEqual(fixture("log-consistency-response.json"));
  });
});

// --- scope claiming ------------------------------------------------------------------------------------

describe("wire fixtures — scope claiming", () => {
  // The OIDC fixture's JWT is a shape placeholder (a real one is minted per-run against the
  // hermetic JWKS below, since the signing key is ephemeral); the github/domain fixtures are fed
  // verbatim. Harness matches claim.test.ts.
  let privateKey: CryptoKey;
  const KID = "test-key-1";

  function b64url(bytes: Uint8Array): string {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  const b64urlStr = (s: string) => b64url(new TextEncoder().encode(s));

  async function signJwt(claims: Record<string, unknown>): Promise<string> {
    const header = { alg: "RS256", kid: KID, typ: "JWT" };
    const input = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(claims))}`;
    const sig = new Uint8Array(
      await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, new TextEncoder().encode(input)),
    );
    return `${input}.${b64url(sig)}`;
  }

  beforeAll(async () => {
    const kp = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    privateKey = kp.privateKey;
    const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey & Record<string, unknown>;
    jwk.kid = KID;
    jwk.alg = "RS256";
    jwk.use = "sig";
    fetchMock.activate();
    fetchMock.disableNetConnect();
    fetchMock
      .get("https://oidc.test")
      .intercept({ path: "/jwks" })
      .reply(200, JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } })
      .persist();
  });

  it("claims with the canonical OIDC request shape and returns the canonical response", async () => {
    const fix = fixture("claim-request-oidc.json");
    expect(Object.keys(fix).sort()).toStrictEqual(["oidc", "scope", "token"]);
    const now = Math.floor(Date.now() / 1000);
    const oidc = await signJwt({
      iss: "https://oidc.test",
      aud: "noeta-registry",
      iat: now,
      exp: now + 300,
      repository_owner: fix.scope,
      repository_owner_id: "1001",
    });
    const r = await post("/scopes/claim", JSON.stringify({ ...fix, oidc }));
    expect(r.status).toBe(201);
    expect(await r.json()).toStrictEqual(fixture("claim-response.json"));
  });

  it("claims with the canonical github_token request, verbatim", async () => {
    fetchMock
      .get("https://gh-api.test")
      .intercept({ path: "/user" })
      .reply(200, JSON.stringify({ login: "widgetco", id: 1001 }), {
        headers: { "content-type": "application/json" },
      });
    const r = await post("/scopes/claim", raw("claim-request-github-token.json"));
    expect(r.status).toBe(201);
    expect(await r.json()).toStrictEqual(fixture("claim-response.json"));
  });

  it("claims with the canonical domain request, verbatim", async () => {
    fetchMock
      .get("https://widgetco.dev")
      .intercept({ path: "/.well-known/noeta-registry.txt" })
      .reply(200, "noeta-scope=widgetco\n", { headers: { "content-type": "text/plain" } });
    const r = await post("/scopes/claim", raw("claim-request-domain.json"));
    expect(r.status).toBe(201);
    expect(await r.json()).toStrictEqual(fixture("claim-response-domain.json"));
  });
});

// --- advisory feed ---------------------------------------------------------------------------------------

describe("wire fixtures — advisory feed", () => {
  it("publishing the canonical advisory into a fresh feed reproduces feed/checkpoint/key exactly", async () => {
    const pub = await post("/advisories", raw("advisory-request.json"), ADMIN);
    expect(pub.status).toBe(201);
    expect(await pub.json()).toStrictEqual(fixture("advisory-response.json"));

    // Deterministic Ed25519 again: the per-advisory signature, feed digest, and head signature in
    // the fixtures were produced with this suite's fixed advisory test key.
    const feed = await get("/advisories");
    expect(feed.status).toBe(200);
    expect(await feed.json()).toStrictEqual(fixture("advisory-feed-response.json"));
    const cp = await get("/advisories/checkpoint");
    expect(cp.status).toBe(200);
    expect(await cp.json()).toStrictEqual(fixture("advisory-checkpoint-response.json"));
    const key = await get("/advisories/key");
    expect(key.status).toBe(200);
    expect(await key.json()).toStrictEqual(fixture("advisory-key-response.json"));

    // The advisory's log inclusion proof has the same shape as a release proof.
    const proof = (await (await get("/log/advisory/NOETA-2026-0001")).json()) as any;
    expect(Object.keys(proof).sort()).toStrictEqual(
      Object.keys(fixture("log-proof-response.json")).sort(),
    );
    expect(proof.index).toBe(0);
  });
});

import { fetchMock, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

// Self-service scope claiming (namespace-protection #1). We mint GitHub-style OIDC tokens with a
// throwaway RS256 keypair and serve the matching JWKS via fetchMock, so the whole flow — signature
// verification, issuer/audience/expiry checks, and the anti-squat authorization rule — is exercised
// hermetically against the real Worker (issuer/audience/JWKS URL come from vitest.config.ts).

const TOKEN = "claim-publish-token-abc123"; // a publish token the claimant binds to its scope

let privateKey: CryptoKey;
const KID = "test-key-1";

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const b64urlStr = (s: string) => b64url(new TextEncoder().encode(s));

async function signJwt(key: CryptoKey, claims: Record<string, unknown>): Promise<string> {
  const header = { alg: "RS256", kid: KID, typ: "JWT" };
  const input = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(claims))}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, new TextEncoder().encode(input)),
  );
  return `${input}.${b64url(sig)}`;
}

/** GitHub-style OIDC claims for `owner`/`ownerId`, overridable for the negative cases. */
function claims(owner: string, ownerId: string, over: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: "https://oidc.test",
    aud: "noeta-registry",
    iat: now,
    exp: now + 300,
    repository_owner: owner,
    repository_owner_id: ownerId,
    ...over,
  };
}

const claim = (scope: string, oidc: string, token = TOKEN) =>
  SELF.fetch("https://registry.test/v1/scopes/claim", {
    method: "POST",
    body: JSON.stringify({ scope, token, oidc }),
  });

// The laptop (device-flow) path: a GitHub OAuth access token instead of an OIDC JWT.
const claimGithub = (scope: string, githubToken: string, token = TOKEN) =>
  SELF.fetch("https://registry.test/v1/scopes/claim", {
    method: "POST",
    body: JSON.stringify({ scope, token, github_token: githubToken }),
  });

// One-shot mocks of the GitHub REST calls verifyGithubOwnership makes (GITHUB_API_URL = gh-api.test).
function mockGithubUser(login: string, id: number) {
  fetchMock
    .get("https://gh-api.test")
    .intercept({ path: "/user" })
    .reply(200, JSON.stringify({ login, id }), { headers: { "content-type": "application/json" } });
}
function mockGithubMembership(org: string, body: unknown, status = 200) {
  fetchMock
    .get("https://gh-api.test")
    .intercept({ path: `/user/memberships/orgs/${org}` })
    .reply(status, JSON.stringify(body), { headers: { "content-type": "application/json" } });
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

  // Serve the JWKS the Worker fetches (OIDC_JWKS_URL = https://oidc.test/jwks), persistently.
  fetchMock.activate();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://oidc.test")
    .intercept({ path: "/jwks" })
    .reply(200, JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } })
    .persist();
});

describe("self-service scope claiming", () => {
  it("claims the scope matching the GitHub owner, then publishes with the bound token", async () => {
    const oidc = await signJwt(privateKey, claims("widgetco", "1001"));
    const c = await claim("widgetco", oidc);
    expect(c.status).toBe(201);
    expect(((await c.json()) as any).owner).toBe("widgetco");

    // The bound token now owns the scope end-to-end.
    const pub = await SELF.fetch("https://registry.test/v1/packages/widgetco/gears", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ version: "1.0.0", url: "u", tag: "t", sha: "s" }),
    });
    expect(pub.status).toBe(201);
  });

  it("refuses to claim a scope that isn't the claimant's own org/user", async () => {
    // The token proves ownership of `attacker`, but tries to grab `stripe` — the anti-squat rule.
    const oidc = await signJwt(privateKey, claims("attacker", "666"));
    const c = await claim("stripe", oidc);
    expect(c.status).toBe(403);
    expect(((await c.json()) as any).error).toContain("cannot claim scope");
  });

  it("never lets a built-in namespace be claimed", async () => {
    for (const scope of ["std", "noeta", "core"]) {
      const oidc = await signJwt(privateKey, claims(scope, "7"));
      expect((await claim(scope, oidc)).status).toBe(403);
    }
  });

  it("lets a first-party scope be claimed only by its designated org", async () => {
    // `para` is reserved to `noeta-dev`: another org proving its own identity cannot claim it, even
    // though its OIDC token verifies — the anti-squat rule uses the designated owner, not the name.
    const intruder = await signJwt(privateKey, claims("randomcorp", "8"));
    const denied = await claim("para", intruder);
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as any).error).toContain("noeta-dev");

    // The designated org claims it via the ordinary OIDC flow — no admin token.
    const owner = await signJwt(privateKey, claims("noeta-dev", "5050"));
    const ok = await claim("para", owner);
    expect(ok.status).toBe(201);
    expect(((await ok.json()) as any).owner).toBe("noeta-dev");

    // And the bound token then publishes under `para`.
    const pub = await SELF.fetch("https://registry.test/v1/packages/para/html", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ version: "1.0.0", url: "u", tag: "t", sha: "s" }),
    });
    expect(pub.status).toBe(201);
  });

  it("rejects an expired or wrong-issuer token (before any JWKS work)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = await signJwt(privateKey, claims("acmeexp", "9", { exp: now - 10 }));
    expect((await claim("acmeexp", expired)).status).toBe(401);
    const wrongIss = await signJwt(privateKey, claims("acmeiss", "9", { iss: "https://evil.test" }));
    expect((await claim("acmeiss", wrongIss)).status).toBe(401);
    const wrongAud = await signJwt(privateKey, claims("acmeaud", "9", { aud: "someone-else" }));
    expect((await claim("acmeaud", wrongAud)).status).toBe(401);
  });

  it("rejects a token signed by a key not in the JWKS", async () => {
    const other = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const forged = await signJwt(other.privateKey, claims("forgeco", "10"));
    const c = await claim("forgeco", forged);
    expect(c.status).toBe(401);
    expect(((await c.json()) as any).error).toContain("signature");
  });

  it("lets the same identity rotate its token, but not a different owner or the admin", async () => {
    const oidc = await signJwt(privateKey, claims("rotateco", "2002"));
    expect((await claim("rotateco", oidc)).status).toBe(201);
    // Same owner_id re-claims with a new token → 200 (rotation).
    const again = await claim("rotateco", await signJwt(privateKey, claims("rotateco", "2002")), TOKEN + "new");
    expect(again.status).toBe(200);
    // A different identity that somehow also names itself `rotateco` cannot take it over.
    const impostor = await claim("rotateco", await signJwt(privateKey, claims("rotateco", "9999")));
    expect(impostor.status).toBe(409);
  });

  it("refuses to claim a scope already owned by the admin bootstrap", async () => {
    // Admin provisions `firstparty`; a self-service claim for the same name (even with a valid OIDC
    // proof) is refused — ownership never transfers implicitly from admin to a claimant.
    const reg = await SELF.fetch("https://registry.test/v1/scopes", {
      method: "POST",
      headers: { authorization: "Bearer test-admin-token" },
      body: JSON.stringify({ scope: "firstparty", token: "admin-owned-token-xyz" }),
    });
    expect(reg.status).toBe(201);
    const c = await claim("firstparty", await signJwt(privateKey, claims("firstparty", "3003")));
    expect(c.status).toBe(409);
  });

  // --- Laptop (GitHub OAuth device-flow) claiming ------------------------------------------------

  it("claims a personal scope with a GitHub token whose login matches", async () => {
    mockGithubUser("lapuser", 7001); // token holder == the scope
    const c = await claimGithub("lapuser", "gho_devicetoken");
    expect(c.status).toBe(201);
    expect(((await c.json()) as any).owner).toBe("lapuser");
  });

  it("claims an org scope when the token holder is an active admin", async () => {
    mockGithubUser("some-admin", 42); // login != scope → org membership is checked
    mockGithubMembership("lapcorp", {
      role: "admin",
      state: "active",
      organization: { login: "lapcorp", id: 8002 },
    });
    const c = await claimGithub("lapcorp", "gho_devicetoken");
    expect(c.status).toBe(201);
    expect(((await c.json()) as any).owner).toBe("lapcorp");
  });

  it("refuses an org scope for a non-admin (or non-member)", async () => {
    mockGithubUser("some-member", 43);
    mockGithubMembership("membercorp", {
      role: "member",
      state: "active",
      organization: { login: "membercorp", id: 8003 },
    });
    expect((await claimGithub("membercorp", "gho_devicetoken")).status).toBe(403);

    mockGithubUser("stranger", 44);
    mockGithubMembership("notmine", {}, 404); // not a member at all
    expect((await claimGithub("notmine", "gho_devicetoken")).status).toBe(403);
  });

  it("treats the OIDC and OAuth paths as one identity (interchangeable, same GitHub id)", async () => {
    // Claim via CI OIDC, binding owner_id 5005…
    const oidc = await signJwt(privateKey, claims("crossorg", "5005"));
    expect((await claim("crossorg", oidc)).status).toBe(201);
    // …then re-claim from a laptop: an admin of `crossorg` whose org id is the SAME 5005 → rotation.
    mockGithubUser("cross-admin", 1);
    mockGithubMembership("crossorg", {
      role: "admin",
      state: "active",
      organization: { login: "crossorg", id: 5005 },
    });
    expect((await claimGithub("crossorg", "gho_devicetoken", TOKEN + "rot")).status).toBe(200);
    // A different GitHub org id (a name collision on another account) cannot take it over.
    mockGithubUser("other-admin", 2);
    mockGithubMembership("crossorg", {
      role: "admin",
      state: "active",
      organization: { login: "crossorg", id: 9999 },
    });
    expect((await claimGithub("crossorg", "gho_devicetoken")).status).toBe(409);
  });

  it("requires exactly one proof", async () => {
    const neither = await SELF.fetch("https://registry.test/v1/scopes/claim", {
      method: "POST",
      body: JSON.stringify({ scope: "noproof", token: TOKEN }),
    });
    expect(neither.status).toBe(400);
    const both = await SELF.fetch("https://registry.test/v1/scopes/claim", {
      method: "POST",
      body: JSON.stringify({ scope: "bothproof", token: TOKEN, oidc: "x", github_token: "y" }),
    });
    expect(both.status).toBe(400);
    // Three proofs at once is also rejected.
    const three = await SELF.fetch("https://registry.test/v1/scopes/claim", {
      method: "POST",
      body: JSON.stringify({ scope: "tri", token: TOKEN, oidc: "x", github_token: "y", domain: "tri.dev" }),
    });
    expect(three.status).toBe(400);
  });

  // --- domain proof (namespace-protection #1, follow-on) -----------------------------------------

  const claimDomain = (scope: string, domain: string, token = TOKEN) =>
    SELF.fetch("https://registry.test/v1/scopes/claim", {
      method: "POST",
      body: JSON.stringify({ scope, token, domain }),
    });

  // Serve the well-known control file `verifyDomainOwnership` fetches (over https, disableNetConnect).
  function mockWellKnown(domain: string, body: string | null, status = 200) {
    const i = fetchMock.get(`https://${domain}`).intercept({ path: "/.well-known/noeta-registry.txt" });
    if (body === null) i.reply(status, "not found");
    else i.reply(status, body, { headers: { "content-type": "text/plain" } });
  }

  it("claims a scope by proving control of the matching domain, then publishes", async () => {
    mockWellKnown("acme.dev", "noeta-scope=acme\n");
    const c = await claimDomain("acme", "acme.dev");
    expect(c.status).toBe(201);
    expect(((await c.json()) as any).owner).toBe("acme.dev");
    // The bound token owns the scope end-to-end.
    const pub = await SELF.fetch("https://registry.test/v1/packages/acme/widgets", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ version: "1.0.0", url: "u", tag: "t", sha: "s" }),
    });
    expect(pub.status).toBe(201);
  });

  it("refuses a domain whose first label isn't the scope (anti-squat)", async () => {
    // Controlling `evil.dev` cannot claim `stripe` — the label must be the scope.
    const c = await claimDomain("stripe", "evil.dev");
    expect(c.status).toBe(403);
    expect(((await c.json()) as any).error).toContain("first label");
  });

  it("refuses when the well-known file is missing or doesn't bind the scope", async () => {
    mockWellKnown("missing.dev", null, 404);
    expect((await claimDomain("missing", "missing.dev")).status).toBe(403);
    mockWellKnown("nobind.dev", "hello world\n");
    const c = await claimDomain("nobind", "nobind.dev");
    expect(c.status).toBe(403);
    expect(((await c.json()) as any).error).toContain("noeta-scope=nobind");
  });

  it("re-claims from the same domain but refuses a different owner kind", async () => {
    mockWellKnown("rotate.dev", "noeta-scope=rotate\n");
    expect((await claimDomain("rotate", "rotate.dev")).status).toBe(201);
    // Same domain, new token → re-claim (200).
    mockWellKnown("rotate.dev", "noeta-scope=rotate\n");
    expect((await claimDomain("rotate", "rotate.dev", TOKEN + "rot")).status).toBe(200);
    // A GitHub principal cannot take over a domain-owned scope.
    const oidc = await signJwt(privateKey, claims("rotate", "12345"));
    expect((await claim("rotate", oidc)).status).toBe(409);
  });

  it("refuses domain proof for a reserved first-party scope", async () => {
    // `para` is claimable only by its designated GitHub org, never by domain.
    mockWellKnown("para.dev", "noeta-scope=para\n");
    const c = await claimDomain("para", "para.dev");
    expect(c.status).toBe(403);
    expect(((await c.json()) as any).error).toContain("GitHub org");
  });
});

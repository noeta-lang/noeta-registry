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
});

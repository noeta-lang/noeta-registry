// OIDC token verification (namespace-protection arc #1) — verify a GitHub Actions OIDC JWT so a
// scope can be claimed self-service by whoever proves they control the matching GitHub org/user.
//
// GitHub signs workflow OIDC tokens (RS256) with keys published at its JWKS endpoint. We verify the
// signature against that key set, check the issuer / audience / expiry, and hand back the claims. The
// caller (the claim endpoint) enforces the *authorization* rule — scope must equal the token's
// `repository_owner` — so this module stays a pure authentication seam.
//
// Deliberately dependency-free (Web Crypto only), matching the rest of the Worker. Config comes from
// the environment so a test can point the issuer/JWKS at a hermetic double.

/** The subset of GitHub OIDC claims we consume. */
export interface OidcClaims {
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  /** The org or user that owns the workflow's repository — the identity that may claim its scope. */
  repository_owner: string;
  /** The stable numeric id of that owner — what we pin, so a rename/transfer can't take a scope over. */
  repository_owner_id: string;
  [k: string]: unknown;
}

export interface OidcConfig {
  issuer: string;
  audience: string;
  jwksUrl: string;
}

/** Read the OIDC config from the environment, defaulting to GitHub Actions' public issuer. `audience`
 *  has no safe default (it is deployment-specific), so its absence disables self-service claiming. */
export function oidcConfig(env: {
  OIDC_ISSUER?: string;
  OIDC_AUDIENCE?: string;
  OIDC_JWKS_URL?: string;
}): OidcConfig | null {
  const issuer = env.OIDC_ISSUER ?? "https://token.actions.githubusercontent.com";
  const jwksUrl = env.OIDC_JWKS_URL ?? issuer.replace(/\/$/, "") + "/.well-known/jwks";
  const audience = env.OIDC_AUDIENCE;
  if (!audience) return null;
  return { issuer, audience, jwksUrl };
}

/** A JSON Web Key (the fields we use for RS256 / ES256 verification). */
interface Jwk {
  kid?: string;
  kty: string;
  alg?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
}

/** Verify a GitHub-style OIDC JWT and return its claims, or throw with a human-readable reason. The
 *  returned claims are authenticated (signature + issuer + audience + expiry); authorization is the
 *  caller's job. */
export async function verifyOidc(jwt: string, cfg: OidcConfig): Promise<OidcClaims> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("malformed OIDC token (not a three-part JWT)");
  const [headerB64, payloadB64, sigB64] = parts;

  const header = jsonFromB64url(headerB64, "header");
  const claims = jsonFromB64url(payloadB64, "payload") as OidcClaims;
  const alg = String(header.alg ?? "");
  if (alg !== "RS256" && alg !== "ES256") {
    throw new Error(`unsupported OIDC signing algorithm \`${alg}\` (expected RS256 or ES256)`);
  }

  // Claim checks first (cheap, and a clear error) — issuer, audience, expiry window.
  if (claims.iss !== cfg.issuer) {
    throw new Error(`OIDC issuer \`${claims.iss}\` is not the trusted issuer \`${cfg.issuer}\``);
  }
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(cfg.audience)) {
    throw new Error(`OIDC audience does not include \`${cfg.audience}\``);
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp <= now) throw new Error("OIDC token is expired");
  if (typeof claims.nbf === "number" && claims.nbf > now + 60) {
    throw new Error("OIDC token is not yet valid");
  }
  if (typeof claims.repository_owner !== "string" || typeof claims.repository_owner_id !== "string") {
    throw new Error("OIDC token is missing repository_owner / repository_owner_id claims");
  }

  // Fetch the issuer's JWKS and select the key that signed this token (by `kid`).
  const jwk = await fetchSigningKey(cfg.jwksUrl, header.kid ? String(header.kid) : undefined);
  const key = await importVerifyKey(jwk, alg);
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = b64urlToBytes(sigB64);
  const algParams =
    alg === "RS256"
      ? { name: "RSASSA-PKCS1-v1_5" }
      : { name: "ECDSA", hash: "SHA-256" };
  const ok = await crypto.subtle.verify(algParams, key, signature, data);
  if (!ok) throw new Error("OIDC token signature does not verify against the issuer's JWKS");
  return claims;
}

/** Fetch the JWKS and return the key matching `kid` (or the sole key when the token omits `kid`). */
async function fetchSigningKey(jwksUrl: string, kid: string | undefined): Promise<Jwk> {
  let res: Response;
  try {
    res = await fetch(jwksUrl);
  } catch (err) {
    throw new Error(`cannot fetch the OIDC JWKS (${String(err)})`);
  }
  if (!res.ok) throw new Error(`OIDC JWKS fetch failed (HTTP ${res.status})`);
  const body = (await res.json()) as { keys?: Jwk[] };
  const keys = body.keys ?? [];
  if (keys.length === 0) throw new Error("OIDC JWKS contains no keys");
  const jwk = kid ? keys.find((k) => k.kid === kid) : keys[0];
  if (!jwk) throw new Error(`OIDC JWKS has no key for kid \`${kid}\``);
  return jwk;
}

/** Import a JWK as a Web Crypto verification key for the token's algorithm. */
function importVerifyKey(jwk: Jwk, alg: string): Promise<CryptoKey> {
  const algorithm =
    alg === "RS256"
      ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
      : { name: "ECDSA", namedCurve: "P-256" };
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, algorithm, false, ["verify"]);
}

function jsonFromB64url(part: string, what: string): Record<string, unknown> {
  try {
    return JSON.parse(new TextDecoder().decode(b64urlToBytes(part)));
  } catch {
    throw new Error(`malformed OIDC token (${what} is not valid base64url JSON)`);
  }
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

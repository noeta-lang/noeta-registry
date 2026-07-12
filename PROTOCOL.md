# Noeta registry — wire protocol (v1)

The registry is an **index**, not a code store: it maps a package identity + version to the **git
coordinates** (URL + tag + pinned commit SHA) where that release's source lives. It never hosts or
serves package source — a consumer fetches from git and verifies the SHA. This is the contract the
Rust client (`noeta-pm`'s HTTP `Index`) and this Cloudflare Worker both implement; the client is the
source of truth for the shape, the server conforms.

All paths are under `/v1`. Bodies and responses are JSON (`application/json`).

## `GET /v1/packages/{company}/{package}`

List every published version of a package. An unknown package returns `200` with an empty `versions`
array (not a 404) so the client has a single success path.

```
200 OK
{
  "name": "acme/imgfx",
  "versions": [
    { "version": "1.2.0", "url": "https://github.com/acme/imgfx", "tag": "v1.2.0",
      "sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4", "yanked": false,
      "deps": [ { "package": "acme/bytes", "req": "^1.0" } ] }
  ]
}
```

`deps` is each version's **registry dependencies** (`{ package: "company/package", req }`). The index
carries them so a resolver can backtrack over version ranges by reading a candidate's requirements
here, instead of cloning every candidate's source — the crates.io-index model. A signed release also
carries its provenance — a `signature` (key) or `bundle` (keyless) field — for the consumer to verify.

A `yanked` version is still returned (so an existing lockfile can still resolve it — Go's model) but
a resolver must not newly *select* it.

## `POST /v1/packages/{company}/{package}`

Publish a release. Requires `Authorization: Bearer <token>`; the token must own the **scope**
(`{company}`) — you can only publish under a company you control.

```
Body: { "version": "1.2.0", "url": "https://…/acme/imgfx", "tag": "v1.2.0", "sha": "e3b0c4…",
        "deps": [ { "package": "acme/bytes", "req": "^1.0" } ],   // deps optional, default []
        "signature": "<128-hex>" | "bundle": "<json>" }           // provenance — at most one, optional

201 Created                         published
200 OK                              idempotent — identical coordinates already published
409 Conflict                        this version exists with different coordinates (immutable)
401 Unauthorized / 403 Forbidden    missing/invalid token, or token does not own {company}
400 Bad Request                     malformed body / identity / both provenance roots / bad signature
```

**Provenance (optional, at most one root).** A release may attest its `version → commit` under one
of two trust roots — never both (a second root is a downgrade surface):
- `signature` — a 128-hex Ed25519 signature over the canonical attestation. **Verified server-side**
  against the scope's registered public key (`GET /v1/scopes/{scope}`); a signature that doesn't
  verify is a `400`, so the index never serves a non-attesting one.
- `bundle` — a keyless Sigstore bundle (DSSE envelope + Fulcio certificate + Rekor inclusion proof),
  as a JSON string. **Stored verbatim, not verified server-side**: its trust root is Sigstore's public
  infrastructure, not a per-scope key, and a keyless consumer verifies the bundle *offline* against
  its own pinned policy — so the registry is never the trust boundary for it. Validated for shape
  (non-empty JSON) only.

Both provenance fields are echoed back on `GET` (`signature` / `bundle`, absent when unset).

A published `(name, version)` is **immutable**: it can be *yanked* but never overwritten with
different coordinates. The `sha` is recorded at publish time so the index — not just a consumer's
lockfile — is authoritative on "this version = this commit".

## `POST /v1/packages/{company}/{package}/{version}/yank` — body `{ "yanked": true|false }`

Mark (or un-mark) a version yanked. Same scope-ownership auth. Yank never deletes — existing pins
keep resolving; new selections skip it.

## `GET /v1/scopes/{scope}` — the scope's public key

Serve a scope's registered Ed25519 **public key** (hex), for a consumer to verify that scope's
release signatures independently of trusting the registry. `404` if the scope registered no key.

```
200 OK   { "scope": "acme", "public_key": "<64-char hex>" }
```

## `PUT /v1/packages/{company}/{package}/docs/{version}`

Store a release's **documentation artifact** — the `docs.json` the toolchain generates
(`noeta doc --out`). Requires `Authorization: Bearer <token>` owning `{company}` (same auth as
publish). The body is the **verbatim `docs.json`** (`content-type: application/json`); it must be
valid JSON and ≤ 1 MiB. The `(company/package, version)` must already be **published** — docs
belong to a release.

```
200 OK               docs stored (last-wins — a re-upload overwrites)
404 Not Found        that (name, version) is not published
401 / 403            missing/invalid token, or token does not own {company}
400 Bad Request      body is not valid JSON
413 Payload Too Large  artifact exceeds 1 MiB
```

Docs are **advisory metadata, not provenance**: unsigned and mutable (unlike the immutable release
record), so a regenerated artifact — or a registry that regenerates docs from source itself, the
docs.rs model — can refresh them without touching the release.

## `GET /v1/packages/{company}/{package}/docs/{version}`

Serve a release's stored documentation artifact **verbatim** (the `docs.json`, not a wrapper), or
`404` if none is stored.

```
200 OK   <the docs.json artifact, application/json>
404 Not Found   no docs stored for this (name, version)
```

## `POST /v1/scopes` *(admin, bootstrap)*

Register a scope's publish token. Requires `Authorization: Bearer <ADMIN_TOKEN>` (a Worker secret).
Body `{ "scope": "acme", "token": "<publish-token>" }`. The token is stored **hashed** (SHA-256);
publishing presents the raw token and the Worker compares hashes. This is the minimal bootstrap; a
real deployment grows OAuth/device-flow onboarding.

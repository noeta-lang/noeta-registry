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
      "sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4", "yanked": false }
  ]
}
```

A `yanked` version is still returned (so an existing lockfile can still resolve it — Go's model) but
a resolver must not newly *select* it.

## `POST /v1/packages/{company}/{package}`

Publish a release. Requires `Authorization: Bearer <token>`; the token must own the **scope**
(`{company}`) — you can only publish under a company you control.

```
Body: { "version": "1.2.0", "url": "https://…/acme/imgfx", "tag": "v1.2.0", "sha": "e3b0c4…" }

201 Created                         published
200 OK                              idempotent — identical coordinates already published
409 Conflict                        this version exists with different coordinates (immutable)
401 Unauthorized / 403 Forbidden    missing/invalid token, or token does not own {company}
400 Bad Request                     malformed body / identity
```

A published `(name, version)` is **immutable**: it can be *yanked* but never overwritten with
different coordinates. The `sha` is recorded at publish time so the index — not just a consumer's
lockfile — is authoritative on "this version = this commit".

## `POST /v1/packages/{company}/{package}/{version}/yank` — body `{ "yanked": true|false }`

Mark (or un-mark) a version yanked. Same scope-ownership auth. Yank never deletes — existing pins
keep resolving; new selections skip it.

## `POST /v1/scopes` *(admin, bootstrap)*

Register a scope's publish token. Requires `Authorization: Bearer <ADMIN_TOKEN>` (a Worker secret).
Body `{ "scope": "acme", "token": "<publish-token>" }`. The token is stored **hashed** (SHA-256);
publishing presents the raw token and the Worker compares hashes. This is the minimal bootstrap; a
real deployment grows OAuth/device-flow onboarding.

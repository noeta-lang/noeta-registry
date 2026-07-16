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
403 Forbidden                       {company} is a reserved built-in namespace (std/noeta/core)
403 Forbidden                       {company} requires provenance but this release carries none
400 Bad Request                     malformed body / identity / both provenance roots / bad signature
```

**Reserved namespaces.** `std`, `noeta`, and `core` are **built-in** scopes: they are provided by
the Noeta compiler itself and never live in a registry, so they can never be *registered* or
*published* — a `std/*` release could only be an attempt to shadow core code. The client mirrors this
(`noeta-pm`'s `reserved` module): it refuses to fetch a built-in scope from *any* registry, so a
third-party or compromised index can't smuggle a forged `std/*` past a consumer. First-party
*published* namespaces (e.g. `para`) are resolvable like any package but reserved against open
self-service claims.

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

## `PUT /v1/packages/{company}/{package}/readme/{version}`

Store a release's **README** — the raw markdown of the package's `README.md`, uploaded by
`noeta publish` and rendered on the package's browser page (the npm/crates.io model; the registry
never fetches source, so a README is only ever what the publisher uploads). Requires
`Authorization: Bearer <token>` owning `{company}` (same auth as publish). The body is the
**verbatim markdown** (`content-type: text/markdown`), non-empty and ≤ 256 KiB. The
`(company/package, version)` must already be **published** — a README belongs to a release.

```
200 OK               readme stored (last-wins — a re-upload overwrites)
404 Not Found        that (name, version) is not published
401 / 403            missing/invalid token, or token does not own {company}
400 Bad Request      empty body
413 Payload Too Large  README exceeds 256 KiB
```

Like docs, a README is **advisory metadata, not provenance**: unsigned and mutable, never part of
the immutable release record; the web renderer treats it as untrusted input (escape-first, under a
strict CSP).

## `GET /v1/packages/{company}/{package}/readme/{version}`

Serve a release's stored README **verbatim**, or `404` if none is stored.

```
200 OK   <the README markdown, text/markdown>
404 Not Found   no readme stored for this (name, version)
```

## `POST /v1/scopes/claim` — self-service scope claim (GitHub-proven)

Claim a scope by **proving you control the GitHub org/user of the same name**. Two proofs, one from
each environment — provide **exactly one**:
- `oidc` — a GitHub Actions **OIDC token** (from CI). The scalable, admin-free path.
- `github_token` — a GitHub OAuth **access token** (from the laptop device flow), for claiming off-CI.

Either way the proof-of-control is the anti-squatting mechanism — you cannot claim `stripe` unless you
*are* `stripe` (or an admin of the `stripe` org).

```
Body: { "scope": "acme", "token": "<publish-token>",
        "oidc": "<GitHub OIDC JWT>" | "github_token": "<GitHub OAuth token>" }   // exactly one

201 Created   { "status": "scope claimed",    "scope": "acme", "owner": "acme" }
200 OK        { "status": "scope re-claimed", "scope": "acme", "owner": "acme" }   // token rotation
401 Unauthorized   OIDC token missing / expired / wrong issuer|audience / bad signature
403 Forbidden      not the org/user's owner (OIDC), not its admin (OAuth), or a built-in namespace
409 Conflict       scope already owned by another principal (different identity, or the admin)
400 Bad Request    malformed body / not exactly one proof
501 Not Implemented  OIDC claiming is not configured on this registry (no OIDC_AUDIENCE)
```

For **OIDC**, the Worker verifies the JWT against the issuer's JWKS (issuer/audience/expiry) and
requires `repository_owner` to be the scope. For **OAuth**, it calls the GitHub API (`/user`, and for
an org `/user/memberships/orgs/{org}` — needs `read:org`) to confirm the token holder is the scope's
user or an active admin of the org. A **reserved first-party scope** is claimable only by its
*designated org* (e.g. `para` only by `noeta-dev`).

Both proofs resolve to the owner's **stable GitHub numeric id**, pinned as `owner_id` under one
`owner_kind` (`github`) — so a scope claimed from CI and re-claimed from a laptop are one identity
(the paths are interchangeable), a later **re-claim** (to rotate the publish token) must come from that
*same* identity, a renamed/transferred org can't take a scope over, and an admin-bootstrapped scope is
never transferred to a claimant. Built-in namespaces (`std`/`noeta`/`core`) are never claimable.
Configure via `OIDC_ISSUER` / `OIDC_JWKS_URL` / `OIDC_AUDIENCE` (OIDC) and `GITHUB_API_URL` (OAuth,
default `https://api.github.com`).

## `POST /v1/scopes/{scope}/policy` — set a scope's publishing policy

Set the scope's **require-provenance** policy. Requires `Authorization: Bearer <token>` owning
`{scope}` (same auth as publish — the scope's owner sets its own policy).

```
Body: { "require_provenance": true, "root": "keyless" }   // root optional: "key" | "keyless"

200 OK   { "status": "policy updated", "scope": "para", "require_provenance": true, "root": "keyless" }
401 / 403   missing/invalid token, or token does not own {scope}
400 Bad Request   malformed body / bad root
```

When `require_provenance` is on, `POST /v1/packages/{scope}/…` **refuses a release that lacks the
required provenance** (403) — so a leaked publish token alone can no longer push a release: the
attacker also needs the signing key (`key` root, whose Ed25519 signature the registry verifies) or the
OIDC identity behind a keyless bundle (`keyless` root). `root` narrows which is required; omitted, a
key signature *or* a keyless bundle satisfies it. Default is off (unsigned allowed) so the existing
ecosystem keeps working — this is opt-in, per scope, and the recommended setting for any scope whose
releases are signed. Consumers can additionally demand provenance for a dependency independently of
the scope's own policy via `[trust].require_provenance` in their `noeta.toml`.

## `POST /v1/scopes` *(admin, bootstrap)*

Register a scope's publish token directly. Requires `Authorization: Bearer <ADMIN_TOKEN>` (a Worker
secret). Body `{ "scope": "acme", "token": "<publish-token>" }`. The token is stored **hashed**
(SHA-256); publishing presents the raw token and the Worker compares hashes. This is an escape hatch
for provisioning a scope outside the OIDC flow; ordinary users — and the first party for its own
reserved namespaces (e.g. `noeta-dev` claiming `para`) — take the OIDC `claim` path above. A built-in
namespace (`std`/`noeta`/`core`) is refused even here.

## Transparency log

Every published release is appended to an **append-only, tamper-evident log** — an RFC 6962 Merkle
tree — so a client can verify, without trusting the registry, that a release is logged (**inclusion**)
and that the log was only ever appended to, never rewritten (**consistency**). Together these stop a
compromised registry from *equivocating* — serving one history to one client and a different one to
another. Publishing echoes the release's `log_index`. All log reads are `GET` and unauthenticated.

### `GET /v1/log/checkpoint` — the signed tree head

```
200 OK   { "tree_size": 42, "root_hash": "<hex>", "signature": "<hex Ed25519>" }
501      the log is not configured (no signing key)
```

The signature is over the canonical bytes `noeta-log-checkpoint-v1\n{tree_size}\n{root_hash}\n`,
signed with the log's Ed25519 key. A client **pins** the log's public key and verifies every checkpoint
against it.

### `GET /v1/log/key` — the log's public key

`200 OK { "public_key": "<64-hex Ed25519>" }` (or `404` if unset). What a client pins.

### `GET /v1/log/proof/{company}/{package}/{version}` — inclusion proof

```
200 OK   { "index": 7, "tree_size": 42, "root_hash": "<hex>",
           "record": "<canonical leaf record>", "proof": ["<hex>", …] }
404      that release is not in the log
```

The client recomputes the leaf hash from `record` — the canonical
`noeta-transparency-log-v1\n{name}\n{version}\n{url}\n{tag}\n{sha}\n{provenance}\n` — and verifies the
audit `proof` reconstructs `root_hash`, which must match a signed checkpoint. `provenance` is
`key:{sig}`, `keyless:{sha256(bundle)}`, or `unsigned`.

### `GET /v1/log/consistency?from={m}&to={n}` — consistency proof

```
200 OK   { "from": 30, "to": 42, "root_from": "<hex>", "root_to": "<hex>", "proof": ["<hex>", …] }
400      unless 1 ≤ from ≤ to ≤ tree_size
```

Proves the tree of size `from` is a prefix of the tree of size `to` (append-only). A client that pinned
an earlier checkpoint fetches this against a newer one to confirm the registry didn't rewrite history.

Configure signing via `LOG_PRIVATE_KEY` (base64 PKCS8 Ed25519, a Worker secret) and `LOG_PUBLIC_KEY`
(hex). Without them the log is still appended to and proofs are served, but checkpoints return `501`.

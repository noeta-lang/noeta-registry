# Noeta registry — wire protocol (v1)

The registry is an **index**, not a code store: it maps a package identity + version to the **git
coordinates** (URL + tag + pinned commit SHA) where that release's source lives. It never hosts or
serves package source — a consumer fetches from git and verifies the SHA. This is the contract the
Rust client (`noeta-pm`'s HTTP `Index`) and this Cloudflare Worker both implement; the client is the
source of truth for the shape, the server conforms.

All paths are under `/v1`. Bodies and responses are JSON (`application/json`). Two conventions hold
everywhere:

- **Optional fields are omitted when absent — never `null`** (both directions).
- **Errors are always `{ "error": "<message>" }`** with a matching HTTP status.

The schema is pinned by **golden wire fixtures**: one canonical set of request/response JSON files,
kept in the language repo at `crates/noeta-pm/test_data/wire/` and mirrored **verbatim** here at
`test/fixtures/wire/` (same `MANIFEST.sha256` in both copies; each repo's test suite hashes its copy,
so a diverged or stale copy fails tests). See `test/fixtures/wire/README.md` for the sync rule. When
this document and the fixtures disagree, the fixtures win — fix the prose.

## `GET /v1/packages/{company}/{package}`

List every published version of a package. An unknown package returns `200` with an empty `versions`
array (not a 404) so the client has a single success path.

```
200 OK
{
  "name": "acme/imgfx",
  "versions": [
    { "version": "1.2.0", "url": "https://github.com/acme/imgfx", "tag": "v1.2.0",
      "sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
      "deps": [ { "package": "acme/bytes", "req": "^1.0" } ],
      "signature": "<128-hex>",                        // or "bundle": "<json string>" — at most one
      "yanked": false,
      "published_at": "2026-02-10T09:30:00.000Z",      // ISO-8601 UTC, the stored record
      "published_at_unix": 1770715800000,              // the same instant as epoch milliseconds
      "license": "MIT OR Apache-2.0",                  // omitted when the release declared none
      "keywords": [ "image", "simd" ],                 // sorted; omitted when the release declared none
      "description": "Fast image effects for Noeta" }  // one-line blurb; omitted when none declared
  ]
}
```

`deps` is each version's **registry dependencies** (`{ package: "company/package", req }`), always
present (`[]` when none). The index carries them so a resolver can backtrack over version ranges by
reading a candidate's requirements here, instead of cloning every candidate's source — the
crates.io-index model. A signed release also carries its provenance — a `signature` (key) or
`bundle` (keyless) field — for the consumer to verify. `published_at` and `published_at_unix`
describe the same publish instant (the numeric form feeds the client's `[trust].publish_cooldown`
window without an ISO-8601 parser).

A `yanked` version is still returned (so an existing lockfile can still resolve it — Go's model) but
a resolver must not newly *select* it. Clients must carry the flag through their parse — dropping
yanked rows at deserialization loses the distinction between "yanked" and "never published".

## `POST /v1/packages/{company}/{package}`

Publish a release. Requires `Authorization: Bearer <token>`; the token must own the **scope**
(`{company}`) — you can only publish under a company you control.

```
Body: { "version": "1.2.0", "url": "https://…/acme/imgfx", "tag": "v1.2.0", "sha": "e3b0c4…",
        "deps": [ { "package": "acme/bytes", "req": "^1.0" } ],   // deps optional, default []
        "license": "MIT OR Apache-2.0",                           // optional SPDX expression
        "keywords": [ "image", "simd" ],                          // optional, ≤ 5 discovery tags
        "description": "Fast image effects for Noeta",            // optional, ≤ 200-char single line
        "signature": "<128-hex>" | "bundle": "<json>" }           // provenance — at most one, optional

201 Created   { "status": "published", "name": "acme/imgfx", "version": "1.2.0", "sha": "e3b0c4…",
                "license": "MIT OR Apache-2.0",                   // omitted when none declared
                "keywords": [ "image", "simd" ],                  // omitted when none declared
                "description": "Fast image effects for Noeta",    // omitted when none declared
                "provenance": "key" | "keyless" | "unsigned",
                "log_index": 7 }                                  // the release's transparency-log leaf
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

**License (optional).** The release's declared license as an SPDX expression (≤ 120 chars,
shape-checked only). Part of the **immutable release record** — echoed on `GET` and bound into the
release's transparency-log leaf — so what the index said at resolve time is tamper-evident. It is
**publisher-asserted**: the registry never fetches source and cannot verify the claim matches the
repository's LICENSE file; the SHA pin means a consumer can always check the release's actual tree.

**Keywords (optional).** Up to 5 discovery tags, each 1–20 chars of `[a-z0-9-]` starting
alphanumeric (`para`, `aether`, `no-std`). They answer the question the index otherwise can't —
"what builds on top of `para`?" — and are browsable at `/keywords/{keyword}`. A **set**: duplicates
collapse and both the stored rows and every echo are **sorted**, so the order sent doesn't matter.
The narrow charset is the point: one canonical spelling per tag is what makes a listing group
instead of fragmenting across `Aether`/`aether_`/`AEther`.

Part of the immutable release record (a re-publish that only re-tags is a `409`, not a silent
no-op), but deliberately **not bound into the transparency-log leaf**, unlike `license`. The leaf
binds what a consumer must trust at resolve time — identity, coordinates, provenance, license. A
keyword is discovery metadata: tampering with one mis-files a package in a listing; it cannot
redirect a build or misrepresent a legal claim. Binding it would grow the leaf's record format, and
every client's parse of it, for no security gain.

Declared in the manifest as `[package] keywords` and sent on publish by `noeta-pm`; the shape is
pinned by the golden fixtures (`publish-request-signed.json`, `versions-response.json`) in both
repos. Optional and omitted-when-absent, so a client or registry that predates the field stays
compatible in both directions.

**Description (optional).** A single-line blurb, ≤ 200 characters, no control characters — the
summary shown next to a package in search results and on its page. Declared as `[package]
description`. Like `keywords`, it is part of the immutable release record but **not** bound into the
transparency-log leaf (discovery prose, not a resolve-time claim), and it feeds the FTS search index
alongside the name and keywords. Optional and omitted-when-absent.

**Global package search.** `GET /search?q=…` (the web browser) matches over package names,
keywords, and descriptions via an FTS5 index (BM25-ranked, name weighted highest), returning one
result per package — its most-recently-published release. The query is reduced to alphanumeric
prefix terms before it reaches the index, so no input is a syntax error or a match operator.

**Reserved for the browser.** `keywords` and `search` cannot be registered or claimed as scopes:
packages live at the web browser's root (`/{company}/{package}`), so those scopes would be shadowed
by `/keywords/{keyword}` and `/search`. A registry-server URL concern only — unlike the built-in
scopes it does not change resolution, so the client does not mirror it.

A published `(name, version)` is **immutable**: it can be *yanked* but never overwritten with
different coordinates, deps, license, keywords, or description. The `sha` is recorded at publish time
so the index — not just a consumer's lockfile — is authoritative on "this version = this commit".

## `POST /v1/packages/{company}/{package}/{version}/yank` — body `{ "yanked": true|false }`

Mark (or un-mark) a version yanked. Same scope-ownership auth. Yank never deletes — existing pins
keep resolving; new selections skip it.

```
200 OK          { "status": "yanked" | "unyanked", "name": "acme/imgfx", "version": "1.0.0" }
404 Not Found   that (name, version) is not published
```

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

## `POST /v1/scopes/claim` — self-service scope claim (ownership-proven)

Claim a scope by **proving you control the identity of the same name**. Three proofs — provide
**exactly one**:
- `oidc` — a GitHub Actions **OIDC token** (from CI). The scalable, admin-free path.
- `github_token` — a GitHub OAuth **access token** (from the laptop device flow), for claiming off-CI.
- `domain` — a **domain** whose first label is the scope (`acme` ↔ `acme.dev`); the registry fetches
  `https://{domain}/.well-known/noeta-registry.txt` and requires a `noeta-scope={scope}` line.

Either way the proof-of-control is the anti-squatting mechanism — you cannot claim `stripe` unless you
*are* `stripe` (its GitHub org/user, an admin of it, or the operator of a `stripe.*` domain binding it).

```
Body: { "scope": "acme", "token": "<publish-token>",
        "oidc": "<JWT>" | "github_token": "<OAuth token>" | "domain": "acme.dev" }   // exactly one

201 Created   { "status": "scope claimed",    "scope": "acme", "owner": "acme" }
              // `owner` echoes the proven principal: the GitHub org/user, or the domain
200 OK        { "status": "scope re-claimed", "scope": "acme", "owner": "acme" }   // token rotation
401 Unauthorized   OIDC token missing / expired / wrong issuer|audience / bad signature
403 Forbidden      not the org/user's owner (OIDC), not its admin (OAuth), the domain doesn't bind
                   the scope, or a built-in namespace
409 Conflict       scope already owned by another principal (different identity/kind, or the admin)
400 Bad Request    malformed body / not exactly one proof
501 Not Implemented  OIDC claiming is not configured on this registry (no OIDC_AUDIENCE)
```

For **OIDC**, the Worker verifies the JWT against the issuer's JWKS (issuer/audience/expiry) and
requires `repository_owner` to be the scope. For **OAuth**, it calls the GitHub API (`/user`, and for
an org `/user/memberships/orgs/{org}` — needs `read:org`) to confirm the token holder is the scope's
user or an active admin of the org. A **reserved first-party scope** is claimable only by its
*designated org* (e.g. `para` only by `noeta-lang`).

The two GitHub proofs resolve to the owner's **stable GitHub numeric id**, pinned as `owner_id` under
one `owner_kind` (`github`) — so a scope claimed from CI and re-claimed from a laptop are one identity
(the paths are interchangeable), a later **re-claim** (to rotate the publish token) must come from that
*same* identity, a renamed/transferred org can't take a scope over, and an admin-bootstrapped scope is
never transferred to a claimant. A domain proof pins `owner_kind` `domain` with the domain as the id —
a different owner *kind* can never take over an existing scope. A reserved first-party scope (e.g.
`para`) is claimable only by its designated GitHub org, never by domain. Built-in namespaces
(`std`/`noeta`/`core`) are never claimable.
Configure via `OIDC_ISSUER` / `OIDC_JWKS_URL` / `OIDC_AUDIENCE` (OIDC) and `GITHUB_API_URL` (OAuth,
default `https://api.github.com`).

A **newly claimed** scope starts with the **require-provenance (keyless)** policy — the same state
`POST /v1/scopes/{scope}/policy` sets with `{ "require_provenance": true, "root": "keyless" }` — so
a leaked publish token alone can't push a release from day one; every claim proof is an
OIDC-adjacent identity, so keyless publishing is what a claimant already has. The owner can relax or
retarget the policy at any time via the policy endpoint. A **re-claim** (token rotation) never
changes the policy, and scopes claimed before this default keep whatever policy they had.

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
key signature *or* a keyless bundle satisfies it. Admin-bootstrapped and pre-existing scopes default
to off (unsigned allowed) so the existing ecosystem keeps working; a **newly claimed** scope defaults
to on with the `keyless` root (see the claim endpoint above) — either way the policy stays the
owner's to set, per scope, and require-provenance is the recommended setting for any scope whose
releases are signed. Consumers can additionally demand provenance for a dependency independently of
the scope's own policy via `[trust].require_provenance` in their `noeta.toml`.

## `POST /v1/scopes/{scope}/rotate` — mint a replacement publish token

Replace the scope's publish token with a **fresh, server-minted** one. Authorized by the scope's
**current publish token** (routine hygiene) or the **admin token** (recovery — a claimant who lost
the token can otherwise only re-claim, and an admin-bootstrapped scope can't re-claim). No body.

```
200 OK   { "status": "token rotated", "scope": "acme", "token": "noeta_<64-hex>",
           "note": "shown once — store it now; the previous token no longer publishes" }
401 Unauthorized   no bearer token presented
403 Forbidden      token is neither the scope's current token nor the admin token, or the scope
                   is not registered
```

The new token is generated server-side (32 random bytes — its entropy is never the caller's choice),
stored **hashed** in one atomic UPDATE (there is never a moment with zero or two valid tokens), and
returned **exactly once**: the registry keeps only the hash, so a lost response means another
rotation, not a lookup. Rotation changes the credential only — ownership (`owner_kind`/`owner_id`),
the scope's public key, and its provenance policy are untouched.

## `POST /v1/scopes` *(admin, bootstrap)*

Register a scope's publish token directly. Requires `Authorization: Bearer <ADMIN_TOKEN>` (a Worker
secret). Body `{ "scope": "acme", "token": "<publish-token>", "public_key": "<64-hex>" }` (the
Ed25519 `public_key` — for verifying the scope's release signatures — is optional); responds
`201 { "status": "scope registered", "scope": "acme" }`. The token is stored **hashed**
(SHA-256); publishing presents the raw token and the Worker compares hashes. This is an escape hatch
for provisioning a scope outside the OIDC flow; ordinary users — and the first party for its own
reserved namespaces (e.g. `noeta-lang` claiming `para`) — take the OIDC `claim` path above. A built-in
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
`noeta-transparency-log-v1\n{name}\n{version}\n{url}\n{tag}\n{sha}\n{provenance}\n{license}\n` — and
verifies the audit `proof` reconstructs `root_hash`, which must match a signed checkpoint.
`provenance` is `key:{sig}`, `keyless:{sha256(bundle)}`, or `unsigned`; `license` is the release's
declared SPDX expression, or empty when none.

**Record evolution.** New fields are only ever **appended**, and clients parse length-tolerantly
(match on the fields you know, ignore extras, treat missing trailing fields as pre-dating them) —
`license` was appended after the original six, so leaves written before it still verify unchanged.

### `GET /v1/log/consistency?from={m}&to={n}` — consistency proof

```
200 OK   { "from": 30, "to": 42, "root_from": "<hex>", "root_to": "<hex>", "proof": ["<hex>", …] }
400      unless 1 ≤ from ≤ to ≤ tree_size
```

Proves the tree of size `from` is a prefix of the tree of size `to` (append-only). A client that pinned
an earlier checkpoint fetches this against a newer one to confirm the registry didn't rewrite history.

Configure signing via `LOG_PRIVATE_KEY` (base64 PKCS8 Ed25519, a Worker secret) and `LOG_PUBLIC_KEY`
(hex). Without them the log is still appended to and proofs are served, but checkpoints return `501`.

### `GET /v1/log/advisory/{id}` — an advisory's inclusion proof

The same `{ index, tree_size, root_hash, record, proof }` shape as a release proof, for the leaf of
an advisory's **current state** (`record` is the advisory's canonical bytes — see below). `404` if
the advisory isn't logged.

## Security advisory feed

A signed, RUSTSEC-style database of known-bad releases, so `noeta audit` can flag a pinned dependency.
Signed with its **own** Ed25519 key (a distinct role from the log key): each advisory individually
over its canonical bytes, plus a signed **feed head** `{ count, digest }` a client pins to detect a
dropped/rolled-back feed. Reads are unauthenticated.

### `GET /v1/advisories[?since={seq}]` — the feed

```
200 OK
{
  "advisories": [
    { "id": "NOETA-2026-0001", "package": "acme/imgfx", "ranges": ">=1.0.0, <1.2.0",
      "patched": "1.2.0",                    // optional, informational
      "severity": "low" | "medium" | "high" | "critical",
      "summary": "<one line>", "details": "<may be multi-line>", "url": "<link>",
      "withdrawn": false,                    // a retracted advisory is kept, never deleted
      "seq": 0,                              // monotonic feed cursor (drives ?since delta sync)
      "signature": "<128-hex>",              // Ed25519 over the canonical bytes
      "log_index": 7,                        // its transparency-log leaf; omitted if unlogged
      "tier": "operator",                    // "operator" | "publisher" | "imported" (intake tier)
      "bundle": "<json string>",             // publisher tier only: the owner's keyless attestation
      "upstream_id": "GHSA-…",               // imported tier only: the upstream advisory id
      "upstream_url": "<link>",              // imported tier only: a link to the upstream advisory
      "cvss": "CVSS:3.1/AV:N/…" }            // imported tier: the CVSS vector the band was derived from
  ]
}
```

The canonical bytes an advisory is signed over (and logged as) are
`noeta-advisory-v1\n{id}\n{package}\n{ranges}\n{severity}\n{active|withdrawn}\n{summary}\n{sha256(details)}\n{url}\n{tier}\n`
— reproduced identically by the client (`noeta-pm`'s `advisory::canonical_bytes`), binding the
withdrawn state so an advisory can't be silently un-retracted under the same signature, and the
`tier` (appended after the original eight fields — the record-evolution append rule) so a client can
trust *which* intake tier the registry served. `bundle`/`upstream_id`/`upstream_url` are echoed but
**not** in the signed bytes: the bundle is self-attesting (the consumer verifies it offline), and the
upstream links are provenance metadata, as is `cvss` (see below).

**CVSS-vector severity.** When an imported upstream record carries a CVSS v3.x vector (OSV `severity[]`
entries of type `CVSS_V3`, or GHSA's `cvss.vectorString`), the import computes the base score honestly —
the published CVSS v3.1 base-metric equations — and derives the canonical `severity` band from it,
storing the vector in `cvss`. `cvss` is echoed but **not** signed (like `bundle`/`upstream_*`): the
signed decision is the `severity` band; the vector lets a client re-derive and display the score. A text
severity (`database_specific.severity`) remains the fallback when no vector is present.

**Intake tiers (advisory-intake arc).** Every advisory records how it entered the feed — the arc's
rule is *automate provenance, never judgment*:
- `operator` — operator-curated, admin-issued (`POST /v1/advisories`; the anchor tier, the default).
- `publisher` — issued by a scope's own owner for a package in their own scope
  (`POST /v1/scopes/{scope}/advisories`), carrying a keyless Sigstore `bundle` the consumer verifies
  offline against the scope's pinned identity.
- `imported` — mirrored from an external ecosystem (OSV/GHSA/RUSTSEC) via the operator-curated name map
  (`POST /v1/advisories/import` + the scheduled cron), carrying the upstream id + link.

A **public report** (`POST /v1/reports`) is never an advisory: it is unauthenticated intake, invisible
in the feed, and only becomes an advisory when an operator or scope owner **promotes** it.

### `GET /v1/advisories/checkpoint` — the signed feed head

`200 OK { "count": 1, "digest": "<64-hex>", "signature": "<128-hex>" }` (or `501` when no advisory
key is configured). `digest` is SHA-256 over the id-sorted concatenation of every advisory's
canonical bytes; the signature is over `noeta-advisory-feed-v1\n{count}\n{digest}\n`. A count that
regresses, or a digest that doesn't match the served feed, means an advisory was withheld.

### `GET /v1/advisories/key` — the feed's public key

`200 OK { "public_key": "<64-hex Ed25519>" }` (or `404` if unset). What a client pins.

### `POST /v1/advisories` *(admin)* — publish or update an **operator** advisory

`Authorization: Bearer <ADMIN_TOKEN>`. Body: the advisory fields above minus `seq`/`signature`/
`log_index`/`withdrawn` defaults (`withdrawn` optional, default `false`; `details`/`url` optional,
default `""`; `patched` optional). Idempotent per `id` — re-posting updates the advisory (e.g. to
withdraw or re-scope), bumps `seq`, re-signs, and appends the new state to the transparency log.
Responds `201 { "status": "advisory published", "id": "…", "tier": "operator", "seq": 0, "log_index": 7 }`.
`501` when no advisory signing key is configured.

Configure via `ADVISORY_PRIVATE_KEY` (base64 PKCS8, a Worker secret) / `ADVISORY_PUBLIC_KEY` (hex).

### `POST /v1/scopes/{scope}/advisories` — a **publisher** advisory (scope owner)

A scope's own owner issues an advisory for a package in their own scope (advisory-intake arc, tier 2).
Authenticated exactly like publish: `Authorization: Bearer <token>` owning `{scope}`. Body: the same
advisory fields **plus** a required `bundle` — a keyless Sigstore bundle (JSON string) attesting the
advisory under the owner's OIDC identity, stored verbatim and verified **offline by the consumer**
(the registry is never the trust boundary for it, exactly like a release bundle).

```
Body: { "id": "ACME-2026-0001", "package": "acme/imgfx", "ranges": ">=1.0.0, <1.2.0",
        "severity": "high", "summary": "…", "details": "…", "url": "…", "patched": "1.2.0",
        "bundle": "<keyless Sigstore bundle JSON>" }

201 Created   { "status": "advisory published", "id": "…", "tier": "publisher", "seq": 3, "log_index": 9 }
403 Forbidden  the token doesn't own {scope}, or `package` is not under {scope}
400 Bad Request  malformed body, or a missing/invalid `bundle`
501            no advisory signing key configured
```

The advisory is marked `tier: "publisher"`, re-signed with the feed key, and transparency-logged like
any other. The `bundle` is what makes it publicly attributable and un-forgeable: only the scope owner's
OIDC identity can produce a bundle over these bytes.

### Imported feeds (OSV / GHSA / RUSTSEC) — advisory-intake tier 3

An external ecosystem names packages in its own namespace; a **name mapping** binds one to a Noeta
package identity. Mappings are operator-curated data — a human judgment, never inferred. The scheduled
cron pulls the configured upstream sources, applies the mappings, and imports only mapped packages.

**Source adapters (the scheduled cron).** Each source is env-gated — an unconfigured source is a no-op —
and queried against the operator-curated name map, so only mapped packages ever import. Records are
de-duplicated by upstream id across sources, and the import is idempotent per upstream id.

| Source | Env | How it is pulled |
|---|---|---|
| **OSV** (api.osv.dev) | `OSV_API` (`off` to disable; on by default), `OSV_API_URL` to override the endpoint | `POST /v1/query` per mapped package (full OSV records; `page_token` pagination) |
| **GHSA** (GitHub GraphQL) | `GITHUB_TOKEN` (absent → skip), `GITHUB_GRAPHQL_URL` to override | `securityVulnerabilities(ecosystem, package)` per mapped package, paginated; the advisory's `cvss.vectorString` feeds the severity band |
| **RUSTSEC** | `RUSTSEC_IMPORT_URL` (absent → skip) | its published OSV feed, streamed with `next_page_token` / `next` pagination |
| **Manual override** | `OSV_IMPORT_URL` | a single pre-assembled OSV array/`{advisories}` (backfills, testing) |

OSV and GHSA are queried **per mapped package** rather than swept whole: the mapped set is small and
human-curated, so bounding queries to it keeps the cron's Cloudflare-Workers subrequest use proportional
to the curated set (not to the millions of upstream records), and matches the "only mapped packages
import" principle. Each per-query paginator is capped (a backstop against an unbounded upstream).

#### `POST /v1/name-mappings` *(admin)* / `GET /v1/name-mappings`

```
POST Body: { "ecosystem": "crates.io", "external_name": "imgfx-rs", "noeta_package": "acme/imgfx" }
201 Created  { "status": "mapping registered", … }   // idempotent per (ecosystem, external_name)
GET 200 OK   { "mappings": [ { "ecosystem", "external_name", "noeta_package" }, … ] }   // public
```

#### `POST /v1/advisories/import` *(admin)* — import a batch of OSV records

```
Body: { "advisories": [ <OSV record>, … ] }
200 OK  { "status": "import complete", "imported": 3, "skipped": 1 }
```

Each OSV record's `affected[].package` `(ecosystem, name)` is looked up in the name map; a record with
no mapping is **skipped** (never guessed). A mapped record becomes a `tier: "imported"` advisory whose
`id` is the upstream id (so re-import is idempotent), carrying `upstream_id`/`upstream_url`. The
affected `ranges` are derived from the OSV SEMVER events, and the severity from the CVSS vector (an OSV
`CVSS_V3` `severity[]` entry) when present, else GHSA's `database_specific.severity` (defaulting to
`medium`). The **scheduled cron** runs the same import automatically over the configured source adapters
above.

### Public report queue — advisory-intake tier 4 (intake only)

Anyone may *file* a report; a report is never an advisory and never appears in the signed feed. It
becomes an advisory only via an explicit **promote** (operator or the package's scope owner).

#### `POST /v1/reports` — file a report (unauthenticated, rate-limited)

```
Body: { "package": "acme/imgfx", "summary": "<one line>",
        "ranges": "…", "details": "…", "url": "…", "reporter": "…" }   // all but package+summary optional
201 Created  { "status": "report filed", "id": "<opaque>", "note": "…" }
429 Too Many Requests   the reporter's IP exceeded REPORT_RATE_LIMIT (default 5/hour)
400 Bad Request         malformed body
```

The reporter's IP is hashed for rate-limiting only — never stored raw, never served.

#### `GET /v1/reports[?status=&package=]` *(admin)* / `GET /v1/scopes/{scope}/reports` *(scope owner)*

The triage queue. Admin sees everything; a scope owner sees only their own scope's reports
(owner-authenticated). `ip_hash` is never included.

#### `GET /v1/reports/{id}` *(operator or scope owner)* — one report by id

```
200 OK  { "report": { "id", "package", "ranges", "summary", "details", "url", "reporter", "status", "advisory_id", "created_at" } }
404 Not Found  no such report
```

One report by id, authorized as the operator (admin token) or the scope owner of the report's own
package (scope token) — the same two identities that may promote it. `ip_hash` is never included.
`noeta advisory promote` fetches this to **prefill** the advisory from the report.

#### `POST /v1/reports/{id}/promote` — turn a report into an advisory

Authenticated as an **operator** (admin token → an `operator` advisory) or the **scope owner** of the
report's package (scope token → a `publisher` advisory, which must carry a `bundle`). Body: the
*triaged* advisory fields (the promoter supplies the real id/range/severity/summary; `package` must
match the report's). Marks the report `promoted` and records the advisory id.

```
201 Created  { "status": "report promoted", "report": "<id>", "advisory": "…", "tier": "operator", … }
409 Conflict  the report is already promoted/dismissed
404 Not Found  no such report
```

#### `POST /v1/reports/{id}/dismiss` *(admin)* — close a report without an advisory

`200 OK { "status": "report dismissed", "id": "…" }` (a false alarm or duplicate; the report is kept,
never deleted). `409` if already promoted/dismissed.

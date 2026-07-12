# noeta-registry

The [Noeta](https://noeta.dev) package registry: an **index**, not a code store. It maps a package
identity (`company/package`) + version to the **git coordinates** (repository URL + tag + pinned
commit SHA) where that release's source lives. Consumers fetch the source from git and verify the
SHA; the registry never hosts or serves code — so a registry compromise can, at worst, point at a
different repo/tag, and the consumer's SHA pin catches it.

Runs on **Cloudflare Workers + D1** (SQLite at the edge): tiny, read-dominated, globally replicated,
free at ecosystem-nascent scale. The wire protocol is in [`PROTOCOL.md`](PROTOCOL.md); the Rust
client that consumes it lives in the language toolchain (`noeta-pm`), and this Worker conforms to it.

## Security posture

- **Immutable versions** — a published `(name, version)` can be *yanked* but never re-pointed
  (D1 primary key + application check); a yank never deletes, so existing lockfiles keep resolving.
- **Scope ownership** — a publish token is bound to a `company`; only its owner publishes under it.
- **SHA pinning at publish** — the index records the commit the tag resolved to, so it (not just a
  consumer lockfile) is authoritative on version→commit.
- **Dependency-free Worker** — no runtime npm dependencies (a registry that fights supply-chain
  attacks shouldn't ship a tree of them).
- **Advisory docs** — a release may carry its generated `docs.json` (`noeta doc --out`), stored
  separately and mutably: docs can be refreshed or regenerated without touching the immutable
  release record, and a bad docs blob never affects resolution or the SHA pin.

## Web UI

Every path that is **not** under `/v1` is a public, read-only **browser** (dependency-free HTML,
served by the same Worker):

- `/` — recently published packages.
- `/{company}/{package}` — the package: latest version, git coordinates, dependencies, provenance,
  and a link to its docs.
- `/{company}/{package}/{version}` — a specific version.
- `/{company}/{package}/{version}/docs` — **rendered documentation** from the release's stored
  `docs.json` (the docs.rs analog), if the publisher uploaded one.

It renders only already-public index data and stored docs, so it needs no login, sessions, or
account model — management (publish, yank) stays in the `noeta` CLI. Doc prose is publisher-supplied,
so the small built-in Markdown renderer is **escape-first** and drops non-`http(s)` link schemes; a
strict `Content-Security-Policy` (`default-src 'none'`) is layered on top.

## Local development

```sh
npm install
npm run migrate:local          # apply migrations to the local D1
npm run dev                    # wrangler dev — a local Worker + local D1
```

Then, against `http://localhost:8787`:

```sh
# Bootstrap a scope (admin). Set ADMIN_TOKEN locally in .dev.vars first (ADMIN_TOKEN="…").
curl -XPOST localhost:8787/v1/scopes -H 'authorization: Bearer <ADMIN_TOKEN>' \
  -d '{"scope":"acme","token":"a-publish-token-16+chars"}'

# Publish, then read back.
curl -XPOST localhost:8787/v1/packages/acme/imgfx -H 'authorization: Bearer a-publish-token-16+chars' \
  -d '{"version":"1.2.0","url":"https://github.com/acme/imgfx","tag":"v1.2.0","sha":"e3b0c44…"}'
curl localhost:8787/v1/packages/acme/imgfx
```

## Deploy (your Cloudflare account)

```sh
wrangler d1 create noeta-registry           # paste the printed id into wrangler.jsonc
npm run migrate:remote
wrangler secret put ADMIN_TOKEN             # set the admin token
npm run deploy
```

Generated with assistance from Claude Code; not yet deployed.

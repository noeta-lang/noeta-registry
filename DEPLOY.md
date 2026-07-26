# Deploying the Noeta registry

The registry is a single Cloudflare Worker (`src/index.ts`) over one D1 database, served at
`https://registry.noeta.dev` (a custom domain bound in `wrangler.jsonc` — Wrangler manages the DNS
record itself; never add a CNAME by hand). This file is the operator's ritual: what must exist
before a deploy, how to deploy, how to verify one, and how to back up the database.

## What must exist (one-time provisioning)

### D1 database

`wrangler.jsonc` binds the database as **`DB`** → database **`noeta-registry`**
(`database_id` is committed in `wrangler.jsonc`; migrations live in `migrations/`). On a fresh
account:

```
wrangler d1 create noeta-registry     # paste the printed id into wrangler.jsonc
pnpm run migrate:remote               # wrangler d1 migrations apply noeta-registry --remote
```

`migrate:remote` is **idempotent** — it applies only migrations the database hasn't seen, so it is
safe (and required) to run before any deploy that adds a file under `migrations/`.

### Secrets (names only — values are never committed)

Set with `wrangler secret put <NAME>`; stored by Cloudflare, never in the repo. `.dev.vars` holds
local-dev values and is gitignored — never commit or print it.

| Secret                  | Required | Purpose                                                                                   |
| ----------------------- | -------- | ----------------------------------------------------------------------------------------- |
| `ADMIN_TOKEN`           | yes      | Gates the admin surface: `POST /v1/scopes` bootstrap, advisory publish/import, report triage. |
| `LOG_PRIVATE_KEY`       | yes      | Ed25519 (base64 PKCS8) that signs transparency-log checkpoints. Without it `/v1/log/checkpoint` is 501 (the log still appends). |
| `ADVISORY_PRIVATE_KEY`  | yes      | Ed25519 (base64 PKCS8) that signs advisories and the feed head. Distinct key from the log key on purpose. |
| `GITHUB_TOKEN`          | no       | Enables the GHSA advisory-import source in the daily cron. Absent → that source is a no-op. |

The **public** halves (`LOG_PUBLIC_KEY`, `ADVISORY_PUBLIC_KEY`) are plain vars committed in
`wrangler.jsonc` — clients pin them — as raw 32-byte hex, **not** the SPKI DER openssl emits by
default. If a private key is ever rotated, its public var must be updated in the same deploy, and
clients that pinned the old key will reject the new signatures — rotation of these keys is a
breaking event, not routine hygiene.

Plain configuration (`OIDC_ISSUER`, `OIDC_JWKS_URL`, `OIDC_AUDIENCE`, advisory-source URLs) also
lives in `wrangler.jsonc` `vars`. `OIDC_AUDIENCE` must stay `registry.noeta.dev` — a per-deployment
audience is what stops a claim token minted for one registry being relayed to another.

## The deploy ritual

From the repo root, on a clean checkout of the commit you mean to ship:

```
pnpm install                # honor pnpm-lock.yaml
pnpm run typecheck          # tsc --noEmit
pnpm run test               # vitest (Workers pool: the real Worker against a local D1)
pnpm run migrate:remote     # apply any new migrations FIRST — the old Worker tolerates new
                            # columns, but the new Worker must never race a missing table
pnpm run deploy             # wrangler deploy
```

Order matters: **migrations before code**. Every migration so far is additive (new tables/columns),
so the running Worker keeps working while the schema is ahead; the reverse order would let the new
code query a table that doesn't exist yet.

## Verifying a deploy

The transparency-log checkpoint exercises the Worker, the D1 binding, and the signing secret in one
request:

```
curl -s https://registry.noeta.dev/v1/log/checkpoint
# 200 { "tree_size": N, "root_hash": "<hex>", "signature": "<hex Ed25519>" }  → healthy
# 501 "log is not configured"                                                 → LOG_PRIVATE_KEY missing
# 500 / "no such table"                                                       → migrations not applied
```

Then spot-check the neighbouring surfaces:

```
curl -s https://registry.noeta.dev/v1/log/key          # the pinned log public key
curl -s https://registry.noeta.dev/v1/advisories/key   # the pinned advisory public key
curl -s https://registry.noeta.dev/v1/packages/para/api  # a known package resolves
curl -sI https://registry.noeta.dev/                   # the web browser renders (200, text/html)
```

`tree_size` must never *decrease* across deploys — the log is append-only; a smaller tree than the
last known checkpoint means the database was restored/replaced and clients will (correctly) scream
about consistency. That is exactly the property that makes the checkpoint the right smoke test.

## D1 backup

### How

Whole-database `wrangler d1 export` **does not work here** — it refuses databases with FTS5
virtual tables ("cannot export databases with Virtual Tables (fts5)"), and this database has
`package_fts`. So backups are **data-only, per-table** dumps; schema always comes from
`migrations/`. `scripts/backup-d1.sh` loops every real table with
`wrangler d1 export --no-schema --table <t>` into a timestamped directory:

```
./scripts/backup-d1.sh              # writes backups/noeta-registry-<UTC timestamp>/<table>.sql
./scripts/backup-d1.sh /mnt/nas/d1  # or into a directory of your choice
```

The table list lives in the script — keep it in sync when a migration adds a table.

`backups/` is gitignored — dumps are operator artifacts, not repo content. Restore, should it ever
come to that, into a **fresh** database: apply `migrations/` first (recreates every table,
including the FTS index and its triggers), then `wrangler d1 execute noeta-registry --remote
--file <table>.sql` for each dump, then rebuild the search index:

```
wrangler d1 execute noeta-registry --remote --command "INSERT INTO package_fts(package_fts) VALUES('rebuild')"
```

And note the transparency-log caveat above: restoring an old dump rewinds `tree_size`, which
clients treat as equivocation. A restore is a disaster-recovery event that must ship with an
operator advisory, not a quiet fix.

### Cadence

- **Before every `migrate:remote`** — a migration is the only routine operation that rewrites the
  schema, so it gets a pre-flight dump, every time.
- **Weekly** otherwise (cron or calendar; the database is small — a dump is seconds and kilobytes).
- Cloudflare's own **Time Travel** keeps 30 days of point-in-time restore for D1 independent of
  these dumps; the exports are for what Time Travel doesn't cover — keeping history past 30 days,
  and holding a copy outside Cloudflare.

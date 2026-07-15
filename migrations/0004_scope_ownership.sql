-- Scope ownership binding (namespace-protection arc #1) — move scope registration off the
-- admin-only bootstrap and onto a self-service claim proven by a verifiable OIDC identity.
--
-- A scope is now owned by one of two kinds of principal:
--   • 'admin'       — provisioned via the ADMIN_TOKEN bootstrap (the first party). owner_id is NULL.
--                     First-party reserved namespaces (para) are registrable only this way.
--   • 'github-oidc' — self-service: the claimant proved, via a GitHub Actions OIDC token, that they
--                     control the GitHub org/user whose name equals the scope. owner_id pins the
--                     stable `repository_owner_id` claim, so re-claims (token rotation) require the
--                     *same* identity — a renamed/handed-over org can't silently take it over.
--
-- Existing rows predate this and were admin-bootstrapped; leaving their columns NULL classifies them
-- as admin-owned (owner_id NULL), which self-service claims refuse to overwrite.
ALTER TABLE scopes ADD COLUMN owner_kind TEXT;
ALTER TABLE scopes ADD COLUMN owner_id TEXT;

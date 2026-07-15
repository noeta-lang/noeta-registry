// GitHub OAuth ownership verification (namespace-protection #1, laptop claim) — the off-CI counterpart
// to OIDC. A laptop has no GitHub Actions OIDC token, so instead the client authenticates the user via
// the GitHub OAuth **device flow** and hands us the resulting access token; we call the GitHub API to
// confirm the token holder controls the scope being claimed — it is their own login, or an org they
// administer — and return that principal's **stable GitHub numeric id**.
//
// Crucially that id is the *same* value GitHub Actions puts in the OIDC `repository_owner_id` claim, so
// a scope claimed from CI and re-claimed from a laptop resolve to one owner identity (owner_kind
// `github`) — the two paths are interchangeable, neither can take a scope over from the other.
//
// The access token is used here and never stored. Configurable API base (`GITHUB_API_URL`) so tests
// can point at a hermetic double.

export interface GithubConfig {
  apiBase: string;
}

export function githubConfig(env: { GITHUB_API_URL?: string }): GithubConfig {
  return { apiBase: (env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "") };
}

/** Verify that `token` (a GitHub OAuth access token) proves control of `requiredOwner`, and return
 *  that owner's stable GitHub numeric id (as a string). Throws with a human-readable reason otherwise.
 *  Matching is exact (case-sensitive) to mirror the OIDC path and the registry's case-sensitive
 *  scopes. */
export async function verifyGithubOwnership(
  token: string,
  requiredOwner: string,
  cfg: GithubConfig,
): Promise<string> {
  const headers = {
    authorization: `Bearer ${token}`,
    accept: "application/vnd.github+json",
    "user-agent": "noeta-registry",
    "x-github-api-version": "2022-11-28",
  };

  // Who does this token belong to?
  const userRes = await fetch(`${cfg.apiBase}/user`, { headers });
  if (userRes.status === 401) throw new Error("the GitHub token is invalid or expired");
  if (!userRes.ok) throw new Error(`GitHub \`/user\` returned HTTP ${userRes.status}`);
  const user = (await userRes.json()) as { login?: string; id?: number };
  if (typeof user.login !== "string" || typeof user.id !== "number") {
    throw new Error("GitHub `/user` response is missing login/id");
  }

  // Personal namespace: the scope is the token holder's own login.
  if (user.login === requiredOwner) return String(user.id);

  // Otherwise it must be an org the user actively administers. `read:org` is required for this call.
  const memRes = await fetch(
    `${cfg.apiBase}/user/memberships/orgs/${encodeURIComponent(requiredOwner)}`,
    { headers },
  );
  if (memRes.status === 404 || memRes.status === 403) {
    throw new Error(
      `\`${requiredOwner}\` is not your GitHub login, and you are not a member of an org by that ` +
        `name (or the token lacks the \`read:org\` scope)`,
    );
  }
  if (!memRes.ok) throw new Error(`GitHub membership check returned HTTP ${memRes.status}`);
  const mem = (await memRes.json()) as {
    role?: string;
    state?: string;
    organization?: { login?: string; id?: number };
  };
  if (
    mem.state !== "active" ||
    mem.role !== "admin" ||
    mem.organization?.login !== requiredOwner ||
    typeof mem.organization?.id !== "number"
  ) {
    throw new Error(`you must be an active admin of the \`${requiredOwner}\` org to claim it`);
  }
  return String(mem.organization.id);
}

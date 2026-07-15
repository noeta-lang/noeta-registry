// Domain ownership verification (namespace-protection #1, domain proof) — a third proof-of-control for
// a scope, alongside GitHub OIDC (CI) and GitHub OAuth (laptop). The claimant proves they control the
// DNS domain whose **leftmost label is the scope** (`acme` ⇐ `acme.dev`) by serving a well-known file
// over HTTPS that opts the domain into registry scope binding.
//
// Two conditions, together the anti-squat rule: (1) the scope must equal the domain's first label —
// the domain analogue of "scope == GitHub owner", so you can only claim `acme` by controlling
// `acme.<tld>`; (2) the domain must serve `/.well-known/noeta-registry.txt` containing
// `noeta-scope=<scope>` — so merely controlling a domain doesn't auto-claim, the owner opts in.
//
// owner_kind is `domain` and owner_id is the domain, so re-claims (token rotation) require the same
// domain, and a domain can never take over a GitHub-owned scope (the owner_kind differs). The scheme is
// configurable (`DOMAIN_SCHEME`) only so tests can exercise the flow; production is always https.

const WELL_KNOWN = "/.well-known/noeta-registry.txt";
const MAX_BODY = 4096; // a control file is tiny; cap the read so a hostile server can't stream forever
const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

export interface DomainConfig {
  scheme: string;
}

export function domainConfig(env: { DOMAIN_SCHEME?: string }): DomainConfig {
  return { scheme: env.DOMAIN_SCHEME ?? "https" };
}

/** Verify `domain` is controlled by whoever is claiming `scope`, returning the normalized domain as the
 *  stable owner id. Throws a human-readable reason otherwise. */
export async function verifyDomainOwnership(
  scope: string,
  rawDomain: string,
  cfg: DomainConfig,
): Promise<string> {
  const domain = rawDomain.trim().toLowerCase().replace(/\.$/, "");
  const labels = domain.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) {
    throw new Error(`\`${rawDomain}\` is not a valid domain name`);
  }
  // (1) The scope must be the domain's leftmost label — the anti-squat binding.
  if (labels[0] !== scope) {
    throw new Error(
      `scope \`${scope}\` must be the domain's first label — \`${domain}\` starts with \`${labels[0]}\``,
    );
  }
  const url = `${cfg.scheme}://${domain}${WELL_KNOWN}`;
  let res: Response;
  try {
    // `manual` so a redirect is *not* followed (a 3xx fails the `res.ok` check below) — control must be
    // proven at the domain itself, not at wherever it redirects.
    res = await fetch(url, { headers: { "user-agent": "noeta-registry" }, redirect: "manual" });
  } catch (err) {
    throw new Error(`could not fetch ${url}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!res.ok) {
    throw new Error(`${url} returned HTTP ${res.status} — serve it to prove control of \`${domain}\``);
  }
  const body = (await res.text()).slice(0, MAX_BODY);
  // (2) The file must explicitly bind this scope (opt-in).
  const bound = body
    .split(/\r?\n/)
    .map((l) => l.trim())
    .some((l) => l === `noeta-scope=${scope}`);
  if (!bound) {
    throw new Error(`${url} does not contain the line \`noeta-scope=${scope}\``);
  }
  return domain;
}

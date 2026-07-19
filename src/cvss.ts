// CVSS v3.x base-score computation (advisory-intake residual b). An imported upstream record often
// carries a CVSS vector rather than a text severity (OSV `severity[]` entries of type `CVSS_V3`; GHSA
// `cvss.vectorString`). This module parses a CVSS v3.0/3.1 base vector and computes the base score
// *honestly* — the published CVSS v3.1 base-metric equations (FIRST CVSS v3.1 specification §7.1) — so
// the derived severity band is the real one, not a lookup guess.
//
// Only the **base** metric group is scored (the part every upstream vector carries); temporal and
// environmental modifiers, if present in the vector, are ignored (they don't change the base score).
// The band mapping is the standard qualitative severity rating scale (spec §5):
//   0.0 → none · 0.1–3.9 → low · 4.0–6.9 → medium · 7.0–8.9 → high · 9.0–10.0 → critical
//
// Deterministic and dependency-free; unit-tested against published example vectors (see test/cvss.test.ts).
// The Rust client re-implements the same equations (`noeta-pm`'s `cvss` module) so `noeta audit` can show
// the score it derived from the (unsigned, informational) vector the feed echoes.

export type CvssBand = "none" | "low" | "medium" | "high" | "critical";

interface BaseMetrics {
  av: number; // Attack Vector
  ac: number; // Attack Complexity
  prRaw: "N" | "L" | "H"; // Privileges Required (scored against Scope below)
  ui: number; // User Interaction
  scopeChanged: boolean; // Scope
  c: number; // Confidentiality impact
  i: number; // Integrity impact
  a: number; // Availability impact
}

// Metric weights, verbatim from the CVSS v3.1 specification (§7.4, Table 15+).
const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0.0 };
// Privileges Required is weighted differently when Scope is Changed.
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** Parse a CVSS v3.0/3.1 vector string into its base metrics, or `null` if it is not a well-formed v3
 *  base vector (missing a mandatory base metric, an unknown value, or a non-v3 prefix). Extra
 *  (temporal/environmental) metrics are tolerated and ignored. */
export function parseVector(vector: string): BaseMetrics | null {
  if (typeof vector !== "string") return null;
  const trimmed = vector.trim();
  // Accept an explicit CVSS:3.x prefix; also tolerate a bare metric string (some feeds drop the prefix).
  const body = /^CVSS:3\.[01]\//i.test(trimmed)
    ? trimmed.slice(trimmed.indexOf("/") + 1)
    : /^AV:/i.test(trimmed)
      ? trimmed
      : null;
  if (body === null) return null;

  const m: Record<string, string> = {};
  for (const part of body.split("/")) {
    if (part.length === 0) continue;
    const [k, v] = part.split(":");
    if (!k || !v) return null;
    m[k.toUpperCase()] = v.toUpperCase();
  }

  const av = AV[m.AV];
  const ac = AC[m.AC];
  const ui = UI[m.UI];
  const c = CIA[m.C];
  const i = CIA[m.I];
  const a = CIA[m.A];
  const prRaw = m.PR as "N" | "L" | "H";
  const scope = m.S;
  if (
    av === undefined ||
    ac === undefined ||
    ui === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined ||
    !["N", "L", "H"].includes(prRaw) ||
    !["U", "C"].includes(scope)
  ) {
    return null;
  }
  return { av, ac, prRaw, ui, scopeChanged: scope === "C", c, i, a };
}

/** Round up to one decimal place, per the CVSS v3.1 spec's exact `Roundup` (§Appendix A) — defined on
 *  integers to avoid the binary-float artefacts a naive `Math.ceil(x*10)/10` produces. */
function roundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** The CVSS v3.1 base score for a parsed vector, in [0.0, 10.0], rounded up to one decimal. */
export function baseScore(m: BaseMetrics): number {
  const iss = 1 - (1 - m.c) * (1 - m.i) * (1 - m.a); // Impact Sub-Score
  const impact = m.scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const pr = (m.scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.prRaw];
  const exploitability = 8.22 * m.av * m.ac * pr * m.ui;
  const raw = m.scopeChanged
    ? 1.08 * (impact + exploitability)
    : impact + exploitability;
  return roundup(Math.min(raw, 10));
}

/** The qualitative severity band for a base score (CVSS v3.1 §5, Table 14). */
export function bandForScore(score: number): CvssBand {
  if (score <= 0) return "none";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

/** Parse a CVSS vector and derive `{ score, band }`, or `null` if the vector is not a valid v3 base
 *  vector. The single entry point the import path uses. */
export function scoreVector(vector: string): { score: number; band: CvssBand } | null {
  const m = parseVector(vector);
  if (!m) return null;
  const score = baseScore(m);
  return { score, band: bandForScore(score) };
}

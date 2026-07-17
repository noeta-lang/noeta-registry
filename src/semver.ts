// SemVer version + requirement matching, for one purpose: telling a *reader* whether the release
// they are looking at falls inside an advisory's affected range.
//
// This is a faithful port of the Rust `semver` crate's `VersionReq::matches` — the same crate the
// client (`noeta-pm`'s `advisory.rs`) audits with. That correspondence is the whole point: the web
// UI must never contradict `noeta audit`. The comparator semantics below (including the fiddly
// caret/tilde rules and the pre-release compatibility rule) mirror that crate's `eval.rs` case for
// case, and `test/semver.test.ts` pins the behaviour against its documented examples.
//
// `noeta audit` remains authoritative: this module exists so a page can say "affected"/"not
// affected", and it answers `null` ("unknown") for anything it cannot parse with confidence rather
// than guessing. A wrong "not affected" is the one outcome worth engineering against.

export interface Version {
  major: number;
  minor: number;
  patch: number;
  /** Dot-separated pre-release identifiers; empty for a release version. */
  pre: string[];
}

type Op = "=" | ">" | ">=" | "<" | "<=" | "~" | "^" | "*";

interface Comparator {
  op: Op;
  major: number;
  /** `null` = unspecified (`^1`), which the ops treat as a wildcard. */
  minor: number | null;
  patch: number | null;
  pre: string[];
}

const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
// `^1.2.3-alpha.1`, `>=1.0`, `1.*`, `~0.2` — build metadata is accepted and ignored.
const COMP_RE =
  /^(\^|~|=|>=|<=|>|<)?\s*(\d+)(?:\.(\d+|\*|x|X))?(?:\.(\d+|\*|x|X))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Parse an exact version. Build metadata is stripped (it is not part of precedence). */
export function parseVersion(s: string): Version | null {
  const m = VERSION_RE.exec(s.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    pre: m[4] ? m[4].split(".") : [],
  };
}

function parseComparator(s: string): Comparator | null {
  const t = s.trim();
  if (t === "*" || t === "x" || t === "X") {
    return { op: "*", major: 0, minor: null, patch: null, pre: [] };
  }
  const m = COMP_RE.exec(t);
  if (!m) return null;
  const wild = (v: string | undefined): number | null =>
    v === undefined || v === "*" || v === "x" || v === "X" ? null : Number(v);
  const minor = wild(m[3]);
  const patch = wild(m[4]);
  // `1.*.3` is nonsense — a specified patch under a wildcard minor.
  if (minor === null && patch !== null) return null;
  // A bare `1.*` is the crate's Wildcard op; a bare `1` (no op) is Caret.
  const explicitWildcard = m[3] === "*" || m[3] === "x" || m[3] === "X" || m[4] === "*" || m[4] === "x" || m[4] === "X";
  const op = (m[1] as Op | undefined) ?? (explicitWildcard ? "*" : "^");
  return { op, major: Number(m[2]), minor, patch, pre: m[5] ? m[5].split(".") : [] };
}

/** SemVer §11 pre-release precedence. An empty pre-release outranks any non-empty one (1.0.0 > 1.0.0-a). */
function comparePre(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (xn !== yn) {
      return xn ? -1 : 1; // numeric identifiers rank below alphanumeric
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

function matchesExact(c: Comparator, v: Version): boolean {
  if (v.major !== c.major) return false;
  if (c.minor !== null && v.minor !== c.minor) return false;
  if (c.patch !== null && v.patch !== c.patch) return false;
  return comparePre(v.pre, c.pre) === 0;
}

function matchesGreater(c: Comparator, v: Version): boolean {
  if (v.major !== c.major) return v.major > c.major;
  if (c.minor === null) return false;
  if (v.minor !== c.minor) return v.minor > c.minor;
  if (c.patch === null) return false;
  if (v.patch !== c.patch) return v.patch > c.patch;
  return comparePre(v.pre, c.pre) > 0;
}

function matchesLess(c: Comparator, v: Version): boolean {
  if (v.major !== c.major) return v.major < c.major;
  if (c.minor === null) return false;
  if (v.minor !== c.minor) return v.minor < c.minor;
  if (c.patch === null) return false;
  if (v.patch !== c.patch) return v.patch < c.patch;
  return comparePre(v.pre, c.pre) < 0;
}

function matchesTilde(c: Comparator, v: Version): boolean {
  if (v.major !== c.major) return false;
  if (c.minor !== null && v.minor !== c.minor) return false;
  if (c.patch !== null && v.patch !== c.patch) return v.patch > c.patch;
  return comparePre(v.pre, c.pre) >= 0;
}

function matchesCaret(c: Comparator, v: Version): boolean {
  if (v.major !== c.major) return false;
  if (c.minor === null) return true;
  const minor = c.minor;
  if (c.patch === null) return c.major > 0 ? v.minor >= minor : v.minor === minor;
  const patch = c.patch;
  if (c.major > 0) {
    if (v.minor !== minor) return v.minor > minor;
    if (v.patch !== patch) return v.patch > patch;
  } else if (minor > 0) {
    // 0.x: the minor is the breaking axis, so it must match exactly.
    if (v.minor !== minor) return false;
    if (v.patch !== patch) return v.patch > patch;
  } else if (v.minor !== minor || v.patch !== patch) {
    // 0.0.x: every patch is breaking — only the exact release matches.
    return false;
  }
  return comparePre(v.pre, c.pre) >= 0;
}

function matchesComparator(c: Comparator, v: Version): boolean {
  switch (c.op) {
    case "=":
    case "*":
      return matchesExact(c, v);
    case ">":
      return matchesGreater(c, v);
    case ">=":
      return matchesExact(c, v) || matchesGreater(c, v);
    case "<":
      return matchesLess(c, v);
    case "<=":
      return matchesExact(c, v) || matchesLess(c, v);
    case "~":
      return matchesTilde(c, v);
    case "^":
      return matchesCaret(c, v);
  }
}

/** A pre-release version is only in range when some comparator opted into that exact release line. */
function preIsCompatible(c: Comparator, v: Version): boolean {
  return c.major === v.major && c.minor === v.minor && c.patch === v.patch && c.pre.length > 0;
}

/**
 * Does `version` satisfy `req`?
 *
 * `req` is a Cargo-style requirement: comma-separated comparators, all of which must hold
 * (`">=1.0.0, <1.2.0"`). Returns `null` when either side cannot be parsed — the caller must render
 * that as "unknown" rather than collapsing it to false.
 */
export function satisfies(version: string, req: string): boolean | null {
  const v = parseVersion(version);
  if (!v) return null;

  const raw = req.trim();
  if (raw.length === 0) return null;
  // A bare `*` is the crate's `VersionReq::STAR`: no comparators at all. Note the consequence
  // below — with nothing to opt in, it does not match a pre-release.
  const comparators: Comparator[] = [];
  if (raw !== "*" && raw !== "x" && raw !== "X") {
    for (const part of raw.split(",")) {
      if (part.trim().length === 0) return null;
      const c = parseComparator(part);
      if (!c) return null;
      comparators.push(c);
    }
  }

  for (const c of comparators) {
    if (!matchesComparator(c, v)) return false;
  }
  if (v.pre.length > 0) {
    return comparators.some((c) => preIsCompatible(c, v));
  }
  return true;
}

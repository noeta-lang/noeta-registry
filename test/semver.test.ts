import { describe, expect, it } from "vitest";
import { satisfies } from "../src/semver";

// These cases are lifted from the Rust `semver` crate's documented semantics — the crate the client
// audits with. The point of the module is that the registry's "affected / not affected" verdict
// agrees with `noeta audit`, so the examples are pinned here rather than re-derived.
//
// Every expectation below was differentially checked against `semver::VersionReq::matches` itself
// (a throwaway Rust binary over this exact case list) — including the pre-release corners, where
// intuition is a poor guide. Re-run that check if you extend `src/semver.ts`.

describe("caret requirements", () => {
  it("^1.2.3 := >=1.2.3, <2.0.0", () => {
    expect(satisfies("1.2.3", "^1.2.3")).toBe(true);
    expect(satisfies("1.2.4", "^1.2.3")).toBe(true);
    expect(satisfies("1.9.9", "^1.2.3")).toBe(true);
    expect(satisfies("1.2.2", "^1.2.3")).toBe(false);
    expect(satisfies("2.0.0", "^1.2.3")).toBe(false);
  });

  it("treats the minor as the breaking axis below 1.0", () => {
    // ^0.2.3 := >=0.2.3, <0.3.0
    expect(satisfies("0.2.3", "^0.2.3")).toBe(true);
    expect(satisfies("0.2.9", "^0.2.3")).toBe(true);
    expect(satisfies("0.3.0", "^0.2.3")).toBe(false);
    // ^0.0.3 := >=0.0.3, <0.0.4 — every patch is breaking
    expect(satisfies("0.0.3", "^0.0.3")).toBe(true);
    expect(satisfies("0.0.4", "^0.0.3")).toBe(false);
  });

  it("^1 and ^0 widen to the major", () => {
    expect(satisfies("1.9.9", "^1")).toBe(true);
    expect(satisfies("2.0.0", "^1")).toBe(false);
    expect(satisfies("0.9.9", "^0")).toBe(true);
    expect(satisfies("1.0.0", "^0")).toBe(false);
  });

  it("defaults a bare version to caret", () => {
    expect(satisfies("1.9.0", "1.2.3")).toBe(true);
    expect(satisfies("2.0.0", "1.2.3")).toBe(false);
  });
});

describe("tilde requirements", () => {
  it("~1.2.3 := >=1.2.3, <1.3.0", () => {
    expect(satisfies("1.2.3", "~1.2.3")).toBe(true);
    expect(satisfies("1.2.9", "~1.2.3")).toBe(true);
    expect(satisfies("1.3.0", "~1.2.3")).toBe(false);
    expect(satisfies("1.2.2", "~1.2.3")).toBe(false);
  });

  it("~1 := >=1.0.0, <2.0.0", () => {
    expect(satisfies("1.9.9", "~1")).toBe(true);
    expect(satisfies("2.0.0", "~1")).toBe(false);
  });
});

describe("comparators and wildcards", () => {
  it("matches the advisory fixture's range", () => {
    // NOETA-2026-0001 affects ">=1.0.0, <1.2.0"; the fixture's patched release is 1.2.0.
    const req = ">=1.0.0, <1.2.0";
    expect(satisfies("1.0.0", req)).toBe(true);
    expect(satisfies("1.1.9", req)).toBe(true);
    expect(satisfies("1.2.0", req)).toBe(false);
    expect(satisfies("0.9.9", req)).toBe(false);
  });

  it("handles = and the ordering operators", () => {
    expect(satisfies("1.2.3", "=1.2.3")).toBe(true);
    expect(satisfies("1.2.4", "=1.2.3")).toBe(false);
    expect(satisfies("1.3.0", ">1.2.3")).toBe(true);
    expect(satisfies("1.2.3", ">1.2.3")).toBe(false);
    expect(satisfies("1.2.3", "<=1.2.3")).toBe(true);
  });

  it("handles wildcards", () => {
    expect(satisfies("1.5.0", "1.*")).toBe(true);
    expect(satisfies("2.0.0", "1.*")).toBe(false);
    expect(satisfies("1.2.9", "1.2.*")).toBe(true);
    expect(satisfies("1.3.0", "1.2.*")).toBe(false);
    expect(satisfies("1.0.0", "*")).toBe(true);
  });
});

describe("pre-release rules", () => {
  it("only matches a pre-release when a comparator opted into that release line", () => {
    // ^1.2.3 does not match 1.2.4-alpha: the comparator names 1.2.3, not 1.2.4.
    expect(satisfies("1.2.4-alpha", "^1.2.3")).toBe(false);
    // ...but a comparator on the same major.minor.patch with a pre-release does.
    expect(satisfies("1.2.3-beta", ">=1.2.3-alpha, <1.3.0")).toBe(true);
  });

  it("a bare * does not match a pre-release (VersionReq::STAR has no comparators)", () => {
    expect(satisfies("1.0.0-alpha", "*")).toBe(false);
    expect(satisfies("1.0.0", "*")).toBe(true);
  });

  it("orders pre-release identifiers per SemVer §11", () => {
    // numeric < alphanumeric, and a release outranks any pre-release of the same triple
    expect(satisfies("1.0.0", ">1.0.0-alpha")).toBe(true);
    expect(satisfies("1.0.0-alpha.1", ">1.0.0-alpha.1, <1.0.1")).toBe(false);
    expect(satisfies("1.0.0-alpha.2", ">1.0.0-alpha.1, <1.0.1")).toBe(true);
    expect(satisfies("1.0.0-alpha.beta", ">1.0.0-alpha.1, <1.0.1")).toBe(true);
  });
});

describe("unparseable input answers unknown, never false", () => {
  it("returns null rather than guessing", () => {
    expect(satisfies("1.0.0", "not a range")).toBeNull();
    expect(satisfies("1.0.0", "")).toBeNull();
    expect(satisfies("1.0.0", ">=1.0.0,")).toBeNull();
    expect(satisfies("1.0.0", "1.*.3")).toBeNull();
    expect(satisfies("not-a-version", "^1")).toBeNull();
    expect(satisfies("1.0", "^1")).toBeNull();
  });

  it("accepts and ignores build metadata", () => {
    expect(satisfies("1.2.3+build.5", "^1.2.3")).toBe(true);
  });
});

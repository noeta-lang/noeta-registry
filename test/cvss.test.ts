import { describe, expect, it } from "vitest";
import { baseScore, bandForScore, parseVector, scoreVector } from "../src/cvss";

// CVSS v3.1 base-score computation (advisory-intake residual b). The scores below are the *published*
// values from the FIRST CVSS v3.1 calculator / the referenced CVEs — this suite pins the equations to
// them so a regression in the base-metric math is caught. (Vectors are the base group only; the score
// is independent of any temporal/environmental metrics.)
describe("CVSS v3.1 base score", () => {
  const cases: [string, number, string][] = [
    // The maximal network vector — CVE-2019-0708 (BlueKeep), among many.
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"],
    // Scope-changed full impact — CVE-2021-44228 (Log4Shell): the published 10.0.
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"],
    // A common reflected low-confidentiality, user-interaction vector — the canonical 4.3.
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3, "medium"],
    // Scope-changed, privileges-required, partial impact.
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "medium"],
    // High attack complexity + high privileges + user interaction, minimal impact → low.
    ["CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"],
    // No impact at all → 0.0 / none.
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"],
    // Local privilege escalation, full impact, no interaction — a classic 7.8 High.
    ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "high"],
  ];

  for (const [vector, score, band] of cases) {
    it(`${vector} → ${score} (${band})`, () => {
      const m = parseVector(vector);
      expect(m).not.toBeNull();
      expect(baseScore(m!)).toBe(score);
      expect(bandForScore(score)).toBe(band);
      expect(scoreVector(vector)).toEqual({ score, band });
    });
  }

  it("accepts a CVSS:3.0 prefix and a bare (prefix-less) vector", () => {
    expect(scoreVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.score).toBe(9.8);
    expect(scoreVector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.score).toBe(9.8);
  });

  it("rejects a malformed or non-v3 vector", () => {
    expect(scoreVector("")).toBeNull();
    expect(scoreVector("nonsense")).toBeNull();
    expect(scoreVector("CVSS:2.0/AV:N/AC:L")).toBeNull();
    // Missing a mandatory base metric (no availability).
    expect(scoreVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")).toBeNull();
    // Unknown metric value.
    expect(scoreVector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
  });
});

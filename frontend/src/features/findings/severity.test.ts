import { describe, expect, it } from "vitest";
import type { Finding } from "@/lib/api/findings";
import { severityCounts, severityRank, sortBySeverity } from "./severity";

function finding(partial: Partial<Finding> & { id: string; severity: Finding["severity"] }): Finding {
  return {
    title: partial.title ?? partial.id,
    summary: "",
    category: "cat",
    confidence: 0.5,
    status: "potential",
    evidence: [],
    ...partial,
  } as Finding;
}

describe("severity helpers", () => {
  it("ranks more severe findings lower (earlier)", () => {
    expect(severityRank("critical")).toBeLessThan(severityRank("low"));
    expect(severityRank("nonsense")).toBeGreaterThanOrEqual(severityRank("unknown"));
  });

  it("sorts by severity descending", () => {
    const sorted = sortBySeverity([
      finding({ id: "a", severity: "low" }),
      finding({ id: "b", severity: "critical" }),
      finding({ id: "c", severity: "medium" }),
    ]);
    expect(sorted.map((f) => f.severity)).toEqual(["critical", "medium", "low"]);
  });

  it("counts per severity in order, omitting zeros", () => {
    const counts = severityCounts([
      finding({ id: "a", severity: "high" }),
      finding({ id: "b", severity: "high" }),
      finding({ id: "c", severity: "low" }),
    ]);
    expect(counts).toEqual([
      { severity: "high", count: 2 },
      { severity: "low", count: 1 },
    ]);
  });
});

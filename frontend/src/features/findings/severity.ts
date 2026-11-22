import type { Finding, FindingSeverity, FindingStatus } from "@/lib/api/findings";

/** Severity order, most severe first — used for sorting and summary tiles. */
export const SEVERITY_ORDER: FindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
  "unknown",
];

const SEVERITY_RANK = new Map(SEVERITY_ORDER.map((value, index) => [value, index]));

export function severityRank(severity: string): number {
  return SEVERITY_RANK.get(severity as FindingSeverity) ?? SEVERITY_ORDER.length;
}

/** Sort findings by severity (desc), then title for stable ordering. */
export function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    return bySeverity !== 0 ? bySeverity : a.title.localeCompare(b.title);
  });
}

/** Count findings per severity, in severity order. */
export function severityCounts(findings: Finding[]): { severity: FindingSeverity; count: number }[] {
  const counts = new Map<FindingSeverity, number>();
  for (const finding of findings) {
    const key = (SEVERITY_RANK.has(finding.severity as FindingSeverity)
      ? finding.severity
      : "unknown") as FindingSeverity;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return SEVERITY_ORDER.map((severity) => ({ severity, count: counts.get(severity) ?? 0 })).filter(
    (entry) => entry.count > 0,
  );
}

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  confirmed: "Confirmed",
  potential: "Potential",
  not_reproduced: "Not reproduced",
  inconclusive: "Inconclusive",
  not_tested: "Not tested",
};

export function findingStatusLabel(status: string): string {
  return FINDING_STATUS_LABELS[status as FindingStatus] ?? status;
}

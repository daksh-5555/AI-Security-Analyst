/** Centralized query keys so invalidation stays consistent across features. */
export const queryKeys = {
  health: ["health"] as const,
  assessments: {
    all: ["assessments"] as const,
    list: (params: Record<string, unknown>) => ["assessments", "list", params] as const,
    detail: (id: string) => ["assessments", "detail", id] as const,
    history: (id: string) => ["assessments", "detail", id, "history"] as const,
    runs: (id: string) => ["assessments", "detail", id, "runs"] as const,
    repository: (id: string) => ["assessments", "detail", id, "repository"] as const,
    findings: (id: string, params: Record<string, unknown>) =>
      ["assessments", "detail", id, "findings", params] as const,
    explanations: (id: string, findingId: string) =>
      ["assessments", "detail", id, "findings", findingId, "explanations"] as const,
    targets: (id: string) => ["assessments", "detail", id, "targets"] as const,
    attackSurface: (id: string, source: string) =>
      ["assessments", "detail", id, "attack-surface", source] as const,
    reportJson: (id: string, params: Record<string, unknown>) =>
      ["assessments", "detail", id, "report", "json", params] as const,
    reportHtml: (id: string, params: Record<string, unknown>) =>
      ["assessments", "detail", id, "report", "html", params] as const,
    workflows: (id: string) => ["assessments", "detail", id, "workflows"] as const,
    workflow: (id: string, workflowId: string) =>
      ["assessments", "detail", id, "workflows", workflowId] as const,
    evidence: (id: string, params: Record<string, unknown>) =>
      ["assessments", "detail", id, "evidence", params] as const,
  },
  knowledge: { base: ["knowledge"] as const },
  audit: {
    events: (params: Record<string, unknown>) => ["audit", "events", params] as const,
    denialPatterns: (params: Record<string, unknown>) =>
      ["admin", "denial-patterns", params] as const,
  },
} as const;

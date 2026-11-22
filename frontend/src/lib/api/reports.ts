/**
 * Report hooks. The backend produces a canonical JSON report and a canonical HTML
 * document (M12). The JSON report is intentionally free-form in the OpenAPI spec,
 * so it is typed loosely here and every field is read defensively. Nothing is
 * fabricated — the page only shows what the report actually contains.
 */
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { apiRequest } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

/** The subset of the free-form JSON report this app reads. All optional. */
export interface JsonReport {
  schema_version?: string;
  generator?: { name?: string; version?: string };
  assessment?: { id?: string; type?: string; status?: string; created_at?: string };
  run?: { id?: string; status?: string; completed_at?: string | null } | null;
  executive_summary?: string[];
  counts?: {
    total?: number;
    by_severity?: Record<string, number>;
    by_status?: Record<string, number>;
  };
  findings?: Array<{ id?: string; title?: string; severity?: string; status?: string; summary?: string }>;
  findings_omitted?: number;
  checks_not_run?: unknown[];
  limitations?: unknown[];
  advisories?: unknown[];
}

const BASE = "/api/v1/assessments";

function runQuery(analysisRunId?: string | null) {
  return analysisRunId ? { analysis_run_id: analysisRunId } : undefined;
}

export function useReportJsonQuery(
  assessmentId: string,
  analysisRunId?: string | null,
): UseQueryResult<JsonReport> {
  const params = { analysis_run_id: analysisRunId ?? null };
  return useQuery({
    queryKey: queryKeys.assessments.reportJson(assessmentId, params),
    enabled: Boolean(assessmentId),
    retry: false,
    queryFn: () =>
      apiRequest<JsonReport>(`${BASE}/${assessmentId}/reports/json`, {
        query: runQuery(analysisRunId),
      }),
  });
}

export function useReportHtmlQuery(
  assessmentId: string,
  analysisRunId?: string | null,
): UseQueryResult<string> {
  const params = { analysis_run_id: analysisRunId ?? null };
  return useQuery({
    queryKey: queryKeys.assessments.reportHtml(assessmentId, params),
    enabled: Boolean(assessmentId),
    retry: false,
    queryFn: () =>
      apiRequest<string>(`${BASE}/${assessmentId}/reports/html`, {
        query: runQuery(analysisRunId),
        headers: { Accept: "text/html" },
        responseType: "text",
      }),
  });
}

/** Trigger a client-side download of already-fetched report content. */
export function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

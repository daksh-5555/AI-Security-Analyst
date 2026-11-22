/**
 * Typed hook for the per-assessment evidence browser. The list returns full
 * evidence items (already redacted by the backend — only allowlisted request and
 * response summary keys, never raw bodies or secrets), so the detail view reads
 * from the list rather than refetching.
 */
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { apiRequest, type Schema } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export type EvidenceItem = Schema<"EvidenceItemRead">;

const BASE = "/api/v1/assessments";

export interface EvidenceFilter {
  analysisRunId?: string | null;
  limit: number;
  offset: number;
}

export function useEvidenceQuery(
  assessmentId: string,
  filter: EvidenceFilter,
): UseQueryResult<EvidenceItem[]> {
  const params = {
    analysis_run_id: filter.analysisRunId ?? null,
    limit: filter.limit,
    offset: filter.offset,
  };
  return useQuery({
    queryKey: queryKeys.assessments.evidence(assessmentId, params),
    enabled: Boolean(assessmentId),
    queryFn: () =>
      apiRequest<EvidenceItem[]>(`${BASE}/${assessmentId}/evidence`, {
        query: {
          limit: filter.limit,
          offset: filter.offset,
          ...(filter.analysisRunId ? { analysis_run_id: filter.analysisRunId } : {}),
        },
      }),
  });
}

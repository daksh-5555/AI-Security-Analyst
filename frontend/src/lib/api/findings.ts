/**
 * Typed hooks for findings and their advisory AI explanations. Findings are
 * per-assessment and come straight from deterministic analysis — severity, status
 * and confidence are authoritative. AI explanations are advisory only and never
 * change those values; generating one is an explicit, user-initiated action.
 */
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { apiRequest, type Schema } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export type Finding = Schema<"FindingRead">;
export type FindingSeverity = Schema<"FindingSeverity">;
export type FindingStatus = Schema<"FindingStatus">;
export type FindingExplanation = Schema<"FindingExplanationRead">;
export type EmbeddedEvidence = Schema<"EvidenceRead">;

const BASE = "/api/v1/assessments";

export interface FindingsFilter {
  analysisRunId?: string | null;
}

export function useFindingsQuery(
  assessmentId: string,
  filter: FindingsFilter = {},
): UseQueryResult<Finding[]> {
  const params = { analysis_run_id: filter.analysisRunId ?? null };
  return useQuery({
    queryKey: queryKeys.assessments.findings(assessmentId, params),
    enabled: Boolean(assessmentId),
    queryFn: () =>
      apiRequest<Finding[]>(`${BASE}/${assessmentId}/findings`, {
        query: filter.analysisRunId ? { analysis_run_id: filter.analysisRunId } : undefined,
      }),
  });
}

export function useFindingExplanationsQuery(
  assessmentId: string,
  findingId: string,
  enabled = true,
): UseQueryResult<FindingExplanation[]> {
  return useQuery({
    queryKey: queryKeys.assessments.explanations(assessmentId, findingId),
    enabled: enabled && Boolean(assessmentId) && Boolean(findingId),
    queryFn: () =>
      apiRequest<FindingExplanation[]>(
        `${BASE}/${assessmentId}/findings/${findingId}/explanations`,
      ),
  });
}

export function useGenerateExplanation(assessmentId: string, findingId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<FindingExplanation>(
        `${BASE}/${assessmentId}/findings/${findingId}/explanations`,
        { method: "POST" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.assessments.explanations(assessmentId, findingId),
      });
    },
  });
}

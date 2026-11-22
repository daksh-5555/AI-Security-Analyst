/**
 * Typed hooks for the attack-surface vertical: authorized targets (register,
 * authorize, revoke) and the per-assessment attack-surface summary. Target
 * authorization is a security-sensitive, explicitly-confirmed action — the UI
 * always carries the operator's authorization statement and confirmation, exactly
 * as the backend requires.
 */
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { apiRequest, type Schema } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export type Target = Schema<"AssessmentTargetRead">;
export type TargetStatus = Schema<"TargetStatus">;
export type WebTargetCreate = Schema<"WebTargetCreate">;
export type TargetAuthorizationRequest = Schema<"TargetAuthorizationRequest">;
export type AttackSurfaceSummary = Schema<"AttackSurfaceSummaryResponse">;
export type AttackSurfaceMetrics = Schema<"AttackSurfaceSummaryMetrics">;
export type AttackSurfaceRoute = Schema<"AttackSurfaceRouteSummary">;
export type AttackSurfaceIssue = Schema<"SummaryIssue">;

export type SummarySource = "live" | "persisted";

const BASE = "/api/v1/assessments";

export function useTargetsQuery(assessmentId: string): UseQueryResult<Target[]> {
  return useQuery({
    queryKey: queryKeys.assessments.targets(assessmentId),
    enabled: Boolean(assessmentId),
    queryFn: () => apiRequest<Target[]>(`${BASE}/${assessmentId}/targets`),
  });
}

export function useAttackSurfaceSummaryQuery(
  assessmentId: string,
  source: SummarySource,
): UseQueryResult<AttackSurfaceSummary> {
  return useQuery({
    queryKey: queryKeys.assessments.attackSurface(assessmentId, source),
    enabled: Boolean(assessmentId),
    retry: false,
    queryFn: () =>
      apiRequest<AttackSurfaceSummary>(`${BASE}/${assessmentId}/attack-surface/summary`, {
        query: { source },
      }),
  });
}

function useTargetsInvalidation(assessmentId: string) {
  const queryClient = useQueryClient();
  return () =>
    void queryClient.invalidateQueries({ queryKey: queryKeys.assessments.targets(assessmentId) });
}

export function useRegisterWebTarget(assessmentId: string) {
  const invalidate = useTargetsInvalidation(assessmentId);
  return useMutation({
    mutationFn: (body: WebTargetCreate) =>
      apiRequest<Target>(`${BASE}/${assessmentId}/web-target`, { method: "POST", body }),
    onSuccess: invalidate,
  });
}

export function useAuthorizeTarget(assessmentId: string) {
  const invalidate = useTargetsInvalidation(assessmentId);
  return useMutation({
    mutationFn: ({ targetId, body }: { targetId: string; body: TargetAuthorizationRequest }) =>
      apiRequest<Target>(`${BASE}/${assessmentId}/targets/${targetId}/authorize`, {
        method: "POST",
        body,
      }),
    onSuccess: invalidate,
  });
}

export function useRevokeTarget(assessmentId: string) {
  const invalidate = useTargetsInvalidation(assessmentId);
  return useMutation({
    mutationFn: (targetId: string) =>
      apiRequest<Target>(`${BASE}/${assessmentId}/targets/${targetId}/revoke`, { method: "POST" }),
    onSuccess: invalidate,
  });
}

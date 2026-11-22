/**
 * Typed TanStack Query hooks for the Assessments vertical. Every shape comes from
 * the generated OpenAPI schema; nothing is invented. Runs are polled (no
 * WebSocket) while any run is still in flight. The backend remains the
 * authoritative authorization boundary — these hooks only read and act on what the
 * caller is already allowed to.
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from "@tanstack/react-query";
import { ApiError, apiRequest, type Schema } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export type Assessment = Schema<"AssessmentRead">;
export type AssessmentCreate = Schema<"AssessmentCreate">;
export type AssessmentType = Schema<"AssessmentType">;
export type StatusHistoryEntry = Schema<"AssessmentStatusHistoryRead">;
export type AnalysisRun = Schema<"AnalysisRunRead">;
export type AnalysisRunCreated = Schema<"AnalysisRunCreated">;
export type RepositoryTarget = Schema<"RepositoryTargetRead">;
export type RepositorySourceCreate = Schema<"RepositorySourceCreate">;

const BASE = "/api/v1/assessments";

/** Run states that are still progressing and therefore worth polling. */
const ACTIVE_RUN_STATUSES = new Set(["queued", "running"]);

export interface AssessmentListParams {
  limit: number;
  offset: number;
}

export function useAssessmentsQuery(
  params: AssessmentListParams,
): UseQueryResult<Assessment[]> {
  return useQuery({
    queryKey: queryKeys.assessments.list({ limit: params.limit, offset: params.offset }),
    queryFn: () =>
      apiRequest<Assessment[]>(BASE, {
        query: { limit: params.limit, offset: params.offset },
      }),
  });
}

export function useAssessmentQuery(id: string): UseQueryResult<Assessment> {
  return useQuery({
    queryKey: queryKeys.assessments.detail(id),
    queryFn: () => apiRequest<Assessment>(`${BASE}/${id}`),
    enabled: Boolean(id),
  });
}

export function useAssessmentHistoryQuery(id: string): UseQueryResult<StatusHistoryEntry[]> {
  return useQuery({
    queryKey: queryKeys.assessments.history(id),
    queryFn: () => apiRequest<StatusHistoryEntry[]>(`${BASE}/${id}/history`),
    enabled: Boolean(id),
  });
}

/** Analysis runs, polled every 4s while any run is queued or running. */
export function useAnalysisRunsQuery(id: string): UseQueryResult<AnalysisRun[]> {
  return useQuery({
    queryKey: queryKeys.assessments.runs(id),
    queryFn: () => apiRequest<AnalysisRun[]>(`${BASE}/${id}/analysis-runs`),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const runs = query.state.data as AnalysisRun[] | undefined;
      const active = runs?.some((run) => ACTIVE_RUN_STATUSES.has(run.status));
      return active ? 4000 : false;
    },
  });
}

export function useRepositoryTargetQuery(id: string): UseQueryResult<RepositoryTarget | null> {
  return useQuery({
    queryKey: queryKeys.assessments.repository(id),
    enabled: Boolean(id),
    // A repository assessment starts unconfigured: the backend returns 404 until a
    // source is set, which we normalize to "no target yet" rather than an error.
    queryFn: async () => {
      try {
        return await apiRequest<RepositoryTarget>(`${BASE}/${id}/repository`);
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
  });
}

export function useCreateAssessment() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: AssessmentCreate) =>
      apiRequest<Assessment>(BASE, { method: "POST", body }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.assessments.all });
    },
  });
}

export function useConfigureRepository(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: RepositorySourceCreate) =>
      apiRequest<RepositoryTarget>(`${BASE}/${id}/repository`, { method: "POST", body }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.assessments.repository(id) });
    },
  });
}

export function useStartAnalysisRun(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    // async: queue for the background worker and poll, per the no-WebSocket design.
    mutationFn: () =>
      apiRequest<AnalysisRunCreated>(`${BASE}/${id}/analysis-runs`, {
        method: "POST",
        query: { mode: "async" },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.assessments.runs(id) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.assessments.detail(id) });
    },
  });
}

export function useCancelAnalysisRun(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (runId: string) =>
      apiRequest<AnalysisRun>(`${BASE}/${id}/analysis-runs/${runId}/cancel`, { method: "POST" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.assessments.runs(id) });
    },
  });
}

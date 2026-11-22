/**
 * Typed hooks for the bounded workflow engine. A workflow runs the analysis
 * pipeline with explicit, DB-authoritative state and an approval gate; every
 * lifecycle action (start, approve/deny, cancel, resume) is an explicit,
 * user-initiated state change. Running workflows are polled (no WebSocket).
 */
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { apiRequest, type Schema } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export type Workflow = Schema<"WorkflowRead">;
export type WorkflowDetail = Schema<"WorkflowDetail">;
export type WorkflowCreate = Schema<"WorkflowCreate">;
export type WorkflowApproval = Schema<"WorkflowApproval">;
export type WorkflowStatus = Schema<"WorkflowStatus">;
export type WorkflowEvent = Schema<"WorkflowEventRead">;

const BASE = "/api/v1/assessments";

/** Statuses that are still progressing and therefore worth polling. */
const ACTIVE_STATUSES = new Set<string>(["running", "awaiting_approval"]);

export function useWorkflowsQuery(assessmentId: string): UseQueryResult<Workflow[]> {
  return useQuery({
    queryKey: queryKeys.assessments.workflows(assessmentId),
    enabled: Boolean(assessmentId),
    queryFn: () => apiRequest<Workflow[]>(`${BASE}/${assessmentId}/workflows`),
    refetchInterval: (query) => {
      const data = query.state.data as Workflow[] | undefined;
      return data?.some((workflow) => ACTIVE_STATUSES.has(workflow.status)) ? 4000 : false;
    },
  });
}

export function useWorkflowQuery(
  assessmentId: string,
  workflowId: string,
): UseQueryResult<WorkflowDetail> {
  return useQuery({
    queryKey: queryKeys.assessments.workflow(assessmentId, workflowId),
    enabled: Boolean(assessmentId) && Boolean(workflowId),
    queryFn: () =>
      apiRequest<WorkflowDetail>(`${BASE}/${assessmentId}/workflows/${workflowId}`),
    refetchInterval: (query) => {
      const data = query.state.data as WorkflowDetail | undefined;
      return data && ACTIVE_STATUSES.has(data.status) ? 4000 : false;
    },
  });
}

function useWorkflowInvalidation(assessmentId: string, workflowId?: string) {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.assessments.workflows(assessmentId) });
    if (workflowId) {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.assessments.workflow(assessmentId, workflowId),
      });
    }
  };
}

export function useStartWorkflow(assessmentId: string) {
  const invalidate = useWorkflowInvalidation(assessmentId);
  return useMutation({
    mutationFn: (body: WorkflowCreate) =>
      apiRequest<WorkflowDetail>(`${BASE}/${assessmentId}/workflows`, { method: "POST", body }),
    onSuccess: invalidate,
  });
}

export function useDecideApproval(assessmentId: string, workflowId: string) {
  const invalidate = useWorkflowInvalidation(assessmentId, workflowId);
  return useMutation({
    mutationFn: (body: WorkflowApproval) =>
      apiRequest<WorkflowDetail>(`${BASE}/${assessmentId}/workflows/${workflowId}/approvals`, {
        method: "POST",
        body,
      }),
    onSuccess: invalidate,
  });
}

export function useCancelWorkflow(assessmentId: string, workflowId: string) {
  const invalidate = useWorkflowInvalidation(assessmentId, workflowId);
  return useMutation({
    mutationFn: () =>
      apiRequest<WorkflowDetail>(`${BASE}/${assessmentId}/workflows/${workflowId}/cancel`, {
        method: "POST",
      }),
    onSuccess: invalidate,
  });
}

export function useResumeWorkflow(assessmentId: string, workflowId: string) {
  const invalidate = useWorkflowInvalidation(assessmentId, workflowId);
  return useMutation({
    mutationFn: () =>
      apiRequest<WorkflowDetail>(`${BASE}/${assessmentId}/workflows/${workflowId}/resume`, {
        method: "POST",
      }),
    onSuccess: invalidate,
  });
}

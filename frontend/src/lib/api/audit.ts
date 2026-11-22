/**
 * Typed hook for the admin audit trail. This is an admin-only endpoint: a caller
 * without the role receives 403, which the page surfaces as an access-denied
 * state. The backend is the authoritative boundary; the sidebar only hides the
 * link as a convenience.
 */
import { keepPreviousData, useQuery, type UseQueryResult } from "@tanstack/react-query";
import { apiRequest, type Schema } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export type AuditEvent = Schema<"AuditEventRead">;
export type AuditEventPage = Schema<"AuditEventPage">;
export type AuditAction = Schema<"AuditAction">;
export type AuditOutcome = Schema<"AuditOutcome">;

/** All audit actions, for the action filter (mirrors the backend enum). */
export const AUDIT_ACTIONS: AuditAction[] = [
  "assessment.created",
  "assessment.access_denied",
  "assessment.lifecycle_changed",
  "assessment.lifecycle_denied",
  "repository_target.created",
  "analysis_run.queued",
  "analysis_run.started",
  "analysis_run.completed",
  "analysis_run.failed",
  "analysis_run.cancelled",
  "finding_explanation.created",
  "workflow.started",
  "workflow.approval_recorded",
  "workflow.finished",
  "assessment_target.authorized",
  "assessment_target.revoked",
  "web_target.lab_session_established",
  "web_target.lab_session_cleared",
];

export const AUDIT_OUTCOMES: AuditOutcome[] = ["success", "failure", "denied"];

export interface AuditFilter {
  action?: AuditAction | "";
  outcome?: AuditOutcome | "";
  assessmentId?: string;
  limit: number;
  offset: number;
}

export function useAuditEventsQuery(filter: AuditFilter): UseQueryResult<AuditEventPage> {
  const query: Record<string, string | number> = {
    limit: filter.limit,
    offset: filter.offset,
  };
  if (filter.action) query.action = filter.action;
  if (filter.outcome) query.outcome = filter.outcome;
  if (filter.assessmentId) query.assessment_id = filter.assessmentId;

  return useQuery({
    queryKey: queryKeys.audit.events(query),
    queryFn: () => apiRequest<AuditEventPage>("/api/v1/admin/audit-events", { query }),
    // Keep the previous page visible while the next loads, for smoother paging.
    placeholderData: keepPreviousData,
  });
}

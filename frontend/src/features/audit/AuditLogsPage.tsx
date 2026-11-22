import { useState } from "react";
import { ChevronLeft, ChevronRight, ScrollText } from "lucide-react";
import { Link } from "react-router-dom";
import {
  AUDIT_ACTIONS,
  AUDIT_OUTCOMES,
  useAuditEventsQuery,
  type AuditAction,
  type AuditOutcome,
} from "@/lib/api/audit";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { cn } from "@/lib/utils";
import { formatDateTime, shortId } from "@/lib/format";

const PAGE_SIZE = 25;
const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

const OUTCOME_STYLES: Record<string, string> = {
  success: "bg-emerald/15 text-emerald",
  failure: "bg-destructive/15 text-destructive",
  denied: "bg-severity-medium/15 text-severity-medium",
};

function OutcomeBadge({ outcome }: { outcome: string }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium", OUTCOME_STYLES[outcome] ?? "bg-muted text-muted-foreground")}>
      {outcome}
    </span>
  );
}

export function AuditLogsPage() {
  const [action, setAction] = useState<AuditAction | "">("");
  const [outcome, setOutcome] = useState<AuditOutcome | "">("");
  const [assessmentId, setAssessmentId] = useState("");
  const [page, setPage] = useState(0);

  const query = useAuditEventsQuery({
    action,
    outcome,
    assessmentId: assessmentId.trim() || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const data = query.data;
  const events = data?.items ?? [];
  const total = data?.total ?? 0;
  const canPrev = page > 0;
  const canNext = (page + 1) * PAGE_SIZE < total;

  const resetTo = (apply: () => void) => {
    apply();
    setPage(0);
  };

  return (
    <div>
      <PageHeader
        title="Audit Logs"
        description="Security-relevant events recorded by the backend. Admin access only."
      />

      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <Label htmlFor="audit-outcome" className="text-xs text-muted-foreground">Outcome</Label>
          <select
            id="audit-outcome"
            className={SELECT_CLASS}
            value={outcome}
            onChange={(event) => resetTo(() => setOutcome(event.target.value as AuditOutcome | ""))}
          >
            <option value="">All outcomes</option>
            {AUDIT_OUTCOMES.map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="audit-action" className="text-xs text-muted-foreground">Action</Label>
          <select
            id="audit-action"
            className={cn(SELECT_CLASS, "max-w-[220px]")}
            value={action}
            onChange={(event) => resetTo(() => setAction(event.target.value as AuditAction | ""))}
          >
            <option value="">All actions</option>
            {AUDIT_ACTIONS.map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="audit-assessment" className="text-xs text-muted-foreground">Assessment ID</Label>
          <Input
            id="audit-assessment"
            value={assessmentId}
            onChange={(event) => resetTo(() => setAssessmentId(event.target.value))}
            placeholder="optional"
            className="h-9 w-[220px]"
          />
        </div>
      </div>

      {query.isLoading ? (
        <LoadingRows rows={8} />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : events.length === 0 ? (
        <EmptyState icon={ScrollText} title="No audit events" description="No events match the current filters." />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5 font-medium">Time</th>
                <th className="px-4 py-2.5 font-medium">Action</th>
                <th className="px-4 py-2.5 font-medium">Outcome</th>
                <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Resource</th>
                <th className="hidden px-4 py-2.5 font-medium md:table-cell">Actor</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id} className="border-t border-border">
                  <td className="whitespace-nowrap px-4 py-2.5 text-muted-foreground">{formatDateTime(event.occurred_at)}</td>
                  <td className="px-4 py-2.5 font-mono text-xs">{event.action}</td>
                  <td className="px-4 py-2.5"><OutcomeBadge outcome={event.outcome} /></td>
                  <td className="hidden px-4 py-2.5 sm:table-cell">
                    <span className="text-muted-foreground">{event.resource_type}</span>
                    {event.assessment_id ? (
                      <>
                        {" "}
                        <Link to={`/assessments/${event.assessment_id}`} className="font-mono text-xs text-primary hover:underline">
                          {shortId(event.assessment_id)}
                        </Link>
                      </>
                    ) : event.resource_id ? (
                      <span className="font-mono text-xs"> {shortId(event.resource_id)}</span>
                    ) : null}
                  </td>
                  <td className="hidden px-4 py-2.5 font-mono text-xs text-muted-foreground md:table-cell">
                    {event.actor_user_id ? shortId(event.actor_user_id) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!query.isError && (canPrev || canNext) ? (
        <div className="mt-4 flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            {total} event{total === 1 ? "" : "s"} · page {page + 1}
          </span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={!canPrev} onClick={() => setPage((v) => Math.max(0, v - 1))}>
              <ChevronLeft />
              Previous
            </Button>
            <Button variant="outline" size="sm" disabled={!canNext} onClick={() => setPage((v) => v + 1)}>
              Next
              <ChevronRight />
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

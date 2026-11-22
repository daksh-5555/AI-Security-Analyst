import { useMemo, useState } from "react";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useAnalysisRunsQuery, useAssessmentQuery } from "@/lib/api/assessments";
import { useFindingsQuery } from "@/lib/api/findings";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { shortId } from "@/lib/format";
import { assessmentTypeLabel } from "@/features/assessments/labels";
import { FindingCard } from "./FindingCard";
import { findingStatusLabel, severityCounts, sortBySeverity } from "./severity";

const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

export function AssessmentFindingsPage() {
  const { id = "" } = useParams();
  const assessment = useAssessmentQuery(id);
  const runs = useAnalysisRunsQuery(id);
  const [runFilter, setRunFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const findings = useFindingsQuery(id, { analysisRunId: runFilter || null });

  const all = useMemo(() => findings.data ?? [], [findings.data]);
  const statuses = useMemo(
    () => Array.from(new Set(all.map((finding) => finding.status))),
    [all],
  );
  const visible = useMemo(() => {
    const filtered = statusFilter ? all.filter((f) => f.status === statusFilter) : all;
    return sortBySeverity(filtered);
  }, [all, statusFilter]);
  const counts = useMemo(() => severityCounts(all), [all]);

  return (
    <div className="space-y-5">
      <div>
        <Button asChild variant="ghost" size="sm" className="mb-2 -ml-2 text-muted-foreground">
          <Link to={`/assessments/${id}`}>
            <ArrowLeft />
            {assessment.data ? `${assessmentTypeLabel(assessment.data.assessment_type)} assessment` : "Assessment"}
          </Link>
        </Button>
        <h2 className="text-xl font-semibold tracking-tight text-foreground">Findings</h2>
      </div>

      {findings.isLoading ? (
        <LoadingRows rows={6} />
      ) : findings.isError ? (
        <ErrorState error={findings.error} onRetry={() => void findings.refetch()} />
      ) : (
        <>
          {counts.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {counts.map(({ severity, count }) => (
                <span key={severity} className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1">
                  <SeverityBadge severity={severity} />
                  <span className="text-sm font-medium">{count}</span>
                </span>
              ))}
            </div>
          ) : null}

          <div className="flex flex-wrap items-end gap-4">
            <div className="space-y-1">
              <Label htmlFor="run-filter" className="text-xs text-muted-foreground">Run</Label>
              <select
                id="run-filter"
                className={SELECT_CLASS}
                value={runFilter}
                onChange={(event) => setRunFilter(event.target.value)}
              >
                <option value="">All runs</option>
                {(runs.data ?? []).map((run) => (
                  <option key={run.id} value={run.id}>
                    {shortId(run.id)} · {run.status}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="status-filter" className="text-xs text-muted-foreground">Status</Label>
              <select
                id="status-filter"
                className={SELECT_CLASS}
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
              >
                <option value="">All statuses</option>
                {statuses.map((status) => (
                  <option key={status} value={status}>
                    {findingStatusLabel(status)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {visible.length === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title={all.length === 0 ? "No findings" : "No findings match the filters"}
              description={
                all.length === 0
                  ? "This assessment has no findings yet. Run an analysis to produce findings."
                  : "Adjust the run or status filter to see more."
              }
            />
          ) : (
            <div className="space-y-2">
              {visible.map((finding) => (
                <FindingCard key={finding.id} assessmentId={id} finding={finding} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

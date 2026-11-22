import { useState } from "react";
import { ArrowLeft, ChevronLeft, ChevronRight, FileSearch } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useAnalysisRunsQuery, useAssessmentQuery } from "@/lib/api/assessments";
import { useEvidenceQuery } from "@/lib/api/evidence";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { shortId } from "@/lib/format";
import { assessmentTypeLabel } from "@/features/assessments/labels";
import { EvidenceCard } from "./EvidenceCard";

const PAGE_SIZE = 25;
const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

export function AssessmentEvidencePage() {
  const { id = "" } = useParams();
  const assessment = useAssessmentQuery(id);
  const runs = useAnalysisRunsQuery(id);
  const [runFilter, setRunFilter] = useState("");
  const [page, setPage] = useState(0);

  const query = useEvidenceQuery(id, {
    analysisRunId: runFilter || null,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });
  const items = query.data ?? [];
  const canPrev = page > 0;
  const canNext = items.length === PAGE_SIZE;

  const onRunChange = (value: string) => {
    setRunFilter(value);
    setPage(0);
  };

  return (
    <div className="space-y-5">
      <div>
        <Button asChild variant="ghost" size="sm" className="mb-2 -ml-2 text-muted-foreground">
          <Link to={`/assessments/${id}`}>
            <ArrowLeft />
            {assessment.data ? `${assessmentTypeLabel(assessment.data.assessment_type)} assessment` : "Assessment"}
          </Link>
        </Button>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 className="text-xl font-semibold tracking-tight text-foreground">Evidence</h2>
          <div className="space-y-1">
            <Label htmlFor="evidence-run" className="text-xs text-muted-foreground">Run</Label>
            <select
              id="evidence-run"
              className={SELECT_CLASS}
              value={runFilter}
              onChange={(event) => onRunChange(event.target.value)}
            >
              <option value="">All runs</option>
              {(runs.data ?? []).map((run) => (
                <option key={run.id} value={run.id}>
                  {shortId(run.id)} · {run.status}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {query.isLoading ? (
        <LoadingRows rows={6} />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={FileSearch}
          title={page === 0 ? "No evidence" : "No more evidence"}
          description={
            page === 0
              ? "This assessment has no evidence yet. Run an analysis to collect evidence."
              : "You have reached the end of the list."
          }
        />
      ) : (
        <div className="space-y-2">
          {items.map((item) => (
            <EvidenceCard key={item.id} item={item} />
          ))}
        </div>
      )}

      {(canPrev || canNext) && !query.isError ? (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">Page {page + 1}</span>
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

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, ClipboardList } from "lucide-react";
import { useAssessmentsQuery } from "@/lib/api/assessments";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button } from "@/components/ui/button";
import { StatusPill } from "@/components/common/StatusPill";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel } from "./labels";
import { CreateAssessmentDialog } from "./CreateAssessmentDialog";

const PAGE_SIZE = 20;

export function AssessmentsPage() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const offset = page * PAGE_SIZE;
  const query = useAssessmentsQuery({ limit: PAGE_SIZE, offset });

  const rows = query.data ?? [];
  const canPrev = page > 0;
  // No total count is exposed, so a full page implies there may be more.
  const canNext = rows.length === PAGE_SIZE;

  const open = (id: string) => navigate(`/assessments/${id}`);

  return (
    <div>
      <PageHeader
        title="Assessments"
        description="Create and track repository and web assessments, and run analysis."
        actions={<CreateAssessmentDialog onCreated={open} />}
      />

      {query.isLoading ? (
        <LoadingRows rows={6} />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title={page === 0 ? "No assessments yet" : "No more assessments"}
          description={
            page === 0
              ? "Create your first assessment to begin analysis."
              : "You have reached the end of the list."
          }
        />
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5 font-medium">Type</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Created</th>
                <th className="hidden px-4 py-2.5 font-medium md:table-cell">Updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((assessment) => (
                <tr
                  key={assessment.id}
                  onClick={() => open(assessment.id)}
                  className="cursor-pointer border-t border-border transition-colors hover:bg-muted/40"
                >
                  <td className="px-4 py-3 font-medium text-foreground">
                    {assessmentTypeLabel(assessment.assessment_type)}
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={assessment.status} />
                  </td>
                  <td className="hidden px-4 py-3 text-muted-foreground sm:table-cell">
                    {formatDateTime(assessment.created_at)}
                  </td>
                  <td className="hidden px-4 py-3 text-muted-foreground md:table-cell">
                    {formatDateTime(assessment.updated_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(canPrev || canNext) && !query.isError ? (
        <div className="mt-4 flex items-center justify-between">
          <span className="text-xs text-muted-foreground">Page {page + 1}</span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!canPrev}
              onClick={() => setPage((value) => Math.max(0, value - 1))}
            >
              <ChevronLeft />
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!canNext}
              onClick={() => setPage((value) => value + 1)}
            >
              Next
              <ChevronRight />
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

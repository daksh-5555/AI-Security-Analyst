import { ChevronRight, ClipboardList, FileText } from "lucide-react";
import { Link } from "react-router-dom";
import { useAssessmentsQuery } from "@/lib/api/assessments";
import { PageHeader } from "@/components/layout/PageHeader";
import { StatusPill } from "@/components/common/StatusPill";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel } from "@/features/assessments/labels";

export function ReportsPage() {
  // Reports are per-assessment, so this is an honest assessment picker.
  const query = useAssessmentsQuery({ limit: 20, offset: 0 });
  const rows = query.data ?? [];

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Choose an assessment to view and download its report."
      />

      {query.isLoading ? (
        <LoadingRows rows={6} />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title="No assessments yet"
          description="Create an assessment and run analysis to produce a report."
        />
      ) : (
        <div className="space-y-2">
          {rows.map((assessment) => (
            <Link
              key={assessment.id}
              to={`/assessments/${assessment.id}/report`}
              className="flex items-center gap-3 rounded-lg border border-border px-4 py-3 transition-colors hover:bg-muted/40"
            >
              <FileText className="size-4 shrink-0 text-muted-foreground" />
              <span className="min-w-0 flex-1">
                <span className="block font-medium text-foreground">
                  {assessmentTypeLabel(assessment.assessment_type)} assessment
                </span>
                <span className="block text-xs text-muted-foreground">
                  Updated {formatDateTime(assessment.updated_at)}
                </span>
              </span>
              <StatusPill status={assessment.status} />
              <ChevronRight className="size-4 shrink-0 text-muted-foreground" />
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

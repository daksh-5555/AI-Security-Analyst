import { useState } from "react";
import { ArrowLeft, ChevronRight, GitBranch, Loader2, Play } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "@/lib/api/client";
import { useAssessmentQuery } from "@/lib/api/assessments";
import { useStartWorkflow, useWorkflowsQuery } from "@/lib/api/workflows";
import { Button } from "@/components/ui/button";
import { StatusPill } from "@/components/common/StatusPill";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { formatDateTime, shortId } from "@/lib/format";
import { assessmentTypeLabel } from "@/features/assessments/labels";

export function WorkflowsPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const assessment = useAssessmentQuery(id);
  const query = useWorkflowsQuery(id);
  const start = useStartWorkflow(id);
  const [explain, setExplain] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const workflows = query.data ?? [];

  const onStart = async () => {
    setError(null);
    try {
      const created = await start.mutateAsync({ explain_findings: explain });
      navigate(`/assessments/${id}/workflows/${created.id}`);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "Unable to start the workflow.");
    }
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
          <h2 className="text-xl font-semibold tracking-tight text-foreground">Workflows</h2>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-sm text-muted-foreground">
              <input
                type="checkbox"
                checked={explain}
                onChange={(event) => setExplain(event.target.checked)}
                disabled={start.isPending}
                className="size-4 rounded border-input accent-primary"
              />
              AI explanations
            </label>
            <Button size="sm" onClick={() => void onStart()} disabled={start.isPending}>
              {start.isPending ? <Loader2 className="animate-spin" /> : <Play />}
              Start workflow
            </Button>
          </div>
        </div>
      </div>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      {query.isLoading ? (
        <LoadingRows rows={4} />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : workflows.length === 0 ? (
        <EmptyState
          icon={GitBranch}
          title="No workflows"
          description="Start a workflow to run the analysis pipeline with an approval gate."
        />
      ) : (
        <div className="space-y-2">
          {workflows.map((workflow) => (
            <Link
              key={workflow.id}
              to={`/assessments/${id}/workflows/${workflow.id}`}
              className="flex items-center gap-3 rounded-lg border border-border px-4 py-3 transition-colors hover:bg-muted/40"
            >
              <GitBranch className="size-4 shrink-0 text-muted-foreground" />
              <span className="min-w-0 flex-1 space-y-1">
                <span className="flex items-center gap-2">
                  <StatusPill status={workflow.status} />
                  <span className="font-mono text-xs text-muted-foreground">{shortId(workflow.id)}</span>
                </span>
                <span className="block text-xs text-muted-foreground">
                  {workflow.current_node} · step {workflow.step_count}/{workflow.max_steps} · {formatDateTime(workflow.created_at)}
                </span>
              </span>
              <ChevronRight className="size-4 shrink-0 text-muted-foreground" />
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

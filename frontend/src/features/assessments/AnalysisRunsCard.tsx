import { useState } from "react";
import { Loader2, Play, RefreshCw } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import {
  useAnalysisRunsQuery,
  useCancelAnalysisRun,
  useStartAnalysisRun,
  type AnalysisRun,
} from "@/lib/api/assessments";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusPill } from "@/components/common/StatusPill";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { formatDateTime, shortId } from "@/lib/format";

const ACTIVE = new Set(["queued", "running"]);

interface AnalysisRunsCardProps {
  assessmentId: string;
  canStart: boolean;
  startHint?: string;
}

export function AnalysisRunsCard({ assessmentId, canStart, startHint }: AnalysisRunsCardProps) {
  const query = useAnalysisRunsQuery(assessmentId);
  const start = useStartAnalysisRun(assessmentId);
  const cancel = useCancelAnalysisRun(assessmentId);
  const [error, setError] = useState<string | null>(null);

  const runs = query.data ?? [];
  const polling = runs.some((run) => ACTIVE.has(run.status));

  const onStart = async () => {
    setError(null);
    try {
      await start.mutateAsync();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "Unable to start the run.");
    }
  };

  const onCancel = async (run: AnalysisRun) => {
    setError(null);
    try {
      await cancel.mutateAsync(run.id);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "Unable to cancel the run.");
    }
  };

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            Analysis runs
            {polling ? (
              <span className="inline-flex items-center gap-1 text-xs font-normal text-cyan">
                <RefreshCw className="size-3 animate-spin" />
                live
              </span>
            ) : null}
          </CardTitle>
          <CardDescription>Queue a background analysis run and track its progress.</CardDescription>
        </div>
        <Button size="sm" onClick={() => void onStart()} disabled={!canStart || start.isPending}>
          {start.isPending ? <Loader2 className="animate-spin" /> : <Play />}
          Start run
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {!canStart && startHint ? (
          <p className="text-xs text-muted-foreground">{startHint}</p>
        ) : null}
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}

        {query.isLoading ? (
          <LoadingRows rows={3} />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : runs.length === 0 ? (
          <EmptyState
            icon={Play}
            title="No runs yet"
            description="Start a run to analyze this assessment."
          />
        ) : (
          <ul className="divide-y divide-border">
            {runs.map((run) => (
              <li key={run.id} className="flex items-center justify-between gap-3 py-3">
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2">
                    <StatusPill status={run.status} />
                    <span className="font-mono text-xs text-muted-foreground">{shortId(run.id)}</span>
                    {run.stage ? (
                      <span className="text-xs text-muted-foreground">· {run.stage}</span>
                    ) : null}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Started {formatDateTime(run.started_at)}
                    {run.completed_at ? ` · finished ${formatDateTime(run.completed_at)}` : ""}
                    {` · ${run.findings_count} finding${run.findings_count === 1 ? "" : "s"}`}
                    {run.attempts > 1 ? ` · attempt ${run.attempts}` : ""}
                  </p>
                  {run.error_message ? (
                    <p className="text-xs text-destructive">{run.error_message}</p>
                  ) : null}
                </div>
                {ACTIVE.has(run.status) ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void onCancel(run)}
                    disabled={cancel.isPending || Boolean(run.cancel_requested_at)}
                  >
                    {run.cancel_requested_at ? "Cancelling…" : "Cancel"}
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

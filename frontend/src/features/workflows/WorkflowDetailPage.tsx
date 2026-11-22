import { useState } from "react";
import { ArrowLeft, RefreshCw } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "@/lib/api/client";
import {
  useCancelWorkflow,
  useDecideApproval,
  useResumeWorkflow,
  useWorkflowQuery,
  type WorkflowApproval,
  type WorkflowDetail,
} from "@/lib/api/workflows";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusPill } from "@/components/common/StatusPill";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingCards } from "@/components/states/LoadingState";
import { formatDateTime, shortId } from "@/lib/format";

const ACTIVE = new Set<string>(["running", "awaiting_approval"]);
const RESUMABLE = new Set<string>(["failed", "cancelled"]);

function ApprovalGate({
  assessmentId,
  workflowId,
  pending,
}: {
  assessmentId: string;
  workflowId: string;
  pending: string[];
}) {
  const decide = useDecideApproval(assessmentId, workflowId);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const onDecide = async (check: string, decision: WorkflowApproval["decision"]) => {
    setError(null);
    if (!reason.trim()) {
      setError("Enter a reason for your decision.");
      return;
    }
    try {
      await decide.mutateAsync({
        check: check as WorkflowApproval["check"],
        decision,
        reason: reason.trim(),
      });
      setReason("");
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "Unable to record the decision.");
    }
  };

  return (
    <Card className="border-violet/40 bg-violet/5">
      <CardHeader>
        <CardTitle className="text-base">Approval required</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">
          This workflow is paused awaiting a decision on: {pending.join(", ")}.
        </p>
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          disabled={decide.isPending}
          rows={2}
          placeholder="Reason for approving or denying…"
          className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
        {pending.map((check) => (
          <div key={check} className="flex items-center gap-2">
            <span className="flex-1 font-mono text-xs text-muted-foreground">{check}</span>
            <Button size="sm" onClick={() => void onDecide(check, "approve")} disabled={decide.isPending}>
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => void onDecide(check, "deny")}
              disabled={decide.isPending}
            >
              Deny
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function EventsTimeline({ workflow }: { workflow: WorkflowDetail }) {
  const events = [...(workflow.events ?? [])].sort((a, b) => a.sequence - b.sequence);
  if (events.length === 0) {
    return <p className="text-sm text-muted-foreground">No events recorded yet.</p>;
  }
  return (
    <ol className="space-y-3">
      {events.map((event) => (
        <li key={event.sequence} className="flex items-start gap-3 text-sm">
          <span className="mt-1 size-1.5 shrink-0 rounded-full bg-border" aria-hidden />
          <div>
            <p>
              <span className="font-mono text-xs">{event.node}</span> —{" "}
              <span className="text-muted-foreground">{event.outcome}</span>
            </p>
            <p className="text-xs text-muted-foreground">
              {formatDateTime(event.occurred_at)}
              {event.attempt > 1 ? ` · attempt ${event.attempt}` : ""}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function WorkflowDetailPage() {
  const { id = "", workflowId = "" } = useParams();
  const query = useWorkflowQuery(id, workflowId);
  const cancel = useCancelWorkflow(id, workflowId);
  const resume = useResumeWorkflow(id, workflowId);
  const [error, setError] = useState<string | null>(null);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "The action could not be completed.");
    }
  };

  const backLink = (
    <Button asChild variant="ghost" size="sm" className="mb-2 -ml-2 text-muted-foreground">
      <Link to={`/assessments/${id}/workflows`}>
        <ArrowLeft />
        Workflows
      </Link>
    </Button>
  );

  if (query.isLoading) {
    return (
      <div>
        {backLink}
        <LoadingCards count={3} />
      </div>
    );
  }
  if (query.isError || !query.data) {
    return (
      <div>
        {backLink}
        <ErrorState error={query.error} title="Workflow unavailable" onRetry={() => void query.refetch()} />
      </div>
    );
  }

  const workflow = query.data;
  const isActive = ACTIVE.has(workflow.status);
  const isResumable = RESUMABLE.has(workflow.status);

  return (
    <div className="space-y-5">
      <div>
        {backLink}
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-xl font-semibold tracking-tight text-foreground">Workflow</h2>
          <StatusPill status={workflow.status} />
          {isActive ? (
            <span className="inline-flex items-center gap-1 text-xs text-cyan">
              <RefreshCw className="size-3 animate-spin" />
              live
            </span>
          ) : null}
          <span className="font-mono text-xs text-muted-foreground">{shortId(workflow.id)}</span>
          <div className="ml-auto flex gap-2">
            {isActive ? (
              <Button variant="outline" size="sm" onClick={() => void act(() => cancel.mutateAsync())} disabled={cancel.isPending}>
                Cancel
              </Button>
            ) : null}
            {isResumable ? (
              <Button variant="outline" size="sm" onClick={() => void act(() => resume.mutateAsync())} disabled={resume.isPending}>
                Resume
              </Button>
            ) : null}
          </div>
        </div>
      </div>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      {workflow.status === "awaiting_approval" && workflow.pending_approvals.length > 0 ? (
        <ApprovalGate assessmentId={id} workflowId={workflowId} pending={workflow.pending_approvals} />
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Progress</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[auto,1fr] gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto,1fr,auto,1fr]">
            <dt className="text-muted-foreground">Current node</dt>
            <dd className="font-mono text-xs">{workflow.current_node}</dd>
            <dt className="text-muted-foreground">Steps</dt>
            <dd>{workflow.step_count} / {workflow.max_steps}</dd>
            <dt className="text-muted-foreground">Graph</dt>
            <dd className="font-mono text-xs">{workflow.graph_version}</dd>
            <dt className="text-muted-foreground">Created</dt>
            <dd>{formatDateTime(workflow.created_at)}</dd>
            {workflow.completed_at ? (
              <>
                <dt className="text-muted-foreground">Completed</dt>
                <dd>{formatDateTime(workflow.completed_at)}</dd>
              </>
            ) : null}
            {workflow.error_code ? (
              <>
                <dt className="text-muted-foreground">Error</dt>
                <dd className="text-destructive">{workflow.error_code}</dd>
              </>
            ) : null}
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Events</CardTitle>
        </CardHeader>
        <CardContent>
          <EventsTimeline workflow={workflow} />
        </CardContent>
      </Card>
    </div>
  );
}

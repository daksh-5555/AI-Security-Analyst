import { ArrowLeft, FileSearch, FileText, GitBranch, Network, ShieldAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import {
  useAssessmentHistoryQuery,
  useAssessmentQuery,
  useRepositoryTargetQuery,
} from "@/lib/api/assessments";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusPill } from "@/components/common/StatusPill";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingCards } from "@/components/states/LoadingState";
import { formatDateTime, shortId } from "@/lib/format";
import { assessmentTypeLabel } from "./labels";
import { RepositorySourceCard } from "./RepositorySourceCard";
import { AnalysisRunsCard } from "./AnalysisRunsCard";

function BackLink() {
  return (
    <Button asChild variant="ghost" size="sm" className="mb-2 -ml-2 text-muted-foreground">
      <Link to="/assessments">
        <ArrowLeft />
        Assessments
      </Link>
    </Button>
  );
}

export function AssessmentDetailPage() {
  const { id = "" } = useParams();
  const assessment = useAssessmentQuery(id);
  const history = useAssessmentHistoryQuery(id);
  const repository = useRepositoryTargetQuery(id);

  if (assessment.isLoading) {
    return (
      <div>
        <BackLink />
        <LoadingCards count={3} />
      </div>
    );
  }

  if (assessment.isError || !assessment.data) {
    return (
      <div>
        <BackLink />
        <ErrorState
          error={assessment.error}
          title="Assessment unavailable"
          onRetry={() => void assessment.refetch()}
        />
      </div>
    );
  }

  const data = assessment.data;
  const isRepository = data.assessment_type === "repository";
  const isWebSecurity = data.assessment_type === "web_security";
  const repositoryConfigured = Boolean(repository.data);

  // Only gate what we can honestly gate; the backend remains authoritative.
  let canStart = true;
  let startHint: string | undefined;
  if (isRepository && !repositoryConfigured) {
    canStart = false;
    startHint = "Configure a repository source before running.";
  } else if (isWebSecurity) {
    canStart = false;
    startHint = "Web target configuration arrives in a later stage.";
  }

  return (
    <div className="space-y-5">
      <div>
        <BackLink />
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-xl font-semibold tracking-tight text-foreground">
            {assessmentTypeLabel(data.assessment_type)} assessment
          </h2>
          <StatusPill status={data.status} />
          <span className="font-mono text-xs text-muted-foreground">{shortId(data.id)}</span>
          <div className="ml-auto flex gap-2">
            <Button asChild variant="outline" size="sm">
              <Link to={`/assessments/${id}/attack-surface`}>
                <Network />
                Attack surface
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to={`/assessments/${id}/findings`}>
                <ShieldAlert />
                View findings
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to={`/assessments/${id}/evidence`}>
                <FileSearch />
                Evidence
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to={`/assessments/${id}/report`}>
                <FileText />
                Report
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to={`/assessments/${id}/workflows`}>
                <GitBranch />
                Workflows
              </Link>
            </Button>
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[auto,1fr] gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto,1fr,auto,1fr]">
            <dt className="text-muted-foreground">Type</dt>
            <dd className="font-medium">{assessmentTypeLabel(data.assessment_type)}</dd>
            <dt className="text-muted-foreground">Status</dt>
            <dd className="capitalize">{data.status}</dd>
            <dt className="text-muted-foreground">Created</dt>
            <dd>{formatDateTime(data.created_at)}</dd>
            <dt className="text-muted-foreground">Updated</dt>
            <dd>{formatDateTime(data.updated_at)}</dd>
          </dl>
        </CardContent>
      </Card>

      {isRepository ? <RepositorySourceCard assessmentId={id} /> : null}

      <AnalysisRunsCard assessmentId={id} canStart={canStart} startHint={startHint} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Status history</CardTitle>
        </CardHeader>
        <CardContent>
          {history.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading history…</p>
          ) : history.isError ? (
            <ErrorState error={history.error} onRetry={() => void history.refetch()} />
          ) : (history.data ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">No status changes recorded yet.</p>
          ) : (
            <ol className="space-y-3">
              {(history.data ?? []).map((entry) => (
                <li key={entry.id} className="flex items-start gap-3 text-sm">
                  <span className="mt-1 size-1.5 shrink-0 rounded-full bg-border" aria-hidden />
                  <div>
                    <p>
                      <span className="capitalize text-muted-foreground">
                        {entry.previous_status}
                      </span>{" "}
                      → <span className="font-medium capitalize">{entry.new_status}</span>
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {formatDateTime(entry.changed_at)}
                      {entry.reason ? ` · ${entry.reason}` : ""}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

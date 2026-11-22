import { useMemo } from "react";
import { Activity, ClipboardList, FileSearch, FileText, Network, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { useAssessmentsQuery, type Assessment } from "@/lib/api/assessments";
import { useHealthQuery } from "@/lib/api/health";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusPill } from "@/components/common/StatusPill";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel } from "@/features/assessments/labels";

// How many of the most recent assessments the derived counts are computed over.
// The backend has no aggregate-stats endpoint, so this is an honest local rollup.
const SAMPLE_SIZE = 50;

const STATUS_ORDER = ["queued", "running", "completed", "failed"];

function countBy(items: Assessment[], key: (a: Assessment) => string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) counts.set(key(item), (counts.get(key(item)) ?? 0) + 1);
  return counts;
}

const QUICK_LINKS = [
  { to: "/assessments", label: "Assessments", icon: ClipboardList },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/attack-surface", label: "Attack Surface", icon: Network },
  { to: "/evidence", label: "Evidence", icon: FileSearch },
  { to: "/reports", label: "Reports", icon: FileText },
];

export function OverviewPage() {
  const health = useHealthQuery();
  const assessments = useAssessmentsQuery({ limit: SAMPLE_SIZE, offset: 0 });

  const rows = useMemo(() => assessments.data ?? [], [assessments.data]);
  const statusCounts = useMemo(() => countBy(rows, (a) => a.status), [rows]);
  const typeCounts = useMemo(() => countBy(rows, (a) => a.assessment_type), [rows]);
  const sampledAll = rows.length < SAMPLE_SIZE;
  const recent = rows.slice(0, 6);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        description="A single view of assessment activity, derived from real backend data — nothing here is fabricated."
        actions={
          <Button asChild size="sm">
            <Link to="/assessments">Go to assessments</Link>
          </Button>
        }
      />

      <Card>
        <CardHeader className="flex-row items-center gap-2">
          <Activity className="size-4 text-primary" />
          <CardTitle className="text-sm">Backend connectivity</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center gap-3 text-sm">
          <span className={health.isError ? "text-destructive" : health.isLoading ? "text-muted-foreground" : "text-emerald"}>
            {health.isLoading ? "Checking…" : health.isError ? "Unreachable" : "Online"}
          </span>
          <span className="text-muted-foreground">
            {health.data?.status ? `/health reports "${health.data.status}"` : "GET /health (live, unauthenticated)"}
          </span>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">
            Assessments by status
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {assessments.isLoading ? (
            <LoadingRows rows={2} />
          ) : assessments.isError ? (
            <ErrorState error={assessments.error} onRetry={() => void assessments.refetch()} />
          ) : rows.length === 0 ? (
            <EmptyState
              icon={ClipboardList}
              title="No assessments yet"
              description="Create your first assessment to see activity here."
            />
          ) : (
            <>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {STATUS_ORDER.filter((status) => (statusCounts.get(status) ?? 0) > 0).map((status) => (
                  <div key={status} className="rounded-md border border-border px-3 py-2">
                    <p className="text-2xl font-semibold text-foreground">{statusCounts.get(status)}</p>
                    <StatusPill status={status} />
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
                {[...typeCounts.entries()].map(([type, count]) => (
                  <span key={type}>
                    {assessmentTypeLabel(type)}: <span className="font-medium text-foreground">{count}</span>
                  </span>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                Derived from the {sampledAll ? rows.length : `latest ${SAMPLE_SIZE}`} assessment
                {rows.length === 1 ? "" : "s"} — a local rollup, not a global statistics endpoint.
              </p>
            </>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center gap-2">
            <ClipboardList className="size-4 text-muted-foreground" />
            <CardTitle className="text-sm">Recent assessments</CardTitle>
          </CardHeader>
          <CardContent>
            {assessments.isLoading ? (
              <LoadingRows rows={3} />
            ) : assessments.isError ? (
              <ErrorState error={assessments.error} onRetry={() => void assessments.refetch()} />
            ) : recent.length === 0 ? (
              <EmptyState title="No assessments yet" description="Create one to begin." />
            ) : (
              <ul className="divide-y divide-border">
                {recent.map((assessment) => (
                  <li key={assessment.id}>
                    <Link
                      to={`/assessments/${assessment.id}`}
                      className="flex items-center gap-3 py-2.5 transition-colors hover:text-foreground"
                    >
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium text-foreground">
                          {assessmentTypeLabel(assessment.assessment_type)}
                        </span>
                        <span className="block text-xs text-muted-foreground">
                          Updated {formatDateTime(assessment.updated_at)}
                        </span>
                      </span>
                      <StatusPill status={assessment.status} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center gap-2">
            <Network className="size-4 text-muted-foreground" />
            <CardTitle className="text-sm">Quick links</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2">
              {QUICK_LINKS.map((link) => (
                <Button key={link.to} asChild variant="outline" size="sm" className="justify-start">
                  <Link to={link.to}>
                    <link.icon />
                    {link.label}
                  </Link>
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

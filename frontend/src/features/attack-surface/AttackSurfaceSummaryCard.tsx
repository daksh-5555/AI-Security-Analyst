import { useState } from "react";
import {
  useAttackSurfaceSummaryQuery,
  type AttackSurfaceMetrics,
  type SummarySource,
} from "@/lib/api/attackSurface";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingCards } from "@/components/states/LoadingState";
import { cn } from "@/lib/utils";

const MAX_ROWS = 100;

const METRIC_TILES: { key: keyof AttackSurfaceMetrics; label: string }[] = [
  { key: "route_count", label: "Routes" },
  { key: "issue_count", label: "Issues" },
  { key: "sensitive_operation_count", label: "Sensitive ops" },
  { key: "input_count", label: "Inputs" },
  { key: "handler_count", label: "Handlers" },
  { key: "call_count", label: "Calls" },
  { key: "routes_with_authentication", label: "Routes w/ authn" },
  { key: "routes_with_authorization", label: "Routes w/ authz" },
];

function metricValue(metrics: AttackSurfaceMetrics, key: keyof AttackSurfaceMetrics): number {
  const value = metrics[key];
  return typeof value === "number" ? value : 0;
}

export function AttackSurfaceSummaryCard({ assessmentId }: { assessmentId: string }) {
  const [source, setSource] = useState<SummarySource>("persisted");
  const query = useAttackSurfaceSummaryQuery(assessmentId, source);
  const summary = query.data;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
        <div className="space-y-1">
          <CardTitle className="text-base">Attack surface</CardTitle>
          <CardDescription>Routes, inputs and issues discovered by static analysis.</CardDescription>
        </div>
        <div className="flex overflow-hidden rounded-md border border-border text-xs">
          {(["persisted", "live"] as SummarySource[]).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setSource(value)}
              className={cn(
                "px-2.5 py-1 capitalize transition-colors",
                source === value ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted",
              )}
            >
              {value}
            </button>
          ))}
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {query.isLoading ? (
          <LoadingCards count={4} />
        ) : query.isError ? (
          <ErrorState
            error={query.error}
            title="No attack surface yet"
            onRetry={() => void query.refetch()}
          />
        ) : !summary ? (
          <EmptyState title="No data" description="No attack-surface summary is available." />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {METRIC_TILES.map(({ key, label }) => (
                <div key={key} className="rounded-md border border-border px-3 py-2">
                  <p className="text-xl font-semibold text-foreground">
                    {metricValue(summary.summary, key)}
                  </p>
                  <p className="text-xs text-muted-foreground">{label}</p>
                </div>
              ))}
            </div>

            {!summary.summary.is_complete ? (
              <p className="text-xs text-severity-medium">
                Analysis is incomplete — some sources were truncated or did not finish.
              </p>
            ) : null}

            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                Routes ({summary.routes.length})
              </h3>
              {summary.routes.length === 0 ? (
                <p className="text-sm text-muted-foreground">No routes detected.</p>
              ) : (
                <div className="overflow-x-auto rounded-md border border-border">
                  <table className="w-full text-sm">
                    <thead className="bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
                      <tr>
                        <th className="px-3 py-2 font-medium">Method</th>
                        <th className="px-3 py-2 font-medium">Path</th>
                        <th className="hidden px-3 py-2 font-medium sm:table-cell">Framework</th>
                        <th className="hidden px-3 py-2 font-medium md:table-cell">Handler</th>
                        <th className="px-3 py-2 font-medium">Issues</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.routes.slice(0, MAX_ROWS).map((route) => (
                        <tr key={route.route_id} className="border-t border-border">
                          <td className="px-3 py-2 font-mono text-xs">{route.http_method}</td>
                          <td className="px-3 py-2 font-mono text-xs">{route.path}</td>
                          <td className="hidden px-3 py-2 text-muted-foreground sm:table-cell">
                            {route.framework}
                          </td>
                          <td className="hidden px-3 py-2 font-mono text-xs text-muted-foreground md:table-cell">
                            {route.handler_name ?? "—"}
                          </td>
                          <td className="px-3 py-2">{route.issue_ids?.length ?? 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {summary.routes.length > MAX_ROWS ? (
                    <p className="px-3 py-2 text-xs text-muted-foreground">
                      Showing first {MAX_ROWS} of {summary.routes.length} routes.
                    </p>
                  ) : null}
                </div>
              )}
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                Issues ({summary.issues.length})
              </h3>
              {summary.issues.length === 0 ? (
                <p className="text-sm text-muted-foreground">No attack-surface issues.</p>
              ) : (
                <ul className="space-y-2">
                  {summary.issues.slice(0, MAX_ROWS).map((issue) => (
                    <li key={issue.issue_id} className="rounded-md border border-border p-3 text-sm">
                      <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <span className="rounded bg-muted px-1.5 py-0.5 capitalize">{issue.kind.replace(/_/g, " ")}</span>
                        <span>{issue.category}</span>
                        {issue.route_http_method ? <span>· {issue.route_http_method}</span> : null}
                        {typeof issue.line_number === "number" ? <span>· line {issue.line_number}</span> : null}
                      </p>
                      <p className="mt-1">{issue.explanation}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

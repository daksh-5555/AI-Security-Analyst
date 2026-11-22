import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useDenialPatternsQuery } from "@/lib/api/admin";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { formatDateTime, shortId } from "@/lib/format";

const LIMIT = 50;
const WINDOW_OPTIONS = [
  { hours: 24, label: "Last 24h" },
  { hours: 24 * 7, label: "Last 7 days" },
  { hours: 24 * 30, label: "Last 30 days" },
];
const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

export function AdministrationPage() {
  const [minAttempts, setMinAttempts] = useState(2);
  const [windowHours, setWindowHours] = useState(24 * 7);
  const query = useDenialPatternsQuery({ minAttempts, limit: LIMIT, windowHours });
  const data = query.data;
  const patterns = data?.patterns ?? [];

  return (
    <div>
      <PageHeader
        title="Administration"
        description="Security monitoring from the backend audit trail. Admin access only."
      />

      <Card>
        <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="size-4 text-muted-foreground" />
              Repeated access denials
            </CardTitle>
            <CardDescription>
              Actor / resource / action combinations denied at least the threshold number of times.
            </CardDescription>
          </div>
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="window" className="text-xs text-muted-foreground">Window</Label>
              <select
                id="window"
                className={SELECT_CLASS}
                value={windowHours}
                onChange={(event) => setWindowHours(Number(event.target.value))}
              >
                {WINDOW_OPTIONS.map((option) => (
                  <option key={option.hours} value={option.hours}>{option.label}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="min-attempts" className="text-xs text-muted-foreground">Min attempts</Label>
              <Input
                id="min-attempts"
                type="number"
                min={1}
                value={minAttempts}
                onChange={(event) => setMinAttempts(Math.max(1, Number(event.target.value) || 1))}
                className="h-9 w-24"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {query.isLoading ? (
            <LoadingRows rows={5} />
          ) : query.isError ? (
            <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          ) : patterns.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title="No denial patterns"
              description="No actor repeatedly hit an authorization denial in this window."
            />
          ) : (
            <>
              {data ? (
                <p className="text-xs text-muted-foreground">
                  {data.total} pattern{data.total === 1 ? "" : "s"} · window {formatDateTime(data.from_time)} – {formatDateTime(data.to_time)}
                </p>
              ) : null}
              <div className="overflow-x-auto rounded-md border border-border">
                <table className="w-full text-sm">
                  <thead className="bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Action</th>
                      <th className="px-4 py-2.5 font-medium">Attempts</th>
                      <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Resource</th>
                      <th className="hidden px-4 py-2.5 font-medium md:table-cell">Actor</th>
                      <th className="hidden px-4 py-2.5 font-medium lg:table-cell">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {patterns.map((pattern, index) => (
                      <tr key={`${pattern.action}-${pattern.actor_user_id ?? "anon"}-${index}`} className="border-t border-border">
                        <td className="px-4 py-2.5 font-mono text-xs">{pattern.action}</td>
                        <td className="px-4 py-2.5 font-semibold text-destructive">{pattern.attempt_count}</td>
                        <td className="hidden px-4 py-2.5 sm:table-cell">
                          <span className="text-muted-foreground">{pattern.resource_type}</span>
                          {pattern.resource_id ? <span className="font-mono text-xs"> {shortId(pattern.resource_id)}</span> : null}
                        </td>
                        <td className="hidden px-4 py-2.5 font-mono text-xs text-muted-foreground md:table-cell">
                          {pattern.actor_user_id ? shortId(pattern.actor_user_id) : "—"}
                        </td>
                        <td className="hidden whitespace-nowrap px-4 py-2.5 text-muted-foreground lg:table-cell">
                          {formatDateTime(pattern.last_seen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

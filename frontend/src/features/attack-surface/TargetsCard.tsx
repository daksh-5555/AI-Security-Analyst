import { useState } from "react";
import { Crosshair, Plus } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import {
  useAuthorizeTarget,
  useRegisterWebTarget,
  useRevokeTarget,
  useTargetsQuery,
  type Target,
} from "@/lib/api/attackSurface";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/states/EmptyState";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingRows } from "@/components/states/LoadingState";
import { cn } from "@/lib/utils";
import { formatDateTime } from "@/lib/format";
import { TargetAuthDialog } from "./TargetAuthDialog";

const STATUS_STYLES: Record<string, string> = {
  authorized: "bg-emerald/15 text-emerald",
  pending_authorization: "bg-severity-medium/15 text-severity-medium",
  revoked: "bg-destructive/15 text-destructive",
};

function TargetStatusBadge({ status }: { status: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        STATUS_STYLES[status] ?? "bg-muted text-muted-foreground",
      )}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function TargetsCard({
  assessmentId,
  isWebSecurity,
}: {
  assessmentId: string;
  isWebSecurity: boolean;
}) {
  const query = useTargetsQuery(assessmentId);
  const register = useRegisterWebTarget(assessmentId);
  const authorize = useAuthorizeTarget(assessmentId);
  const revoke = useRevokeTarget(assessmentId);
  const [error, setError] = useState<string | null>(null);

  const targets = query.data ?? [];

  const onRevoke = async (target: Target) => {
    setError(null);
    try {
      await revoke.mutateAsync(target.id);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.userMessage : "Unable to revoke the target.");
    }
  };

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Crosshair className="size-4 text-muted-foreground" />
            Targets
          </CardTitle>
          <CardDescription>Authorized scope for this assessment.</CardDescription>
        </div>
        {isWebSecurity ? (
          <TargetAuthDialog
            mode="register"
            trigger={
              <Button size="sm">
                <Plus />
                Register web target
              </Button>
            }
            onConfirm={async ({ baseUrl, statement }) => {
              await register.mutateAsync({
                base_url: baseUrl ?? "",
                authorization_statement: statement,
                confirm_authorized: true,
              });
            }}
          />
        ) : null}
      </CardHeader>
      <CardContent className="space-y-3">
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}

        {query.isLoading ? (
          <LoadingRows rows={2} />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : targets.length === 0 ? (
          <EmptyState
            icon={Crosshair}
            title="No targets"
            description={
              isWebSecurity
                ? "Register a web target to define the authorized scope."
                : "A repository target is created when you configure the repository source."
            }
          />
        ) : (
          <ul className="divide-y divide-border">
            {targets.map((target) => (
              <li key={target.id} className="flex items-start justify-between gap-3 py-3">
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <TargetStatusBadge status={target.status} />
                    <span className="break-all font-mono text-xs text-foreground">{target.target}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{target.target_type}</p>
                  {target.authorization_statement ? (
                    <p className="text-xs text-muted-foreground">
                      “{target.authorization_statement}”
                    </p>
                  ) : null}
                  {target.authorized_at ? (
                    <p className="text-xs text-muted-foreground">
                      Authorized {formatDateTime(target.authorized_at)}
                    </p>
                  ) : null}
                  {target.revoked_at ? (
                    <p className="text-xs text-destructive">
                      Revoked {formatDateTime(target.revoked_at)}
                    </p>
                  ) : null}
                </div>
                <div className="shrink-0">
                  {target.status === "authorized" ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => void onRevoke(target)}
                      disabled={revoke.isPending}
                    >
                      Revoke
                    </Button>
                  ) : (
                    <TargetAuthDialog
                      mode="authorize"
                      trigger={
                        <Button variant="outline" size="sm">
                          Authorize
                        </Button>
                      }
                      onConfirm={async ({ statement }) => {
                        await authorize.mutateAsync({
                          targetId: target.id,
                          body: { authorization_statement: statement, confirm_authorized: true },
                        });
                      }}
                    />
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

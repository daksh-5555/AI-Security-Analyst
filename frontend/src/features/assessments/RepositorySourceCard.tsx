import { useState, type FormEvent } from "react";
import { FolderGit2, Loader2 } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import {
  useConfigureRepository,
  useRepositoryTargetQuery,
  type RepositoryTarget,
} from "@/lib/api/assessments";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorState } from "@/components/states/ErrorState";
import { formatDateTime } from "@/lib/format";

interface RepositorySourceCardProps {
  assessmentId: string;
  /** Lifts the configured target up so the parent can gate "Start run". */
  onConfigured?: (target: RepositoryTarget) => void;
}

export function RepositorySourceCard({ assessmentId, onConfigured }: RepositorySourceCardProps) {
  const query = useRepositoryTargetQuery(assessmentId);
  const configure = useConfigureRepository(assessmentId);
  const [location, setLocation] = useState("");
  const [error, setError] = useState<string | null>(null);

  const target = query.data ?? null;

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (!location.trim()) {
      setError("Enter the repository path.");
      return;
    }
    try {
      const created = await configure.mutateAsync({
        source_kind: "local_path",
        location: location.trim(),
      });
      onConfigured?.(created);
    } catch (cause) {
      setError(
        cause instanceof ApiError ? cause.userMessage : "Unable to configure the repository.",
      );
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <FolderGit2 className="size-4 text-muted-foreground" />
          Repository source
        </CardTitle>
        <CardDescription>
          A local repository path to analyze. The backend validates it against its allowed roots.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading source…</p>
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : target ? (
          <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Kind</dt>
            <dd className="font-medium capitalize">{target.source_kind.replace(/_/g, " ")}</dd>
            <dt className="text-muted-foreground">Location</dt>
            <dd className="break-all font-mono text-xs">{target.location}</dd>
            <dt className="text-muted-foreground">Configured</dt>
            <dd>{formatDateTime(target.created_at)}</dd>
          </dl>
        ) : (
          <form className="space-y-3" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label htmlFor="repo-location">Local repository path</Label>
              <Input
                id="repo-location"
                value={location}
                onChange={(event) => setLocation(event.target.value)}
                placeholder="/srv/repositories/my-app"
                disabled={configure.isPending}
                autoComplete="off"
              />
            </div>
            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            ) : null}
            <Button type="submit" size="sm" disabled={configure.isPending}>
              {configure.isPending ? <Loader2 className="animate-spin" /> : null}
              Configure source
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  );
}

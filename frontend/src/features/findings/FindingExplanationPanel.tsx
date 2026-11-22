import { useState } from "react";
import { Loader2, Sparkles, TriangleAlert } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import {
  useFindingExplanationsQuery,
  useGenerateExplanation,
  type FindingExplanation,
} from "@/lib/api/findings";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/states/ErrorState";
import { formatDateTime } from "@/lib/format";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</p>
      {children}
    </div>
  );
}

function ExplanationBody({ explanation }: { explanation: FindingExplanation }) {
  if (explanation.status === "unavailable" || !explanation.explanation) {
    return (
      <p className="text-sm text-muted-foreground">
        Explanation unavailable{explanation.error_code ? ` (${explanation.error_code})` : ""}.
      </p>
    );
  }
  const output = explanation.explanation;
  return (
    <div className="space-y-3">
      <Section title="Summary">
        <p className="text-sm">{output.summary}</p>
      </Section>
      <Section title="Impact">
        <p className="text-sm">{output.impact}</p>
      </Section>
      <Section title="Technical explanation">
        <p className="text-sm">{output.technical_explanation}</p>
      </Section>
      {output.remediation_steps.length > 0 ? (
        <Section title="Remediation steps">
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            {output.remediation_steps.map((step, index) => (
              <li key={index}>{step}</li>
            ))}
          </ol>
        </Section>
      ) : null}
      {output.validation_guidance.length > 0 ? (
        <Section title="Validation guidance">
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {output.validation_guidance.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </Section>
      ) : null}
      {output.uncertainty ? (
        <Section title="Uncertainty">
          <p className="text-sm text-muted-foreground">{output.uncertainty}</p>
        </Section>
      ) : null}
    </div>
  );
}

export function FindingExplanationPanel({
  assessmentId,
  findingId,
}: {
  assessmentId: string;
  findingId: string;
}) {
  const query = useFindingExplanationsQuery(assessmentId, findingId);
  const generate = useGenerateExplanation(assessmentId, findingId);
  const [error, setError] = useState<string | null>(null);

  const explanations = query.data ?? [];

  const onGenerate = async () => {
    setError(null);
    try {
      await generate.mutateAsync();
    } catch (cause) {
      setError(
        cause instanceof ApiError ? cause.userMessage : "Unable to generate an explanation.",
      );
    }
  };

  return (
    <div className="space-y-3 rounded-md border border-violet/30 bg-violet/5 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-medium text-foreground">
          <Sparkles className="size-4 text-violet" />
          AI explanation
        </div>
        <Button size="sm" variant="outline" onClick={() => void onGenerate()} disabled={generate.isPending}>
          {generate.isPending ? <Loader2 className="animate-spin" /> : <Sparkles />}
          Generate
        </Button>
      </div>

      <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
        <TriangleAlert className="mt-0.5 size-3 shrink-0" />
        Advisory only. It does not change the finding's status, severity, or confidence, which come
        from deterministic analysis.
      </p>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      {query.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading explanations…</p>
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : explanations.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No explanation yet. Generate one to see an advisory analysis.
        </p>
      ) : (
        <ul className="space-y-3">
          {explanations.map((explanation) => (
            <li key={explanation.id} className="space-y-2 border-t border-violet/20 pt-3 first:border-t-0 first:pt-0">
              <p className="text-xs text-muted-foreground">
                {explanation.provider} · {explanation.model} ·{" "}
                {explanation.input_tokens + explanation.output_tokens} tokens ·{" "}
                {formatDateTime(explanation.created_at)}
              </p>
              <ExplanationBody explanation={explanation} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

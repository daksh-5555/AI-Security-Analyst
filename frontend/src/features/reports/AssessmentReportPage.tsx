import { useState } from "react";
import { ArrowLeft, Code2, Download, ExternalLink } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useAnalysisRunsQuery, useAssessmentQuery } from "@/lib/api/assessments";
import { downloadBlob, useReportHtmlQuery, useReportJsonQuery } from "@/lib/api/reports";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { ErrorState } from "@/components/states/ErrorState";
import { LoadingCards } from "@/components/states/LoadingState";
import { shortId } from "@/lib/format";
import { assessmentTypeLabel } from "@/features/assessments/labels";
import { ReportSummary } from "./ReportSummary";

const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

export function AssessmentReportPage() {
  const { id = "" } = useParams();
  const assessment = useAssessmentQuery(id);
  const runs = useAnalysisRunsQuery(id);
  const [runFilter, setRunFilter] = useState("");

  const run = runFilter || null;
  const json = useReportJsonQuery(id, run);
  const html = useReportHtmlQuery(id, run);

  const suffix = runFilter ? `-run-${shortId(runFilter)}` : "";

  const openHtmlInNewTab = () => {
    if (!html.data) return;
    const url = URL.createObjectURL(new Blob([html.data], { type: "text/html" }));
    window.open(url, "_blank", "noopener");
    // Revoke after the tab has had time to load the blob.
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
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
          <h2 className="text-xl font-semibold tracking-tight text-foreground">Report</h2>
          <div className="flex flex-wrap items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="report-run" className="text-xs text-muted-foreground">Run</Label>
              <select
                id="report-run"
                className={SELECT_CLASS}
                value={runFilter}
                onChange={(event) => setRunFilter(event.target.value)}
              >
                <option value="">Whole assessment</option>
                {(runs.data ?? []).map((r) => (
                  <option key={r.id} value={r.id}>
                    {shortId(r.id)} · {r.status}
                  </option>
                ))}
              </select>
            </div>
            <Button
              variant="outline"
              size="sm"
              disabled={!json.data}
              onClick={() => json.data && downloadBlob(JSON.stringify(json.data, null, 2), `report-${shortId(id)}${suffix}.json`, "application/json")}
            >
              <Code2 />
              JSON
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!html.data}
              onClick={() => html.data && downloadBlob(html.data, `report-${shortId(id)}${suffix}.html`, "text/html")}
            >
              <Download />
              HTML
            </Button>
            <Button variant="outline" size="sm" disabled={!html.data} onClick={openHtmlInNewTab}>
              <ExternalLink />
              Open
            </Button>
          </div>
        </div>
      </div>

      {json.isLoading ? (
        <LoadingCards count={3} />
      ) : json.isError ? (
        <ErrorState
          error={json.error}
          title="Report unavailable"
          onRetry={() => void json.refetch()}
        />
      ) : json.data ? (
        <ReportSummary report={json.data} />
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Rendered report</CardTitle>
        </CardHeader>
        <CardContent>
          {html.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading preview…</p>
          ) : html.isError ? (
            <ErrorState error={html.error} onRetry={() => void html.refetch()} />
          ) : html.data ? (
            <iframe
              // Sandboxed with no privileges: the backend report is static HTML with
              // no scripts, and this prevents any embedded content from running.
              sandbox=""
              srcDoc={html.data}
              title="Rendered assessment report"
              className="h-[600px] w-full rounded-md border border-border bg-white"
            />
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

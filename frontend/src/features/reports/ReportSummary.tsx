import type { JsonReport } from "@/lib/api/reports";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { formatDateTime } from "@/lib/format";
import { assessmentTypeLabel } from "@/features/assessments/labels";
import { findingStatusLabel } from "@/features/findings/severity";

function SeverityCounts({ counts }: { counts?: Record<string, number> }) {
  const entries = Object.entries(counts ?? {}).filter(([, value]) => value > 0);
  if (entries.length === 0) return <p className="text-sm text-muted-foreground">No findings.</p>;
  return (
    <div className="flex flex-wrap gap-2">
      {entries.map(([severity, count]) => (
        <span key={severity} className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1">
          <SeverityBadge severity={severity} />
          <span className="text-sm font-medium">{count}</span>
        </span>
      ))}
    </div>
  );
}

function StatusCounts({ counts }: { counts?: Record<string, number> }) {
  const entries = Object.entries(counts ?? {}).filter(([, value]) => value > 0);
  if (entries.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
      {entries.map(([status, count]) => (
        <span key={status} className="text-muted-foreground">
          {findingStatusLabel(status)}: <span className="font-medium text-foreground">{count}</span>
        </span>
      ))}
    </div>
  );
}

export function ReportSummary({ report }: { report: JsonReport }) {
  const assessment = report.assessment;
  const counts = report.counts;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Report</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[auto,1fr] gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto,1fr,auto,1fr]">
            {assessment?.type ? (
              <>
                <dt className="text-muted-foreground">Assessment</dt>
                <dd className="font-medium">{assessmentTypeLabel(assessment.type)}</dd>
              </>
            ) : null}
            {assessment?.status ? (
              <>
                <dt className="text-muted-foreground">Status</dt>
                <dd className="capitalize">{assessment.status}</dd>
              </>
            ) : null}
            {report.generator?.name ? (
              <>
                <dt className="text-muted-foreground">Generator</dt>
                <dd>
                  {report.generator.name}
                  {report.generator.version ? ` ${report.generator.version}` : ""}
                </dd>
              </>
            ) : null}
            {report.schema_version ? (
              <>
                <dt className="text-muted-foreground">Schema</dt>
                <dd className="font-mono text-xs">{report.schema_version}</dd>
              </>
            ) : null}
            {report.run?.completed_at ? (
              <>
                <dt className="text-muted-foreground">Run finished</dt>
                <dd>{formatDateTime(report.run.completed_at)}</dd>
              </>
            ) : null}
          </dl>
        </CardContent>
      </Card>

      {report.executive_summary && report.executive_summary.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Executive summary</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc space-y-1.5 pl-5 text-sm">
              {report.executive_summary.map((line, index) => (
                <li key={index}>{line}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Findings{typeof counts?.total === "number" ? ` (${counts.total})` : ""}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <SeverityCounts counts={counts?.by_severity} />
          <StatusCounts counts={counts?.by_status} />
          {report.findings && report.findings.length > 0 ? (
            <ul className="divide-y divide-border">
              {report.findings.map((finding, index) => (
                <li key={finding.id ?? index} className="flex items-start gap-3 py-2.5">
                  {finding.severity ? <SeverityBadge severity={finding.severity} className="mt-0.5" /> : null}
                  <span className="min-w-0 flex-1">
                    <span className="block font-medium text-foreground">{finding.title}</span>
                    {finding.status ? (
                      <span className="text-xs text-muted-foreground">{findingStatusLabel(finding.status)}</span>
                    ) : null}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}
          {typeof report.findings_omitted === "number" && report.findings_omitted > 0 ? (
            <p className="text-xs text-muted-foreground">
              {report.findings_omitted} finding{report.findings_omitted === 1 ? "" : "s"} omitted from this report.
            </p>
          ) : null}
        </CardContent>
      </Card>

      {report.limitations && report.limitations.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Limitations</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
              {report.limitations.map((item, index) => (
                <li key={index}>{typeof item === "string" ? item : JSON.stringify(item)}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

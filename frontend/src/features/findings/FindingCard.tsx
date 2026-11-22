import { useState } from "react";
import { ChevronDown } from "lucide-react";
import type { EmbeddedEvidence, Finding } from "@/lib/api/findings";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { cn } from "@/lib/utils";
import { formatDateTime } from "@/lib/format";
import { findingStatusLabel } from "./severity";
import { FindingExplanationPanel } from "./FindingExplanationPanel";

function Chips({ label, values }: { label: string; values?: string[] | null }) {
  if (!values || values.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className="text-xs text-muted-foreground">{label}:</span>
      {values.map((value) => (
        <span key={value} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground">
          {value}
        </span>
      ))}
    </span>
  );
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

function EvidenceList({ evidence }: { evidence: EmbeddedEvidence[] }) {
  if (evidence.length === 0) {
    return <p className="text-sm text-muted-foreground">No evidence attached.</p>;
  }
  return (
    <ul className="space-y-2">
      {evidence.map((item, index) => (
        <li key={index} className="rounded border border-border bg-background/60 p-2 text-sm">
          <p>{item.description}</p>
          <p className="mt-1 text-xs text-muted-foreground">Source: {item.source}</p>
        </li>
      ))}
    </ul>
  );
}

export function FindingCard({ assessmentId, finding }: { assessmentId: string; finding: Finding }) {
  const [open, setOpen] = useState(false);
  const confidencePct = Math.round((finding.confidence ?? 0) * 100);

  return (
    <div className="rounded-lg border border-border">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-muted/40"
      >
        <SeverityBadge severity={finding.severity} className="mt-0.5" />
        <span className="min-w-0 flex-1 space-y-1">
          <span className="block font-medium text-foreground">{finding.title}</span>
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span>{finding.category}</span>
            <span>·</span>
            <span>{findingStatusLabel(finding.status)}</span>
            <span>·</span>
            <span>{confidencePct}% confidence</span>
          </span>
        </span>
        <ChevronDown className={cn("mt-1 size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      {open ? (
        <div className="space-y-4 border-t border-border px-4 py-4">
          <p className="text-sm">{finding.summary}</p>

          <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-2 text-sm">
            {finding.affected_component ? (
              <DetailRow label="Component">
                <span className="break-all font-mono text-xs">{finding.affected_component}</span>
              </DetailRow>
            ) : null}
            {finding.remediation ? <DetailRow label="Remediation">{finding.remediation}</DetailRow> : null}
            {finding.rule_id ? (
              <DetailRow label="Rule">
                <span className="font-mono text-xs">{finding.rule_id}</span>
              </DetailRow>
            ) : null}
            {finding.source_stage ? <DetailRow label="Stage">{finding.source_stage}</DetailRow> : null}
            {finding.status_rationale ? (
              <DetailRow label="Status rationale">{finding.status_rationale}</DetailRow>
            ) : null}
            {finding.last_seen_at ? (
              <DetailRow label="Last seen">{formatDateTime(finding.last_seen_at)}</DetailRow>
            ) : null}
          </dl>

          {(finding.cwe_ids?.length || finding.cve_ids?.length) ? (
            <div className="flex flex-wrap gap-x-4 gap-y-2">
              <Chips label="CWE" values={finding.cwe_ids} />
              <Chips label="CVE" values={finding.cve_ids} />
            </div>
          ) : null}

          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Evidence
            </p>
            <EvidenceList evidence={finding.evidence ?? []} />
          </div>

          <FindingExplanationPanel assessmentId={assessmentId} findingId={finding.id} />
        </div>
      ) : null}
    </div>
  );
}

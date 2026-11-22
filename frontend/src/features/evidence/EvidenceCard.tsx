import { useState } from "react";
import { ChevronDown } from "lucide-react";
import type { EvidenceItem } from "@/lib/api/evidence";
import { cn } from "@/lib/utils";
import { formatDateTime } from "@/lib/format";

function locationOf(item: EvidenceItem): string | null {
  if (item.location_path) {
    return item.location_line ? `${item.location_path}:${item.location_line}` : item.location_path;
  }
  return item.url_path ?? null;
}

function KeyValues({ data }: { data: Record<string, unknown> | null }) {
  const entries = Object.entries(data ?? {});
  if (entries.length === 0) return <p className="text-sm text-muted-foreground">—</p>;
  return (
    <dl className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 text-xs">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="font-mono text-muted-foreground">{key}</dt>
          <dd className="break-all font-mono">
            {typeof value === "string" ? value : JSON.stringify(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</p>
      {children}
    </div>
  );
}

export function EvidenceCard({ item }: { item: EvidenceItem }) {
  const [open, setOpen] = useState(false);
  const location = locationOf(item);

  return (
    <div className="rounded-lg border border-border">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-muted/40"
      >
        <span className="mt-0.5 shrink-0 rounded bg-muted px-1.5 py-0.5 text-[11px] font-medium text-muted-foreground">
          {item.source_type}
        </span>
        <span className="min-w-0 flex-1 space-y-1">
          <span className="block font-medium text-foreground">{item.summary || item.evidence_key}</span>
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span>{item.method}</span>
            {location ? (
              <>
                <span>·</span>
                <span className="font-mono">{location}</span>
              </>
            ) : null}
            {item.rule_id ? (
              <>
                <span>·</span>
                <span className="font-mono">{item.rule_id}</span>
              </>
            ) : null}
          </span>
        </span>
        <ChevronDown className={cn("mt-1 size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      {open ? (
        <div className="space-y-4 border-t border-border px-4 py-4">
          <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Tool</dt>
            <dd>{item.tool_name} {item.tool_version}</dd>
            {item.parameter ? (
              <>
                <dt className="text-muted-foreground">Parameter</dt>
                <dd className="font-mono text-xs">{item.parameter}</dd>
              </>
            ) : null}
            <dt className="text-muted-foreground">Observed</dt>
            <dd>{formatDateTime(item.observed_at)}</dd>
            {item.rule_set_version ? (
              <>
                <dt className="text-muted-foreground">Rule set</dt>
                <dd className="font-mono text-xs">{item.rule_set_version}</dd>
              </>
            ) : null}
            {item.content_hash ? (
              <>
                <dt className="text-muted-foreground">Content hash</dt>
                <dd className="break-all font-mono text-xs">{item.content_hash}</dd>
              </>
            ) : null}
            {item.fingerprint ? (
              <>
                <dt className="text-muted-foreground">Fingerprint</dt>
                <dd className="break-all font-mono text-xs">{item.fingerprint}</dd>
              </>
            ) : null}
          </dl>

          {item.redacted_excerpt ? (
            <Section title="Redacted excerpt">
              <pre className="overflow-x-auto rounded bg-muted/50 p-2 text-xs">{item.redacted_excerpt}</pre>
            </Section>
          ) : null}

          {item.request_summary && Object.keys(item.request_summary).length > 0 ? (
            <Section title="Request summary">
              <KeyValues data={item.request_summary} />
            </Section>
          ) : null}
          {item.response_summary && Object.keys(item.response_summary).length > 0 ? (
            <Section title="Response summary">
              <KeyValues data={item.response_summary} />
            </Section>
          ) : null}
          {item.details && Object.keys(item.details).length > 0 ? (
            <Section title="Details">
              <KeyValues data={item.details} />
            </Section>
          ) : null}
          {item.limitations && item.limitations.length > 0 ? (
            <Section title="Limitations">
              <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
                {item.limitations.map((limitation, index) => (
                  <li key={index}>{typeof limitation === "string" ? limitation : JSON.stringify(limitation)}</li>
                ))}
              </ul>
            </Section>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

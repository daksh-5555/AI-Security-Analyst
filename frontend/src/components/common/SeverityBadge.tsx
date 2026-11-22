import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "informational" | "unknown";

const STYLES: Record<Severity, string> = {
  critical: "bg-severity-critical/15 text-severity-critical ring-severity-critical/30",
  high: "bg-severity-high/15 text-severity-high ring-severity-high/30",
  medium: "bg-severity-medium/15 text-severity-medium ring-severity-medium/30",
  low: "bg-severity-low/15 text-severity-low ring-severity-low/30",
  informational: "bg-severity-informational/15 text-severity-informational ring-severity-informational/30",
  unknown: "bg-severity-unknown/15 text-severity-unknown ring-severity-unknown/30",
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const key = (severity in STYLES ? severity : "unknown") as Severity;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ring-inset",
        STYLES[key],
        className,
      )}
    >
      {severity}
    </span>
  );
}

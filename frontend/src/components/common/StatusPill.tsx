import { cn } from "@/lib/utils";

/** Lifecycle status pill for assessments, runs and workflows. */
const STYLES: Record<string, string> = {
  queued: "bg-muted text-muted-foreground",
  running: "bg-cyan/15 text-cyan",
  awaiting_approval: "bg-violet/15 text-violet",
  completed: "bg-emerald/15 text-emerald",
  failed: "bg-destructive/15 text-destructive",
  cancelled: "bg-muted text-muted-foreground",
};

export function StatusPill({ status, className }: { status: string; className?: string }) {
  const style = STYLES[status] ?? "bg-muted text-muted-foreground";
  const dot = status === "running" || status === "awaiting_approval";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium capitalize",
        style,
        className,
      )}
    >
      {dot ? <span className="size-1.5 animate-pulse rounded-full bg-current" /> : null}
      {status.replace(/_/g, " ")}
    </span>
  );
}

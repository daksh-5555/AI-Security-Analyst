import { useHealthQuery } from "@/lib/api/health";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

/** Live, real backend connectivity indicator (GET /health). No fabricated data. */
export function BackendStatus() {
  const { data, isLoading, isError } = useHealthQuery();
  const state = isLoading ? "checking" : isError ? "offline" : "online";
  const color = {
    online: "bg-emerald",
    offline: "bg-destructive",
    checking: "bg-muted-foreground",
  }[state];
  const label = {
    online: `Backend online${data?.status ? ` (${data.status})` : ""}`,
    offline: "Backend unreachable",
    checking: "Checking backend…",
  }[state];

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground">
          <span className={cn("size-2 rounded-full", color, state === "checking" && "animate-pulse")} />
          <span className="hidden sm:inline">{state === "online" ? "Online" : state === "offline" ? "Offline" : "…"}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  );
}

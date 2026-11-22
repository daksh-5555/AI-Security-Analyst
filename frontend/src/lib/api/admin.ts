/**
 * Typed hook for the admin security-monitoring view of repeated access denials.
 * Admin-only: a caller without the role receives 403, which the page surfaces as
 * an access-denied state. The backend is the authoritative boundary.
 */
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { apiRequest, type Schema } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export type DenialPatternResponse = Schema<"DenialPatternResponse">;
export type DenialPattern = Schema<"DenialPattern">;

export interface DenialPatternsFilter {
  minAttempts: number;
  limit: number;
  /** Look-back window in hours; the endpoint requires an explicit from/to time. */
  windowHours: number;
}

export function useDenialPatternsQuery(
  filter: DenialPatternsFilter,
): UseQueryResult<DenialPatternResponse> {
  const toTime = new Date();
  const fromTime = new Date(toTime.getTime() - filter.windowHours * 3600_000);
  const query = {
    min_attempts: filter.minAttempts,
    limit: filter.limit,
    from_time: fromTime.toISOString(),
    to_time: toTime.toISOString(),
  };
  return useQuery({
    // The window end moves each render, so key on the window size, not the exact
    // instant, to avoid refetching on every render.
    queryKey: queryKeys.audit.denialPatterns({
      min_attempts: filter.minAttempts,
      limit: filter.limit,
      window_hours: filter.windowHours,
    }),
    queryFn: () =>
      apiRequest<DenialPatternResponse>(
        "/api/v1/admin/security-monitoring/denial-patterns",
        { query },
      ),
  });
}

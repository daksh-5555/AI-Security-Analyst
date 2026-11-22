import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/api/client";
import { queryKeys } from "@/lib/query/keys";

export interface HealthResponse {
  status?: string;
  [key: string]: unknown;
}

/** Real, unauthenticated backend liveness check (GET /health). */
export function useHealthQuery() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: ({ signal }) => apiRequest<HealthResponse>("/health", { signal }),
    refetchInterval: 30_000,
    retry: false,
  });
}

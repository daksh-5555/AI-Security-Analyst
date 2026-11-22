import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "@/lib/api/client";

/** Shared TanStack Query client. Auth (401) errors are not retried. */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          if (error instanceof ApiError && [400, 401, 403, 404, 422].includes(error.status)) {
            return false;
          }
          return failureCount < 2;
        },
      },
    },
  });
}

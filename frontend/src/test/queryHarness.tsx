import type { ReactElement, ReactNode } from "react";
import { vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { render, type RenderResult } from "@testing-library/react";

/** A QueryClient tuned for tests: no retries, no caching between tests. */
export function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface RenderOptions {
  initialEntries?: string[];
  client?: QueryClient;
}

export function renderWithProviders(
  ui: ReactElement,
  { initialEntries = ["/"], client = createTestQueryClient() }: RenderOptions = {},
): RenderResult {
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
      </QueryClientProvider>
    );
  }
  return render(ui, { wrapper: Wrapper });
}

export interface MockRoute {
  method?: string;
  /** Matches when the request URL contains this substring. */
  url: string;
  status?: number;
  body?: unknown;
  /** Raw text body (served as-is, not JSON-encoded) — e.g. an HTML report. */
  text?: string;
}

/**
 * Install a fetch mock that resolves the first matching route (by method + URL
 * substring). Unmatched requests resolve 404 so tests fail loudly on typos.
 */
export function installFetchMock(routes: MockRoute[]) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = (init.method ?? "GET").toUpperCase();
    const route = routes.find(
      (candidate) => (candidate.method ?? "GET").toUpperCase() === method && url.includes(candidate.url),
    );
    const status = route?.status ?? (route ? 200 : 404);
    if (route?.text !== undefined) {
      return new Response(route.text, { status, headers: { "Content-Type": "text/html" } });
    }
    const body = route?.body ?? (route ? null : { detail: `unmocked ${method} ${url}` });
    return new Response(status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

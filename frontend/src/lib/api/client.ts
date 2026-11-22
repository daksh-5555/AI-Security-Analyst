import type { components, paths } from "./schema";

/** Shorthand for a named backend schema, e.g. Schema<"AssessmentRead">. */
export type Schema<Name extends keyof components["schemas"]> = components["schemas"][Name];
export type ApiPaths = paths;

/**
 * Base URL for the API. Empty by default: the dev Vite proxy and the production
 * same-origin reverse proxy both serve the API under the current origin, so the
 * frontend never embeds a cross-origin host (ADR: no CORS middleware).
 */
export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "";

/** A sanitized API failure. Never contains credentials or raw server internals. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown, message?: string) {
    super(message ?? `Request failed with status ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }

  /** A short, user-safe description derived from the backend's `detail`. */
  get userMessage(): string {
    if (typeof this.detail === "string") return this.detail;
    if (this.detail && typeof this.detail === "object" && "detail" in this.detail) {
      const inner = (this.detail as { detail: unknown }).detail;
      if (typeof inner === "string") return inner;
    }
    if (this.status === 401) return "You are not signed in.";
    if (this.status === 403) return "You do not have access to this resource.";
    if (this.status === 404) return "Not found.";
    return "Something went wrong. Please try again.";
  }
}

/**
 * Authentication hook points. The access token is held in memory by the auth
 * layer (never in storage) and supplied here; the refresh handler lets a single
 * expired-token (401) response trigger one silent refresh-and-retry. Both default
 * to no-ops so the client works before the auth layer mounts.
 */
let authTokenProvider: () => string | null = () => null;
export function setAuthTokenProvider(provider: () => string | null): void {
  authTokenProvider = provider;
}

let refreshHandler: (() => Promise<boolean>) | null = null;
/** Register the silent-refresh callback. Returns true when a new token is ready. */
export function setRefreshHandler(handler: (() => Promise<boolean>) | null): void {
  refreshHandler = handler;
}

/** Paths that must never trigger the 401 refresh-and-retry (to avoid recursion). */
const NO_RETRY_PATHS = ["/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout"];

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  query?: Record<string, string | number | boolean | null | undefined>;
  body?: unknown;
  signal?: AbortSignal;
  /** Extra request headers (e.g. the double-submit X-CSRF-Token on refresh). */
  headers?: Record<string, string>;
  /** Set false for endpoints that return a non-JSON body (e.g. report downloads). */
  parseJson?: boolean;
  /** "text" returns the raw response body as a string (e.g. an HTML report). */
  responseType?: "json" | "text";
  /** Internal: suppress the automatic refresh-and-retry for this call. */
  skipAuthRetry?: boolean;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const url = `${API_BASE_URL}${path}`;
  if (!query) return url;
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== null && value !== undefined) search.append(key, String(value));
  }
  const qs = search.toString();
  return qs ? `${url}?${qs}` : url;
}

/** Typed, centralized request. Throws {@link ApiError} on any non-2xx response. */
export async function apiRequest<TResponse = unknown>(
  path: string,
  options: RequestOptions = {},
): Promise<TResponse> {
  const { method = "GET", query, body, signal, headers: extraHeaders, parseJson = true } = options;

  const send = async (): Promise<Response> => {
    const headers: Record<string, string> = { Accept: "application/json", ...extraHeaders };
    const token = authTokenProvider();
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(buildUrl(path, query), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      credentials: "same-origin",
    });
  };

  let response: Response;
  try {
    response = await send();
    // One silent refresh-and-retry when an in-memory access token has expired.
    if (
      response.status === 401 &&
      !options.skipAuthRetry &&
      refreshHandler !== null &&
      !NO_RETRY_PATHS.includes(path)
    ) {
      const refreshed = await refreshHandler();
      if (refreshed) response = await send();
    }
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError(0, null, "Unable to reach the server.");
  }

  if (!response.ok) {
    let detail: unknown = null;
    try {
      detail = await response.json();
    } catch {
      detail = null;
    }
    throw new ApiError(response.status, detail);
  }

  if (options.responseType === "text") return (await response.text()) as TResponse;
  if (!parseJson || response.status === 204) return undefined as TResponse;
  return (await response.json()) as TResponse;
}

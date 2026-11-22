import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiRequest, setAuthTokenProvider, setRefreshHandler } from "./client";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  setAuthTokenProvider(() => null);
  setRefreshHandler(null);
});

describe("apiRequest", () => {
  it("attaches the bearer token, extra headers, and same-origin credentials", async () => {
    setAuthTokenProvider(() => "tok-123");
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiRequest("/api/v1/thing", { headers: { "X-CSRF-Token": "csrf-1" } });

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer tok-123");
    expect(headers["X-CSRF-Token"]).toBe("csrf-1");
    expect(init.credentials).toBe("same-origin");
  });

  it("refreshes once and retries after a 401", async () => {
    setAuthTokenProvider(() => "tok");
    const refresh = vi.fn().mockResolvedValue(true);
    setRefreshHandler(refresh);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(401, { detail: "expired" }))
      .mockResolvedValueOnce(jsonResponse(200, { value: 42 }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiRequest<{ value: number }>("/api/v1/thing");

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result).toEqual({ value: 42 });
  });

  it("does not retry the auth endpoints themselves", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    setRefreshHandler(refresh);
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(401, { detail: "no" }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest("/api/v1/auth/refresh", { method: "POST" })).rejects.toBeInstanceOf(
      ApiError,
    );
    expect(refresh).not.toHaveBeenCalled();
  });

  it("propagates the 401 when refresh fails", async () => {
    const refresh = vi.fn().mockResolvedValue(false);
    setRefreshHandler(refresh);
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(401, { detail: "expired" }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest("/api/v1/thing")).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTestQueryClient, installFetchMock } from "@/test/queryHarness";
import {
  useAttackSurfaceSummaryQuery,
  useAuthorizeTarget,
  useRegisterWebTarget,
  useRevokeTarget,
  useTargetsQuery,
} from "./attackSurface";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => vi.unstubAllGlobals());

describe("attack-surface hooks", () => {
  it("lists targets", async () => {
    installFetchMock([{ url: "/targets", body: [{ id: "t1", status: "authorized" }] }]);
    const { result } = renderHook(() => useTargetsQuery("a"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toHaveLength(1);
  });

  it("registers a web target with explicit confirmation", async () => {
    const fetchMock = installFetchMock([
      { method: "POST", url: "/web-target", status: 201, body: { id: "t1" } },
    ]);
    const { result } = renderHook(() => useRegisterWebTarget("a"), { wrapper });
    await result.current.mutateAsync({
      base_url: "https://staging.example.com",
      authorization_statement: "engagement #1",
      confirm_authorized: true,
    });
    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.confirm_authorized).toBe(true);
    expect(body.base_url).toBe("https://staging.example.com");
  });

  it("authorizes and revokes a target at the right endpoints", async () => {
    const fetchMock = installFetchMock([
      { method: "POST", url: "/targets/t1/authorize", body: { id: "t1", status: "authorized" } },
      { method: "POST", url: "/targets/t1/revoke", body: { id: "t1", status: "revoked" } },
    ]);
    const authorize = renderHook(() => useAuthorizeTarget("a"), { wrapper });
    await authorize.result.current.mutateAsync({
      targetId: "t1",
      body: { authorization_statement: "ok", confirm_authorized: true },
    });
    const revoke = renderHook(() => useRevokeTarget("a"), { wrapper });
    await revoke.result.current.mutateAsync("t1");

    expect((fetchMock.mock.calls[0][0] as string)).toContain("/targets/t1/authorize");
    expect((fetchMock.mock.calls[1][0] as string)).toContain("/targets/t1/revoke");
  });

  it("requests the summary with the chosen source", async () => {
    const fetchMock = installFetchMock([
      { url: "/attack-surface/summary", body: { repository: "r", summary: {}, routes: [], issues: [], global_evidence: {} } },
    ]);
    const { result } = renderHook(() => useAttackSurfaceSummaryQuery("a", "live"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect((fetchMock.mock.calls[0][0] as string)).toContain("source=live");
  });
});

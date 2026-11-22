import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTestQueryClient, installFetchMock } from "@/test/queryHarness";
import {
  useCancelWorkflow,
  useDecideApproval,
  useStartWorkflow,
  useWorkflowsQuery,
} from "./workflows";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => vi.unstubAllGlobals());

describe("workflow hooks", () => {
  it("lists workflows", async () => {
    installFetchMock([{ url: "/workflows", body: [{ id: "w1", status: "running" }] }]);
    const { result } = renderHook(() => useWorkflowsQuery("a"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toHaveLength(1);
  });

  it("starts a workflow with the explain toggle", async () => {
    const fetchMock = installFetchMock([
      { method: "POST", url: "/workflows", status: 201, body: { id: "w1", status: "running" } },
    ]);
    const { result } = renderHook(() => useStartWorkflow("a"), { wrapper });
    await result.current.mutateAsync({ explain_findings: true });
    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.explain_findings).toBe(true);
  });

  it("records an approval decision and cancels at the right endpoints", async () => {
    const fetchMock = installFetchMock([
      { method: "POST", url: "/workflows/w1/approvals", body: { id: "w1", status: "running" } },
      { method: "POST", url: "/workflows/w1/cancel", body: { id: "w1", status: "cancelled" } },
    ]);
    const approve = renderHook(() => useDecideApproval("a", "w1"), { wrapper });
    await approve.result.current.mutateAsync({ check: "runtime_probes", decision: "approve", reason: "ok" });
    const cancel = renderHook(() => useCancelWorkflow("a", "w1"), { wrapper });
    await cancel.result.current.mutateAsync();

    expect((fetchMock.mock.calls[0][0] as string)).toContain("/workflows/w1/approvals");
    expect((fetchMock.mock.calls[1][0] as string)).toContain("/workflows/w1/cancel");
  });
});

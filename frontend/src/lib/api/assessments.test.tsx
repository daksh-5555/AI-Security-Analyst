import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTestQueryClient, installFetchMock } from "@/test/queryHarness";
import {
  useAssessmentsQuery,
  useRepositoryTargetQuery,
  useStartAnalysisRun,
} from "./assessments";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => vi.unstubAllGlobals());

const sampleAssessment = {
  id: "a1",
  assessment_type: "repository",
  status: "queued",
  owner_id: null,
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:00:00Z",
};

describe("assessment hooks", () => {
  it("lists assessments", async () => {
    installFetchMock([{ url: "/assessments?limit", body: [sampleAssessment] }]);
    const { result } = renderHook(() => useAssessmentsQuery({ limit: 20, offset: 0 }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toHaveLength(1);
    expect(result.current.data?.[0].id).toBe("a1");
  });

  it("normalizes a 404 repository target to null", async () => {
    installFetchMock([{ url: "/repository", status: 404, body: { detail: "not configured" } }]);
    const { result } = renderHook(() => useRepositoryTargetQuery("a1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toBeNull();
  });

  it("queues an analysis run in async mode", async () => {
    const fetchMock = installFetchMock([
      { method: "POST", url: "/analysis-runs", status: 202, body: { ...sampleAssessment, status: "queued" } },
    ]);
    const { result } = renderHook(() => useStartAnalysisRun("a1"), { wrapper });

    await result.current.mutateAsync();

    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain("/assessments/a1/analysis-runs");
    expect(calledUrl).toContain("mode=async");
  });
});

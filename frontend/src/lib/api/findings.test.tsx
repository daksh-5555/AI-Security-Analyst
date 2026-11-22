import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTestQueryClient, installFetchMock } from "@/test/queryHarness";
import { useFindingsQuery, useGenerateExplanation } from "./findings";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => vi.unstubAllGlobals());

describe("findings hooks", () => {
  it("passes the analysis_run_id filter", async () => {
    const fetchMock = installFetchMock([{ url: "/findings", body: [] }]);
    const { result } = renderHook(
      () => useFindingsQuery("abc", { analysisRunId: "run-1" }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("/assessments/abc/findings");
    expect(url).toContain("analysis_run_id=run-1");
  });

  it("generates an explanation via POST", async () => {
    const fetchMock = installFetchMock([
      { method: "POST", url: "/explanations", status: 201, body: { id: "e1", status: "available" } },
    ]);
    const { result } = renderHook(() => useGenerateExplanation("abc", "f1"), { wrapper });

    await result.current.mutateAsync();

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/findings/f1/explanations");
    expect((init as RequestInit).method).toBe("POST");
  });
});

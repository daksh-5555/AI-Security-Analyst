import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTestQueryClient, installFetchMock } from "@/test/queryHarness";
import { useEvidenceQuery } from "./evidence";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => vi.unstubAllGlobals());

describe("evidence hook", () => {
  it("forwards run filter and pagination params", async () => {
    const fetchMock = installFetchMock([{ url: "/evidence", body: [{ id: "e1" }] }]);
    const { result } = renderHook(
      () => useEvidenceQuery("a", { analysisRunId: "r1", limit: 25, offset: 50 }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("/assessments/a/evidence");
    expect(url).toContain("analysis_run_id=r1");
    expect(url).toContain("limit=25");
    expect(url).toContain("offset=50");
  });
});

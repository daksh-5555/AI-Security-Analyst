import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTestQueryClient, installFetchMock } from "@/test/queryHarness";
import { useReportHtmlQuery, useReportJsonQuery } from "./reports";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => vi.unstubAllGlobals());

describe("report hooks", () => {
  it("fetches the JSON report and forwards the run filter", async () => {
    const fetchMock = installFetchMock([
      { url: "/reports/json", body: { schema_version: "assessment-report/1" } },
    ]);
    const { result } = renderHook(() => useReportJsonQuery("a", "run-9"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.schema_version).toBe("assessment-report/1");
    expect((fetchMock.mock.calls[0][0] as string)).toContain("analysis_run_id=run-9");
  });

  it("fetches the HTML report as raw text with an html Accept header", async () => {
    const fetchMock = installFetchMock([
      { url: "/reports/html", text: "<html><body>Report</body></html>" },
    ]);
    const { result } = renderHook(() => useReportHtmlQuery("a"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toContain("<body>Report</body>");
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers.Accept).toBe("text/html");
  });
});

import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTestQueryClient, installFetchMock } from "@/test/queryHarness";
import { useAuditEventsQuery } from "./audit";

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

afterEach(() => vi.unstubAllGlobals());

describe("audit hook", () => {
  it("forwards filters and pagination", async () => {
    const fetchMock = installFetchMock([
      { url: "/admin/audit-events", body: { items: [], total: 0, limit: 25, offset: 0 } },
    ]);
    const { result } = renderHook(
      () =>
        useAuditEventsQuery({
          action: "assessment.created",
          outcome: "denied",
          assessmentId: "a1",
          limit: 25,
          offset: 25,
        }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("/admin/audit-events");
    expect(url).toContain("action=assessment.created");
    expect(url).toContain("outcome=denied");
    expect(url).toContain("assessment_id=a1");
    expect(url).toContain("offset=25");
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AuditLogsPage } from "./AuditLogsPage";

afterEach(() => vi.unstubAllGlobals());

const event = {
  id: "ev1",
  action: "analysis_run.completed",
  outcome: "success",
  resource_type: "analysis_run",
  resource_id: "r1",
  actor_user_id: "u1",
  assessment_id: "a1",
  occurred_at: "2026-11-20T11:00:00Z",
};

describe("AuditLogsPage", () => {
  it("renders audit events from the admin endpoint", async () => {
    installFetchMock([
      { url: "/admin/audit-events", body: { items: [event], total: 1, limit: 25, offset: 0 } },
    ]);
    renderWithProviders(<AuditLogsPage />, { initialEntries: ["/audit"] });

    // The action also appears as a filter <option>, so match all occurrences.
    expect((await screen.findAllByText("analysis_run.completed")).length).toBeGreaterThan(0);
    // Outcome badge text (also a filter option).
    expect(screen.getAllByText("success").length).toBeGreaterThan(0);
  });

  it("shows an access-denied state for a non-admin (403)", async () => {
    installFetchMock([{ url: "/admin/audit-events", status: 403, body: { detail: "forbidden" } }]);
    renderWithProviders(<AuditLogsPage />, { initialEntries: ["/audit"] });

    expect(await screen.findByText(/access denied/i)).toBeInTheDocument();
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { OverviewPage } from "./OverviewPage";

afterEach(() => vi.unstubAllGlobals());

function assessment(id: string, status: string, type: string) {
  return {
    id,
    assessment_type: type,
    status,
    owner_id: null,
    created_at: "2026-11-20T10:00:00Z",
    updated_at: "2026-11-20T11:00:00Z",
  };
}

describe("OverviewPage", () => {
  it("shows live health and a derived assessment breakdown", async () => {
    installFetchMock([
      { url: "/health", body: { status: "ok" } },
      {
        url: "/assessments",
        body: [
          assessment("a1", "completed", "repository"),
          assessment("a2", "running", "web_security"),
        ],
      },
    ]);
    renderWithProviders(<OverviewPage />, { initialEntries: ["/"] });

    expect(await screen.findByText("Online")).toBeInTheDocument();
    // Honest derived-rollup label, not a fabricated global stat.
    expect(await screen.findByText(/derived from .* assessment/i)).toBeInTheDocument();
    // Status tiles render the real statuses.
    expect(screen.getAllByText("completed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("running").length).toBeGreaterThan(0);
  });

  it("shows an empty state when there are no assessments", async () => {
    installFetchMock([
      { url: "/health", body: { status: "ok" } },
      { url: "/assessments", body: [] },
    ]);
    renderWithProviders(<OverviewPage />, { initialEntries: ["/"] });

    expect(await screen.findAllByText(/no assessments yet/i)).toHaveLength(2);
  });
});

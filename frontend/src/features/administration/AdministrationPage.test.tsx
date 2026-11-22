import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AdministrationPage } from "./AdministrationPage";

afterEach(() => vi.unstubAllGlobals());

const pattern = {
  action: "assessment.access_denied",
  resource_type: "assessment",
  resource_id: "a1",
  actor_user_id: "u1",
  attempt_count: 5,
  first_seen: "2026-11-20T10:00:00Z",
  last_seen: "2026-11-20T11:00:00Z",
};

describe("AdministrationPage", () => {
  it("renders denial patterns from the admin endpoint", async () => {
    installFetchMock([
      {
        url: "/denial-patterns",
        body: { from_time: "2026-11-20T00:00:00Z", to_time: "2026-11-20T12:00:00Z", min_attempts: 2, total: 1, patterns: [pattern] },
      },
    ]);
    renderWithProviders(<AdministrationPage />, { initialEntries: ["/administration"] });

    expect(await screen.findByText("assessment.access_denied")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("shows an access-denied state for a non-admin (403)", async () => {
    installFetchMock([{ url: "/denial-patterns", status: 403, body: { detail: "forbidden" } }]);
    renderWithProviders(<AdministrationPage />, { initialEntries: ["/administration"] });

    expect(await screen.findByText(/access denied/i)).toBeInTheDocument();
  });
});

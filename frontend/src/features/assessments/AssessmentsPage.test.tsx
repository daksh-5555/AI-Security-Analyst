import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AssessmentsPage } from "./AssessmentsPage";

afterEach(() => vi.unstubAllGlobals());

const assessment = {
  id: "a1",
  assessment_type: "repository",
  status: "completed",
  owner_id: null,
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T11:00:00Z",
};

describe("AssessmentsPage", () => {
  it("renders assessments from the API", async () => {
    installFetchMock([{ url: "/assessments?limit", body: [assessment] }]);
    renderWithProviders(<AssessmentsPage />, { initialEntries: ["/assessments"] });

    expect(await screen.findByText("Repository")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
  });

  it("shows an empty state when there are no assessments", async () => {
    installFetchMock([{ url: "/assessments?limit", body: [] }]);
    renderWithProviders(<AssessmentsPage />, { initialEntries: ["/assessments"] });

    await waitFor(() =>
      expect(screen.getByText(/no assessments yet/i)).toBeInTheDocument(),
    );
  });

  it("offers a create action", async () => {
    installFetchMock([{ url: "/assessments?limit", body: [] }]);
    renderWithProviders(<AssessmentsPage />, { initialEntries: ["/assessments"] });

    expect(
      await screen.findByRole("button", { name: /new assessment/i }),
    ).toBeInTheDocument();
  });
});

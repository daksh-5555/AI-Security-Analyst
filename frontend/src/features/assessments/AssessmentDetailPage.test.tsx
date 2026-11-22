import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AssessmentDetailPage } from "./AssessmentDetailPage";

afterEach(() => vi.unstubAllGlobals());

const assessment = {
  id: "abc",
  assessment_type: "repository",
  status: "queued",
  owner_id: null,
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:00:00Z",
};

function renderDetail() {
  renderWithProviders(
    <Routes>
      <Route path="/assessments/:id" element={<AssessmentDetailPage />} />
    </Routes>,
    { initialEntries: ["/assessments/abc"] },
  );
}

describe("AssessmentDetailPage", () => {
  it("shows the overview and gates the run until a source is configured", async () => {
    installFetchMock([
      { url: "/assessments/abc/analysis-runs", body: [] },
      { url: "/assessments/abc/history", body: [] },
      { url: "/assessments/abc/repository", status: 404, body: { detail: "none" } },
      { url: "/assessments/abc", body: assessment },
    ]);

    renderDetail();

    expect(await screen.findByRole("heading", { name: /repository assessment/i })).toBeInTheDocument();
    // Repository source not configured → Start run disabled with a hint.
    expect(
      await screen.findByText(/configure a repository source before running/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start run/i })).toBeDisabled();
  });

  it("surfaces an error when the assessment cannot be loaded", async () => {
    installFetchMock([{ url: "/assessments/abc", status: 500, body: { detail: "boom" } }]);
    renderDetail();

    expect(await screen.findByText(/assessment unavailable/i)).toBeInTheDocument();
  });
});

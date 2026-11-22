import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AssessmentReportPage } from "./AssessmentReportPage";

afterEach(() => vi.unstubAllGlobals());

const report = {
  schema_version: "assessment-report/1",
  generator: { name: "AI Security Analyst", version: "1.0" },
  assessment: { id: "abc", type: "repository", status: "completed", created_at: "2026-11-20T10:00:00Z" },
  run: { id: "r1", status: "completed", completed_at: "2026-11-20T11:00:00Z" },
  executive_summary: ["2 high-severity findings require attention."],
  counts: { total: 2, by_severity: { critical: 0, high: 2, medium: 0, low: 0 }, by_status: { potential: 2 } },
  findings: [{ id: "f1", title: "SQL injection", severity: "high", status: "potential" }],
  findings_omitted: 0,
  limitations: ["Dynamic analysis was not performed."],
};

function renderPage() {
  installFetchMock([
    { url: "/reports/json", body: report },
    { url: "/reports/html", text: "<html><body><h1>Assessment report</h1></body></html>" },
    { url: "/assessments/abc/analysis-runs", body: [] },
    { url: "/assessments/abc", body: { id: "abc", assessment_type: "repository", status: "completed", owner_id: null, created_at: "2026-11-20T10:00:00Z", updated_at: "2026-11-20T10:00:00Z" } },
  ]);
  renderWithProviders(
    <Routes>
      <Route path="/assessments/:id/report" element={<AssessmentReportPage />} />
    </Routes>,
    { initialEntries: ["/assessments/abc/report"] },
  );
}

describe("AssessmentReportPage", () => {
  it("renders the JSON report summary", async () => {
    renderPage();
    expect(await screen.findByText(/2 high-severity findings require attention/i)).toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByText(/Dynamic analysis was not performed/i)).toBeInTheDocument();
  });

  it("renders the sandboxed HTML preview and download actions", async () => {
    renderPage();
    const iframe = await screen.findByTitle("Rendered assessment report");
    expect(iframe).toHaveAttribute("sandbox", "");
    expect(screen.getByRole("button", { name: /^JSON$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^HTML$/i })).toBeInTheDocument();
  });
});

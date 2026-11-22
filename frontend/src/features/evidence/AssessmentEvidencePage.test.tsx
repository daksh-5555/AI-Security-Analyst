import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AssessmentEvidencePage } from "./AssessmentEvidencePage";

afterEach(() => vi.unstubAllGlobals());

const evidence = {
  id: "e1",
  analysis_run_id: "r1",
  source_type: "input_sources",
  summary: "Tainted query parameter reaches a database call",
  evidence_key: "k1",
  method: "static",
  tool_name: "analyzer",
  tool_version: "1.0",
  rule_id: "R1",
  rule_set_version: "v1",
  location_path: "app.py",
  location_line: 42,
  url_path: null,
  parameter: "q",
  observed_at: "2026-11-20T11:00:00Z",
  redacted_excerpt: "SELECT * FROM users WHERE name = '...'",
  request_summary: { method: "GET" },
  response_summary: {},
  details: {},
  limitations: [],
  content_hash: "abc123",
  fingerprint: "fp123",
};

function renderPage() {
  installFetchMock([
    { url: "/assessments/abc/evidence", body: [evidence] },
    { url: "/assessments/abc/analysis-runs", body: [] },
    { url: "/assessments/abc", body: { id: "abc", assessment_type: "repository", status: "completed", owner_id: null, created_at: "2026-11-20T10:00:00Z", updated_at: "2026-11-20T10:00:00Z" } },
  ]);
  renderWithProviders(
    <Routes>
      <Route path="/assessments/:id/evidence" element={<AssessmentEvidencePage />} />
    </Routes>,
    { initialEntries: ["/assessments/abc/evidence"] },
  );
}

describe("AssessmentEvidencePage", () => {
  it("lists evidence and expands to show the redacted detail", async () => {
    renderPage();
    const toggle = await screen.findByRole("button", {
      name: /tainted query parameter reaches a database call/i,
    });
    expect(toggle).toBeInTheDocument();

    await userEvent.click(toggle);

    await waitFor(() => expect(screen.getByText(/redacted excerpt/i)).toBeInTheDocument());
    expect(screen.getByText(/SELECT \* FROM users/i)).toBeInTheDocument();
  });
});

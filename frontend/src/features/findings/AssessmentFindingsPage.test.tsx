import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AssessmentFindingsPage } from "./AssessmentFindingsPage";

afterEach(() => vi.unstubAllGlobals());

const criticalFinding = {
  id: "f1",
  title: "SQL injection in login",
  summary: "User input flows into a query unsanitized.",
  category: "injection",
  confidence: 0.9,
  severity: "critical",
  status: "potential",
  evidence: [{ description: "tainted query at login.py:42", source: "input_sources", details: {} }],
};

const lowFinding = {
  id: "f2",
  title: "Verbose error message",
  summary: "Stack trace exposed.",
  category: "info-leak",
  confidence: 0.4,
  severity: "low",
  status: "potential",
  evidence: [],
};

function renderPage() {
  installFetchMock([
    // More specific URLs first: the mock matches the first containing substring.
    { url: "/assessments/abc/findings/f1/explanations", body: [] },
    { url: "/assessments/abc/analysis-runs", body: [] },
    { url: "/assessments/abc/findings", body: [criticalFinding, lowFinding] },
    { url: "/assessments/abc", body: { id: "abc", assessment_type: "repository", status: "completed", owner_id: null, created_at: "2026-11-20T10:00:00Z", updated_at: "2026-11-20T10:00:00Z" } },
  ]);
  renderWithProviders(
    <Routes>
      <Route path="/assessments/:id/findings" element={<AssessmentFindingsPage />} />
    </Routes>,
    { initialEntries: ["/assessments/abc/findings"] },
  );
}

describe("AssessmentFindingsPage", () => {
  it("lists findings sorted by severity with a severity summary", async () => {
    renderPage();

    expect(await screen.findByText("SQL injection in login")).toBeInTheDocument();
    expect(screen.getByText("Verbose error message")).toBeInTheDocument();

    // Critical appears before low in the DOM order.
    const titles = screen.getAllByText(/SQL injection in login|Verbose error message/);
    expect(titles[0]).toHaveTextContent("SQL injection in login");
  });

  it("reveals the advisory AI explanation panel when a finding is expanded", async () => {
    renderPage();
    await screen.findByText("SQL injection in login");

    await userEvent.click(screen.getByRole("button", { name: /SQL injection in login/i }));

    await waitFor(() => expect(screen.getByText(/advisory only/i)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /generate/i })).toBeInTheDocument();
  });
});

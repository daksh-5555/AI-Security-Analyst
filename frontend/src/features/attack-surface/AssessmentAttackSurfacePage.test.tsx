import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { AssessmentAttackSurfacePage } from "./AssessmentAttackSurfacePage";

afterEach(() => vi.unstubAllGlobals());

const webAssessment = {
  id: "web1",
  assessment_type: "web_security",
  status: "queued",
  owner_id: null,
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:00:00Z",
};

const pendingTarget = {
  id: "t1",
  assessment_id: "web1",
  target: "https://staging.example.com",
  target_type: "web_application",
  status: "pending_authorization",
  authorization_statement: null,
  authorization_basis: null,
  authorized_at: null,
  authorized_by_user_id: null,
  created_by_user_id: null,
  revoked_at: null,
  revoked_by_user_id: null,
  policy_snapshot: {},
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:00:00Z",
};

const summary = {
  repository: "r",
  summary: { route_count: 3, issue_count: 1, input_count: 2, handler_count: 3, call_count: 5, sensitive_operation_count: 0, routes_with_authentication: 1, routes_with_authorization: 0, is_complete: true },
  routes: [{ route_id: "r1", path: "/login", http_method: "POST", framework: "fastapi", handler_name: "login", detection_confidence: 0.9, line_number: 10, source_file: "app.py", issue_ids: ["i1"] }],
  issues: [{ issue_id: "i1", kind: "inspection", category: "xss", explanation: "Reflected input", origins: [], route_http_method: "POST", line_number: 10 }],
  global_evidence: {},
};

function renderPage() {
  installFetchMock([
    { url: "/attack-surface/summary", body: summary },
    { url: "/targets", body: [pendingTarget] },
    { url: "/assessments/web1", body: webAssessment },
  ]);
  renderWithProviders(
    <Routes>
      <Route path="/assessments/:id/attack-surface" element={<AssessmentAttackSurfacePage />} />
    </Routes>,
    { initialEntries: ["/assessments/web1/attack-surface"] },
  );
}

describe("AssessmentAttackSurfacePage", () => {
  it("shows targets and a register action for a web assessment", async () => {
    renderPage();
    expect(await screen.findByText("https://staging.example.com")).toBeInTheDocument();
    expect(screen.getByText(/pending authorization/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /register web target/i })).toBeInTheDocument();
  });

  it("renders the attack-surface summary metrics and routes", async () => {
    renderPage();
    expect(await screen.findByText("Routes")).toBeInTheDocument();
    expect(await screen.findByText("/login")).toBeInTheDocument();
    expect(screen.getByText("Reflected input")).toBeInTheDocument();
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { installFetchMock, renderWithProviders } from "@/test/queryHarness";
import { WorkflowDetailPage } from "./WorkflowDetailPage";

afterEach(() => vi.unstubAllGlobals());

const awaitingWorkflow = {
  id: "w1",
  assessment_id: "abc",
  status: "awaiting_approval",
  current_node: "approval_gate",
  step_count: 2,
  max_steps: 10,
  graph_version: "v1",
  created_at: "2026-11-20T10:00:00Z",
  updated_at: "2026-11-20T10:05:00Z",
  pending_approvals: ["runtime_probes"],
  approvals: {},
  options: {},
  events: [{ sequence: 1, node: "start", outcome: "ok", attempt: 1, occurred_at: "2026-11-20T10:01:00Z" }],
};

function renderPage() {
  installFetchMock([{ url: "/workflows/w1", body: awaitingWorkflow }]);
  renderWithProviders(
    <Routes>
      <Route path="/assessments/:id/workflows/:workflowId" element={<WorkflowDetailPage />} />
    </Routes>,
    { initialEntries: ["/assessments/abc/workflows/w1"] },
  );
}

describe("WorkflowDetailPage", () => {
  it("shows the approval gate and the events timeline", async () => {
    renderPage();
    expect(await screen.findByText(/approval required/i)).toBeInTheDocument();
    expect(screen.getByText("runtime_probes")).toBeInTheDocument();
    expect(screen.getByText("start")).toBeInTheDocument();
  });

  it("requires a reason before recording a decision", async () => {
    renderPage();
    await screen.findByText(/approval required/i);

    await userEvent.click(screen.getByRole("button", { name: /^approve$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/enter a reason/i);
  });
});

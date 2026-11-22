import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthHarness, makeAuthValue } from "@/test/authHarness";
import { RequireAuth } from "./RequireAuth";

function renderGuarded(value: Parameters<typeof AuthHarness>[0]["value"]) {
  render(
    <AuthHarness value={value}>
      <MemoryRouter initialEntries={["/secret"]}>
        <Routes>
          <Route element={<RequireAuth />}>
            <Route path="/secret" element={<div>secret content</div>} />
          </Route>
          <Route path="/login" element={<div>login page</div>} />
        </Routes>
      </MemoryRouter>
    </AuthHarness>,
  );
}

describe("RequireAuth", () => {
  it("redirects an anonymous visitor to the login page", () => {
    renderGuarded(makeAuthValue({ user: null }));
    expect(screen.getByText("login page")).toBeInTheDocument();
    expect(screen.queryByText("secret content")).not.toBeInTheDocument();
  });

  it("renders the protected content for an authenticated user", () => {
    renderGuarded(makeAuthValue());
    expect(screen.getByText("secret content")).toBeInTheDocument();
  });

  it("shows a loader while the session is still resolving", () => {
    renderGuarded(makeAuthValue({ status: "loading", user: null }));
    expect(screen.getByRole("status", { name: /checking your session/i })).toBeInTheDocument();
    expect(screen.queryByText("secret content")).not.toBeInTheDocument();
  });
});

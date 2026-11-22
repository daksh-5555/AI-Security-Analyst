import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Breadcrumbs } from "./Breadcrumbs";
import { ALL_NAV_ITEMS } from "./nav";
import { AuthHarness, makeAuthValue, VIEWER_USER } from "@/test/authHarness";

describe("Sidebar", () => {
  it("renders every navigation item for an admin", () => {
    render(
      <AuthHarness>
        <MemoryRouter>
          <Sidebar collapsed={false} />
        </MemoryRouter>
      </AuthHarness>,
    );
    for (const item of ALL_NAV_ITEMS) {
      expect(screen.getByRole("link", { name: new RegExp(item.label, "i") })).toBeInTheDocument();
    }
  });

  it("hides admin-only items from a non-admin", () => {
    render(
      <AuthHarness value={makeAuthValue({ user: VIEWER_USER })}>
        <MemoryRouter>
          <Sidebar collapsed={false} />
        </MemoryRouter>
      </AuthHarness>,
    );
    expect(screen.queryByRole("link", { name: /administration/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /audit logs/i })).not.toBeInTheDocument();
    // Non-admin routes remain.
    expect(screen.getByRole("link", { name: /findings/i })).toBeInTheDocument();
  });

  it("marks the active route", () => {
    render(
      <AuthHarness>
        <MemoryRouter initialEntries={["/findings"]}>
          <Sidebar collapsed={false} />
        </MemoryRouter>
      </AuthHarness>,
    );
    expect(screen.getByRole("link", { name: /findings/i })).toHaveAttribute("aria-current", "page");
  });
});

describe("Breadcrumbs", () => {
  it("derives a trail from the current route", () => {
    render(
      <MemoryRouter initialEntries={["/attack-surface"]}>
        <Breadcrumbs />
      </MemoryRouter>,
    );
    expect(screen.getByText("Home")).toBeInTheDocument();
    expect(screen.getByText("Attack Surface")).toBeInTheDocument();
  });
});

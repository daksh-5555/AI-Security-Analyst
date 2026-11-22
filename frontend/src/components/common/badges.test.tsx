import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityBadge } from "./SeverityBadge";
import { StatusPill } from "./StatusPill";

describe("SeverityBadge", () => {
  it("renders the given severity label", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });
  it("falls back to an unknown style for unexpected values", () => {
    render(<SeverityBadge severity="banana" />);
    expect(screen.getByText("banana")).toHaveClass("text-severity-unknown");
  });
});

describe("StatusPill", () => {
  it("humanizes the status text", () => {
    render(<StatusPill status="awaiting_approval" />);
    expect(screen.getByText("awaiting approval")).toBeInTheDocument();
  });
});

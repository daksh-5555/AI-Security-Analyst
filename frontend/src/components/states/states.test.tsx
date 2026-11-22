import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { ApiError } from "@/lib/api/client";

describe("EmptyState", () => {
  it("shows title and description", () => {
    render(<EmptyState title="No data yet" description="Nothing to show." />);
    expect(screen.getByText("No data yet")).toBeInTheDocument();
    expect(screen.getByText("Nothing to show.")).toBeInTheDocument();
  });
});

describe("ErrorState", () => {
  it("renders the backend user message and retries", async () => {
    const onRetry = vi.fn();
    render(<ErrorState error={new ApiError(500, { detail: "Server exploded" })} onRetry={onRetry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Server exploded");
    await userEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("shows an access-denied message without a retry for 403", () => {
    render(<ErrorState error={new ApiError(403, null)} onRetry={vi.fn()} />);
    expect(screen.getByText("Access denied")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /try again/i })).not.toBeInTheDocument();
  });
});

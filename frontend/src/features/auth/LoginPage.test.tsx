import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api/client";
import { AuthHarness, makeAuthValue } from "@/test/authHarness";
import { LoginPage } from "./LoginPage";

function renderLogin(login: ReturnType<typeof vi.fn>) {
  render(
    <AuthHarness value={makeAuthValue({ user: null, login })}>
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    </AuthHarness>,
  );
}

describe("LoginPage", () => {
  it("submits trimmed credentials to login", async () => {
    const login = vi.fn().mockResolvedValue(undefined);
    renderLogin(login);

    await userEvent.type(screen.getByLabelText(/email/i), "  me@example.com ");
    await userEvent.type(screen.getByLabelText(/password/i), "a-strong-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(login).toHaveBeenCalledWith("me@example.com", "a-strong-password");
  });

  it("shows the backend message when login fails", async () => {
    const login = vi.fn().mockRejectedValue(new ApiError(401, { detail: "Invalid credentials" }));
    renderLogin(login);

    await userEvent.type(screen.getByLabelText(/email/i), "me@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid credentials");
  });

  it("validates presence before calling login", async () => {
    const login = vi.fn();
    renderLogin(login);

    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(login).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(/email and password/i);
  });
});

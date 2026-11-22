import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "@/lib/api/client";
import { ADMIN_USER } from "@/test/authHarness";
import { clearAccessToken } from "./tokenStore";
import { AuthProvider } from "./AuthProvider";
import { useAuth } from "./authContext";

vi.mock("./authApi", () => ({
  loginRequest: vi.fn(),
  refreshRequest: vi.fn(),
  logoutRequest: vi.fn(),
  meRequest: vi.fn(),
}));

import { loginRequest, logoutRequest, meRequest, refreshRequest } from "./authApi";

const tokenResponse = {
  access_token: "access.token",
  token_type: "bearer" as const,
  expires_in: 900,
  refresh_token: "",
  refresh_expires_in: 1209600,
  session_id: "00000000-0000-0000-0000-0000000000aa",
};

function Probe() {
  const { status, user, login, logout } = useAuth();
  return (
    <div>
      <span data-testid="status">{status}</span>
      <span data-testid="user">{user?.email ?? "none"}</span>
      <button type="button" onClick={() => void login("a@b.com", "pw")}>
        login
      </button>
      <button type="button" onClick={() => void logout()}>
        logout
      </button>
    </div>
  );
}

beforeEach(() => {
  vi.mocked(loginRequest).mockReset();
  vi.mocked(refreshRequest).mockReset();
  vi.mocked(logoutRequest).mockReset();
  vi.mocked(meRequest).mockReset();
});

afterEach(() => clearAccessToken());

describe("AuthProvider", () => {
  it("silently signs in from the refresh cookie on mount", async () => {
    vi.mocked(refreshRequest).mockResolvedValue(tokenResponse);
    vi.mocked(meRequest).mockResolvedValue(ADMIN_USER);

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("authenticated"));
    expect(screen.getByTestId("user")).toHaveTextContent(ADMIN_USER.email);
  });

  it("falls back to anonymous when the refresh cookie is missing or invalid", async () => {
    vi.mocked(refreshRequest).mockRejectedValue(new ApiError(401, null));

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("anonymous"));
    expect(meRequest).not.toHaveBeenCalled();
  });

  it("authenticates after an explicit login", async () => {
    vi.mocked(refreshRequest).mockRejectedValue(new ApiError(401, null));
    vi.mocked(loginRequest).mockResolvedValue(tokenResponse);
    vi.mocked(meRequest).mockResolvedValue(ADMIN_USER);

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("anonymous"));

    await userEvent.click(screen.getByRole("button", { name: "login" }));

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("authenticated"));
    expect(loginRequest).toHaveBeenCalledWith("a@b.com", "pw");
    expect(screen.getByTestId("user")).toHaveTextContent(ADMIN_USER.email);
  });

  it("clears the session on logout", async () => {
    vi.mocked(refreshRequest).mockResolvedValue(tokenResponse);
    vi.mocked(meRequest).mockResolvedValue(ADMIN_USER);
    vi.mocked(logoutRequest).mockResolvedValue(undefined);

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("authenticated"));

    await userEvent.click(screen.getByRole("button", { name: "logout" }));

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("anonymous"));
    expect(logoutRequest).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("user")).toHaveTextContent("none");
  });
});

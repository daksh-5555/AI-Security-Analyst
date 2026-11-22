import type { ReactNode } from "react";
import { vi } from "vitest";
import { AuthContext, type AuthContextValue } from "@/lib/auth/authContext";
import type { CurrentUser } from "@/lib/auth/authApi";

export const ADMIN_USER: CurrentUser = {
  id: "00000000-0000-0000-0000-000000000001",
  email: "analyst@example.com",
  is_active: true,
  is_email_verified: true,
  roles: ["Admin"],
};

export const VIEWER_USER: CurrentUser = {
  ...ADMIN_USER,
  id: "00000000-0000-0000-0000-000000000002",
  email: "viewer@example.com",
  roles: ["Viewer"],
};

/** Build a deterministic auth context value for component tests (no network). */
export function makeAuthValue(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  const user = "user" in overrides ? (overrides.user ?? null) : ADMIN_USER;
  return {
    status: overrides.status ?? (user ? "authenticated" : "anonymous"),
    user,
    login: overrides.login ?? vi.fn(async () => {}),
    logout: overrides.logout ?? vi.fn(async () => {}),
    hasRole: overrides.hasRole ?? ((role: string) => user?.roles.includes(role) ?? false),
  };
}

/** Wrap UI in a stub AuthContext for tests that render auth-aware components. */
export function AuthHarness({
  value = makeAuthValue(),
  children,
}: {
  value?: AuthContextValue;
  children: ReactNode;
}) {
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

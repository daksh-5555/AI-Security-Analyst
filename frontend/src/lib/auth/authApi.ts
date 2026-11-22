/**
 * Thin, typed wrappers over the identity endpoints. These are the only functions
 * that know the auth URL shapes; the rest of the app goes through AuthProvider.
 */
import { apiRequest, type Schema } from "@/lib/api/client";
import { csrfHeaders } from "@/lib/auth/csrf";

export type LoginResult = Schema<"LoginResponse">;
export type RefreshResult = Schema<"RefreshResponse">;
export type CurrentUser = Schema<"CurrentUserResponse">;

const LOGIN_URL = "/api/v1/auth/login";
const REFRESH_URL = "/api/v1/auth/refresh";
const LOGOUT_URL = "/api/v1/auth/logout";
const ME_URL = "/api/v1/auth/me";

/** Exchange credentials for an access token (+ HttpOnly refresh cookie). */
export function loginRequest(email: string, password: string): Promise<LoginResult> {
  return apiRequest<LoginResult>(LOGIN_URL, {
    method: "POST",
    body: { email, password },
    skipAuthRetry: true,
  });
}

/**
 * Rotate the refresh cookie for a new access token. No body is sent: the token
 * travels in the HttpOnly cookie, guarded by the double-submit CSRF header. Never
 * triggers the auto-retry (it is the retry).
 */
export function refreshRequest(): Promise<RefreshResult> {
  return apiRequest<RefreshResult>(REFRESH_URL, {
    method: "POST",
    headers: csrfHeaders(),
    skipAuthRetry: true,
  });
}

/** Revoke the current session and clear the auth cookies. Best-effort. */
export function logoutRequest(): Promise<void> {
  return apiRequest<void>(LOGOUT_URL, { method: "POST", parseJson: false, skipAuthRetry: true });
}

/** Fetch the authenticated principal's safe identity fields. */
export function meRequest(): Promise<CurrentUser> {
  return apiRequest<CurrentUser>(ME_URL);
}

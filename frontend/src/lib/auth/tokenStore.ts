/**
 * In-memory access-token store. The access token is deliberately never written to
 * localStorage, sessionStorage, or a cookie readable by JavaScript: it lives only
 * in this module closure for the lifetime of the page. On reload it is gone and
 * the auth layer silently re-obtains one from the HttpOnly refresh cookie.
 */

interface StoredToken {
  token: string;
  /** Epoch milliseconds at which the access token expires. */
  expiresAt: number;
}

let current: StoredToken | null = null;

/** Store a freshly issued access token and its lifetime (seconds). */
export function setAccessToken(token: string, expiresInSeconds: number): void {
  current = { token, expiresAt: Date.now() + expiresInSeconds * 1000 };
}

/** Return the current access token, or null if none is held. */
export function getAccessToken(): string | null {
  return current?.token ?? null;
}

/** Epoch milliseconds until expiry, or null if no token is held. */
export function getAccessTokenExpiry(): number | null {
  return current?.expiresAt ?? null;
}

/** Forget the access token (on logout or a failed refresh). */
export function clearAccessToken(): void {
  current = null;
}

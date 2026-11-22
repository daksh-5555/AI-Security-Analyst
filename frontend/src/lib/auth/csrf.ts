/**
 * Double-submit CSRF helper. The backend sets a readable `aisa_csrf` cookie on
 * login and refresh; the browser must echo its value in the X-CSRF-Token header
 * on any cookie-sourced refresh. The refresh cookie itself is HttpOnly and is
 * never read here.
 */

export const CSRF_COOKIE_NAME = "aisa_csrf";
export const CSRF_HEADER_NAME = "X-CSRF-Token";

/** Read the readable CSRF cookie value, or null if it is absent. */
export function readCsrfToken(): string | null {
  if (typeof document === "undefined" || !document.cookie) return null;
  for (const part of document.cookie.split(";")) {
    const [rawName, ...rest] = part.trim().split("=");
    if (rawName === CSRF_COOKIE_NAME) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return null;
}

/** The CSRF header object for a refresh request, or empty when no cookie exists. */
export function csrfHeaders(): Record<string, string> {
  const token = readCsrfToken();
  return token ? { [CSRF_HEADER_NAME]: token } : {};
}

import { afterEach, describe, expect, it } from "vitest";
import { CSRF_HEADER_NAME, csrfHeaders, readCsrfToken } from "./csrf";

function clearCookie() {
  document.cookie = "aisa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
}

afterEach(clearCookie);

describe("csrf", () => {
  it("reads the aisa_csrf cookie value", () => {
    document.cookie = "aisa_csrf=token-value-123; path=/";
    expect(readCsrfToken()).toBe("token-value-123");
  });

  it("builds the X-CSRF-Token header when the cookie is present", () => {
    document.cookie = "aisa_csrf=hdr-token; path=/";
    expect(csrfHeaders()).toEqual({ [CSRF_HEADER_NAME]: "hdr-token" });
  });

  it("returns no header when the cookie is absent", () => {
    clearCookie();
    expect(readCsrfToken()).toBeNull();
    expect(csrfHeaders()).toEqual({});
  });
});

import { afterEach, describe, expect, it } from "vitest";
import {
  clearAccessToken,
  getAccessToken,
  getAccessTokenExpiry,
  setAccessToken,
} from "./tokenStore";

afterEach(() => clearAccessToken());

describe("tokenStore", () => {
  it("holds a token and computes an expiry in the future", () => {
    const before = Date.now();
    setAccessToken("abc.def.ghi", 900);
    expect(getAccessToken()).toBe("abc.def.ghi");
    expect(getAccessTokenExpiry()).toBeGreaterThanOrEqual(before + 900 * 1000);
  });

  it("returns null once cleared", () => {
    setAccessToken("tok", 60);
    clearAccessToken();
    expect(getAccessToken()).toBeNull();
    expect(getAccessTokenExpiry()).toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { cn, formatDateTime } from "./utils";

describe("cn", () => {
  it("merges and dedupes tailwind classes (last wins)", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
    expect(cn("text-sm", undefined, null, "font-medium")).toBe("text-sm font-medium");
  });
});

describe("formatDateTime", () => {
  it("renders an em dash for empty values", () => {
    expect(formatDateTime(null)).toBe("—");
    expect(formatDateTime(undefined)).toBe("—");
  });
  it("formats a valid ISO timestamp", () => {
    expect(formatDateTime("2026-11-17T10:00:00Z")).not.toBe("—");
  });
});

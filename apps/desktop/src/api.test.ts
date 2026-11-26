import { describe, expect, it } from "vitest";
import { formatSize, formatTime, shortId } from "./api";

describe("display helpers", () => {
  it("formats byte sizes", () => {
    expect(formatSize(null)).toBe("");
    expect(formatSize(512)).toBe("512 B");
    expect(formatSize(2048)).toBe("2.0 KB");
    expect(formatSize(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatSize(3 * 1024 * 1024 * 1024)).toBe("3.00 GB");
  });

  it("shortens device ids", () => {
    expect(shortId("0123456789abcdef")).toBe("01234567");
  });

  it("formats timestamps", () => {
    const fixed = Date.UTC(2026, 0, 2, 3, 4, 5) / 1000;
    expect(formatTime(fixed)).toMatch(/\d{2}:\d{2}/);
  });
});

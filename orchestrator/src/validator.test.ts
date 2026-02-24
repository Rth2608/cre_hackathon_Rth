import { describe, expect, test } from "bun:test";
import { ValidationError, validateMarketRequest } from "./validator";

describe("validateMarketRequest", () => {
  test("accepts valid request with allowlisted domains", async () => {
    const result = await validateMarketRequest({
      question: "Will BTC close above 100k by 2026-12-31?",
      description: "Demo question",
      sourceUrls: ["https://www.reuters.com/world/us/example"],
      resolutionCriteria: "Use Reuters report as canonical reference",
      submitterAddress: "0x1111111111111111111111111111111111111111"
    });

    expect(result.sourceUrls.length).toBe(1);
    expect(result.question).toContain("BTC");
  });

  test("rejects non-allowlisted domains", async () => {
    await expect(
      validateMarketRequest({
        question: "Q",
        description: "D",
        sourceUrls: ["https://www.not-allowed-example.com/article"],
        resolutionCriteria: "R",
        submitterAddress: "0x1111111111111111111111111111111111111111"
      })
    ).rejects.toBeInstanceOf(ValidationError);
  });
});

import { describe, expect, test } from "bun:test";
import { runAllMockNodes, runMockNode } from "./mockNodes";

const input = {
  question: "Will ETH ETF volume exceed 2B tomorrow?",
  description: "volume threshold",
  sourceUrls: ["https://www.bloomberg.com/news/articles/example"],
  resolutionCriteria: "Bloomberg closing report",
  submitterAddress: "0x1111111111111111111111111111111111111111"
};

describe("mock nodes", () => {
  test("returns deterministic output for same request and node", async () => {
    process.env.MOCK_DISABLE_LATENCY = "true";

    const a = await runMockNode("0xabc", input, "gpt");
    const b = await runMockNode("0xabc", input, "gpt");

    expect(a.verdict).toBe(b.verdict);
    expect(a.confidence).toBe(b.confidence);
    expect(a.reportHash).toBe(b.reportHash);
    expect(a.generatedAt).toBe(b.generatedAt);
  });

  test("collects node failures and still returns successful reports", async () => {
    process.env.MOCK_DISABLE_LATENCY = "true";
    process.env.MOCK_FAIL_NODES = "grok";

    const result = await runAllMockNodes("0xdef", input);

    expect(result.reports.length).toBe(3);
    expect(result.failures.length).toBe(1);
    expect(result.failures[0]?.nodeId).toBe("grok");

    delete process.env.MOCK_FAIL_NODES;
  });
});

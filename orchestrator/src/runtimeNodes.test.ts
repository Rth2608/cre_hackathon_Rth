import { describe, expect, test } from "bun:test";
import { runAllRuntimeNodes, runRuntimeNode } from "./runtimeNodes";
import type { RuntimeNode } from "./types";

const input = {
  question: "Will ETH ETF volume exceed 2B tomorrow?",
  description: "volume threshold",
  sourceUrls: ["https://www.bloomberg.com/news/articles/example"],
  resolutionCriteria: "Bloomberg closing report",
  submitterAddress: "0x1111111111111111111111111111111111111111"
};

describe("runtime node report engine", () => {
  const runtimeNode: RuntimeNode = {
    nodeId: "node-gpt",
    modelFamily: "gpt",
    modelName: "operator-gpt",
    operatorAddress: "0x1111111111111111111111111111111111111111"
  };

  test("returns deterministic output for same request and node", async () => {
    const a = await runRuntimeNode("0xabc", input, runtimeNode);
    const b = await runRuntimeNode("0xabc", input, runtimeNode);

    expect(a.verdict).toBe(b.verdict);
    expect(a.confidence).toBe(b.confidence);
    expect(a.reportHash).toBe(b.reportHash);
  });

  test("returns empty result when runtime node list is empty", async () => {
    const result = await runAllRuntimeNodes("0xdef", input, []);
    expect(result.reports.length).toBe(0);
    expect(result.failures.length).toBe(0);
  });

  test("runs all provided runtime nodes", async () => {
    const otherNode: RuntimeNode = {
      nodeId: "node-gemini",
      modelFamily: "gemini",
      modelName: "operator-gemini",
      operatorAddress: "0x2222222222222222222222222222222222222222"
    };
    const result = await runAllRuntimeNodes("0xdef", input, [runtimeNode, otherNode]);
    expect(result.reports.length).toBe(2);
    expect(result.failures.length).toBe(0);
  });
});

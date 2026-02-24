import { describe, expect, test } from "bun:test";
import { computeConsensus } from "./consensus";
import type { NodeReport } from "./types";

function report(nodeId: NodeReport["nodeId"], verdict: NodeReport["verdict"], confidence: number): NodeReport {
  return {
    requestId: "0xrequest",
    nodeId,
    verdict,
    confidence,
    rationale: "r",
    evidenceSummary: "e",
    reportHash: `0x${nodeId}`,
    generatedAt: "2025-01-01T00:00:00.000Z"
  };
}

describe("computeConsensus", () => {
  test("applies weighted score for 4 responders", () => {
    const result = computeConsensus("0xrequest", [
      report("gpt", "PASS", 0.9),
      report("gemini", "PASS", 0.8),
      report("claude", "PASS", 0.7),
      report("grok", "FAIL", 0.5)
    ]);

    expect(result.status).toBe("OK");
    expect(result.responders).toBe(4);
    expect(result.aggregateScore).toBe(0.475);
    expect(result.finalVerdict).toBe("FAIL");
  });

  test("re-normalizes weights for 3 responders", () => {
    const result = computeConsensus("0xrequest", [
      report("gpt", "PASS", 0.8),
      report("gemini", "PASS", 0.8),
      report("claude", "PASS", 0.8)
    ]);

    expect(result.status).toBe("OK");
    expect(result.responders).toBe(3);
    expect(result.aggregateScore).toBe(0.8);
    expect(result.finalVerdict).toBe("PASS");
  });

  test("fails with no quorum when responders are fewer than 3", () => {
    const result = computeConsensus("0xrequest", [
      report("gpt", "PASS", 0.9),
      report("gemini", "FAIL", 0.7)
    ]);

    expect(result.status).toBe("FAILED_NO_QUORUM");
    expect(result.responders).toBe(2);
    expect(result.finalVerdict).toBe("FAIL");
  });
});

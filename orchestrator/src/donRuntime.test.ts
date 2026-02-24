import { describe, expect, test } from "bun:test";
import { DEFAULT_RUNTIME_NODES, runAllRuntimeNodes } from "./mockNodes";
import { buildSignedRuntimeReports } from "./donRuntime";
import { validateSignedReportsForQuorum } from "./donSignatures";

const SAMPLE_INPUT = {
  question: "Will BTC close above 100k by 2026-12-31?",
  description: "Demo request",
  sourceUrls: ["https://www.reuters.com/world/us/example"],
  resolutionCriteria: "Reuters close report",
  submitterAddress: "0x1111111111111111111111111111111111111111"
};

describe("donRuntime", () => {
  test("builds signed reports and reaches quorum with default operators", async () => {
    const previousDisableLatency = process.env.MOCK_DISABLE_LATENCY;
    process.env.MOCK_DISABLE_LATENCY = "true";
    try {
      const requestId = "0x1111111111111111111111111111111111111111111111111111111111111111";
      const runtimeResult = await runAllRuntimeNodes(requestId, SAMPLE_INPUT, DEFAULT_RUNTIME_NODES);

      const signed = await buildSignedRuntimeReports({
        requestId,
        input: SAMPLE_INPUT,
        nodeReports: runtimeResult.reports,
        runtimeNodes: DEFAULT_RUNTIME_NODES
      });

      expect(signed.signedReports.length).toBe(4);
      expect(signed.executionReceipts.length).toBe(4);
      expect(signed.failures.length).toBe(0);
      expect(signed.attestationRootHash).toMatch(/^0x[0-9a-f]{64}$/);

      const quorum = validateSignedReportsForQuorum(signed.domain, signed.signedReports, {
        minResponders: 3,
        maxResponders: 4
      });
      expect(quorum.quorumReached).toBe(true);
      expect(quorum.invalidReports.length).toBe(0);
    } finally {
      if (previousDisableLatency === undefined) {
        delete process.env.MOCK_DISABLE_LATENCY;
      } else {
        process.env.MOCK_DISABLE_LATENCY = previousDisableLatency;
      }
    }
  });
});

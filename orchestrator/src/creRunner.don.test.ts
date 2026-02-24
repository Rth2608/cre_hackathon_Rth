import { describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { runCreWorkflow } from "./creRunner";
import { DEFAULT_RUNTIME_NODES } from "./mockNodes";
import type { MarketRequestInput } from "./types";
import { resolveProjectPath } from "./utils";

const INPUT: MarketRequestInput = {
  question: "Will BTC close above 100k by 2026-12-31?",
  description: "Demo request",
  sourceUrls: ["https://www.reuters.com/world/us/example"],
  resolutionCriteria: "Reuters close report",
  submitterAddress: "0x1111111111111111111111111111111111111111"
};

describe("runCreWorkflow DON mode", () => {
  test("builds signed reports and consensus bundle", async () => {
    const previousEnv = {
      USE_DON_SIGNED_REPORTS: process.env.USE_DON_SIGNED_REPORTS,
      MOCK_DISABLE_LATENCY: process.env.MOCK_DISABLE_LATENCY,
      NODE_ENDPOINT_VERIFY_ENABLED: process.env.NODE_ENDPOINT_VERIFY_ENABLED
    };

    process.env.USE_DON_SIGNED_REPORTS = "true";
    process.env.MOCK_DISABLE_LATENCY = "true";
    process.env.NODE_ENDPOINT_VERIFY_ENABLED = "false";
    const requestId = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    try {
      const result = await runCreWorkflow({
        requestId,
        input: INPUT,
        activeNodes: [],
        runtimeNodes: DEFAULT_RUNTIME_NODES,
        submitOnchain: async () => ({
          txHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          blockNumber: 1,
          gasUsed: "100000",
          chainId: 1,
          simulated: true
        })
      });

      expect(result.signedNodeReports?.length).toBe(4);
      expect(result.quorumValidation?.quorumReached).toBe(true);
      expect(result.consensusBundle).not.toBeUndefined();
      expect(result.consensusBundle?.reportSignatures.length).toBe(4);
      expect(result.finalStatus).toBe("FINALIZED");
    } finally {
      if (previousEnv.USE_DON_SIGNED_REPORTS === undefined) {
        delete process.env.USE_DON_SIGNED_REPORTS;
      } else {
        process.env.USE_DON_SIGNED_REPORTS = previousEnv.USE_DON_SIGNED_REPORTS;
      }
      if (previousEnv.MOCK_DISABLE_LATENCY === undefined) {
        delete process.env.MOCK_DISABLE_LATENCY;
      } else {
        process.env.MOCK_DISABLE_LATENCY = previousEnv.MOCK_DISABLE_LATENCY;
      }
      if (previousEnv.NODE_ENDPOINT_VERIFY_ENABLED === undefined) {
        delete process.env.NODE_ENDPOINT_VERIFY_ENABLED;
      } else {
        process.env.NODE_ENDPOINT_VERIFY_ENABLED = previousEnv.NODE_ENDPOINT_VERIFY_ENABLED;
      }

      await rm(resolveProjectPath("reports", "artifacts", requestId), { recursive: true, force: true });
      await rm(resolveProjectPath("reports", `${requestId}.json`), { force: true });
    }
  });
});

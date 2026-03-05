import { describe, expect, test } from "bun:test";
import { Wallet } from "ethers";
import { runAllRuntimeNodes } from "./runtimeNodes";
import { buildSignedRuntimeReports } from "./donRuntime";
import { validateSignedReportsForQuorum } from "./donSignatures";
import type { RuntimeNode } from "./types";

const SAMPLE_INPUT = {
  question: "Will BTC close above 100k by 2026-12-31?",
  description: "Demo request",
  sourceUrls: ["https://www.reuters.com/world/us/example"],
  resolutionCriteria: "Reuters close report",
  submitterAddress: "0x1111111111111111111111111111111111111111"
};

describe("donRuntime", () => {
  test("builds signed reports and reaches quorum with configured operators", async () => {
    const previousDonKeys = process.env.DON_OPERATOR_PRIVATE_KEYS_JSON;
    const previousContract = process.env.DON_VERIFIER_CONTRACT;
    const wallets = [Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom()];
    const runtimeNodes: RuntimeNode[] = [
      { nodeId: "node-gpt", modelFamily: "gpt", modelName: "gpt-node", operatorAddress: wallets[0]!.address },
      { nodeId: "node-gemini", modelFamily: "gemini", modelName: "gemini-node", operatorAddress: wallets[1]!.address },
      { nodeId: "node-claude", modelFamily: "claude", modelName: "claude-node", operatorAddress: wallets[2]!.address },
      { nodeId: "node-grok", modelFamily: "grok", modelName: "grok-node", operatorAddress: wallets[3]!.address }
    ];
    process.env.DON_OPERATOR_PRIVATE_KEYS_JSON = JSON.stringify(
      Object.fromEntries(wallets.map((wallet) => [wallet.address.toLowerCase(), wallet.privateKey]))
    );
    process.env.DON_VERIFIER_CONTRACT = "0x1111111111111111111111111111111111111111";

    try {
      const requestId = "0x1111111111111111111111111111111111111111111111111111111111111111";
      const runtimeResult = await runAllRuntimeNodes(requestId, SAMPLE_INPUT, runtimeNodes);

      const signed = await buildSignedRuntimeReports({
        requestId,
        input: SAMPLE_INPUT,
        nodeReports: runtimeResult.reports,
        runtimeNodes
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
      if (previousDonKeys === undefined) {
        delete process.env.DON_OPERATOR_PRIVATE_KEYS_JSON;
      } else {
        process.env.DON_OPERATOR_PRIVATE_KEYS_JSON = previousDonKeys;
      }
      if (previousContract === undefined) {
        delete process.env.DON_VERIFIER_CONTRACT;
      } else {
        process.env.DON_VERIFIER_CONTRACT = previousContract;
      }
    }
  });
});

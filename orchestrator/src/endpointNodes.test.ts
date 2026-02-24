import { describe, expect, test } from "bun:test";
import type { MarketRequestInput, RegisteredNode } from "./types";
import { runAllRuntimeNodesViaEndpoints } from "./endpointNodes";
import type { RuntimeNode } from "./mockNodes";

function sampleInput(): MarketRequestInput {
  return {
    question: "Will BTC close above 100k by 2026-12-31 UTC?",
    description: "demo",
    sourceUrls: ["https://www.reuters.com/world/us/example"],
    resolutionCriteria: "Reuters close report",
    submitterAddress: "0x1111111111111111111111111111111111111111"
  };
}

function activeNode(input: { wallet: string; endpointUrl: string; modelFamily: RuntimeNode["modelFamily"] }): RegisteredNode {
  const now = new Date().toISOString();
  const walletLower = input.wallet.toLowerCase();
  return {
    registrationId: walletLower,
    walletAddress: walletLower,
    nodeId: walletLower,
    selectedModelFamilies: [input.modelFamily],
    modelName: "operator-node",
    endpointUrl: input.endpointUrl,
    endpointStatus: "HEALTHY",
    endpointFailureCount: 0,
    stakeAmount: "1000",
    participationEnabled: true,
    worldIdVerified: true,
    status: "ACTIVE",
    registeredAt: now,
    updatedAt: now
  };
}

describe("endpoint node dispatch", () => {
  test("dispatches report from endpoint /verify", async () => {
    const runtimeNode: RuntimeNode = {
      nodeId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      modelFamily: "gpt",
      modelName: "remote-gpt",
      operatorAddress: "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa"
    };

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input, init) => {
      const url = String(input);
      expect(url).toBe("https://operator-1.example.com/verify");
      expect(init?.method).toBe("POST");

      return new Response(
        JSON.stringify({
          ok: true,
          data: {
            verdict: "PASS",
            confidence: 0.79,
            rationale: "remote rationale",
            evidenceSummary: "remote evidence",
            generatedAt: "2026-01-01T00:00:00.000Z"
          }
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }) as typeof fetch;

    try {
      const result = await runAllRuntimeNodesViaEndpoints({
        requestId: "0x89fc08aae4939f45486abcb2bb6917d08b42e4f7faa5902f78a9f0417eccf008",
        input: sampleInput(),
        runtimeNodes: [runtimeNode],
        activeNodes: [
          activeNode({
            wallet: runtimeNode.operatorAddress,
            endpointUrl: "https://operator-1.example.com",
            modelFamily: runtimeNode.modelFamily
          })
        ],
        timeoutMs: 2000,
        verifyPath: "/verify",
        fallbackToMock: false
      });

      expect(result.failures.length).toBe(0);
      expect(result.reports.length).toBe(1);
      expect(result.reports[0]?.nodeId).toBe(runtimeNode.nodeId);
      expect(result.reports[0]?.verdict).toBe("PASS");
      expect(result.reports[0]?.confidence).toBe(0.79);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("requires signed artifacts when enabled", async () => {
    const runtimeNode: RuntimeNode = {
      nodeId: "0xdddddddddddddddddddddddddddddddddddddddd",
      modelFamily: "grok",
      modelName: "remote-grok",
      operatorAddress: "0xd816d4987b236C45C87B74c1964700fBb274B0E5"
    };
    const requestId = "0x89fc08aae4939f45486abcb2bb6917d08b42e4f7faa5902f78a9f0417eccf008";
    const reportHash = "0x1111111111111111111111111111111111111111111111111111111111111111";

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input: RequestInfo | URL, _init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          ok: true,
          data: {
            report: {
              verdict: "PASS",
              confidence: 0.51,
              rationale: "remote rationale",
              evidenceSummary: "remote evidence",
              generatedAt: "2026-01-01T00:00:00.000Z",
              reportHash
            },
            signedReport: {
              payload: {
                requestId,
                round: 1,
                operator: runtimeNode.operatorAddress,
                modelFamily: runtimeNode.modelFamily,
                modelNameHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                promptTemplateHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                canonicalPromptHash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                paramsHash: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                responseHash: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                executionReceiptHash: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                verdict: "PASS",
                confidenceBps: 5100,
                reportHash,
                timestamp: 1767225600
              },
              signature:
                "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111b"
            },
            executionReceipt: {
              requestId,
              round: 1,
              operator: runtimeNode.operatorAddress,
              modelFamily: runtimeNode.modelFamily,
              modelNameHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              promptTemplateHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              canonicalPromptHash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              paramsHash: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
              responseHash: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
              confidentialAttestationHash:
                "0x1212121212121212121212121212121212121212121212121212121212121212",
              providerRequestIdHash: "0x3434343434343434343434343434343434343434343434343434343434343434",
              startedAt: 1767225599,
              endedAt: 1767225600
            }
          }
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      );
    }) as unknown as typeof fetch;

    try {
      const result = await runAllRuntimeNodesViaEndpoints({
        requestId,
        input: sampleInput(),
        runtimeNodes: [runtimeNode],
        activeNodes: [
          activeNode({
            wallet: runtimeNode.operatorAddress,
            endpointUrl: "https://operator-4.example.com",
            modelFamily: runtimeNode.modelFamily
          })
        ],
        timeoutMs: 2000,
        verifyPath: "/verify",
        fallbackToMock: false,
        requireSignedReports: true
      });

      expect(result.failures.length).toBe(0);
      expect(result.reports.length).toBe(1);
      expect(result.signedReports.length).toBe(1);
      expect(result.executionReceipts.length).toBe(1);
      expect(result.signedReports[0]?.payload.operator.toLowerCase()).toBe(runtimeNode.operatorAddress.toLowerCase());
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("returns endpoint_missing failure when fallback is disabled", async () => {
    const runtimeNode: RuntimeNode = {
      nodeId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      modelFamily: "gemini",
      modelName: "remote-gemini",
      operatorAddress: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
    };

    const result = await runAllRuntimeNodesViaEndpoints({
      requestId: "0x89fc08aae4939f45486abcb2bb6917d08b42e4f7faa5902f78a9f0417eccf008",
      input: sampleInput(),
      runtimeNodes: [runtimeNode],
      activeNodes: [],
      timeoutMs: 2000,
      verifyPath: "/verify",
      fallbackToMock: false
    });

    expect(result.reports.length).toBe(0);
    expect(result.failures.length).toBe(1);
    expect(result.failures[0]?.reason).toBe("endpoint_missing");
  });

  test("falls back to mock when endpoint is missing and fallback is enabled", async () => {
    const runtimeNode: RuntimeNode = {
      nodeId: "0xcccccccccccccccccccccccccccccccccccccccc",
      modelFamily: "claude",
      modelName: "remote-claude",
      operatorAddress: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
    };

    const result = await runAllRuntimeNodesViaEndpoints({
      requestId: "0x89fc08aae4939f45486abcb2bb6917d08b42e4f7faa5902f78a9f0417eccf008",
      input: sampleInput(),
      runtimeNodes: [runtimeNode],
      activeNodes: [],
      timeoutMs: 2000,
      verifyPath: "/verify",
      fallbackToMock: true
    });

    expect(result.failures.length).toBe(0);
    expect(result.reports.length).toBe(1);
    expect(result.reports[0]?.nodeId).toBe(runtimeNode.nodeId);
  });
});

import { describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { Wallet, id } from "ethers";
import { runCreWorkflow } from "./creRunner";
import {
  DON_EIP712_TYPES,
  buildDonDomain,
  signConsensusBundlePayloadByKey,
  signOperatorBundleApprovalByKey,
  toNodeReportTypedDataValue
} from "./donSignatures";
import type { MarketRequestInput, RuntimeNode } from "./types";
import { resolveProjectPath } from "./utils";

const INPUT: MarketRequestInput = {
  question: "Will BTC close above 100k by 2026-12-31?",
  description: "Request used for DON integration test",
  sourceUrls: ["https://www.reuters.com/world/us/example"],
  resolutionCriteria: "Reuters close report",
  submitterAddress: "0x1111111111111111111111111111111111111111"
};

describe("runCreWorkflow DON mode", () => {
  test("builds signed reports and consensus bundle via endpoint operators", async () => {
    const previousEnv = {
      USE_DON_SIGNED_REPORTS: process.env.USE_DON_SIGNED_REPORTS,
      NODE_ENDPOINT_VERIFY_ENABLED: process.env.NODE_ENDPOINT_VERIFY_ENABLED,
      DON_ENDPOINT_BUNDLE_SIGNING_ENABLED: process.env.DON_ENDPOINT_BUNDLE_SIGNING_ENABLED,
      REAL_RUNTIME_ONLY: process.env.REAL_RUNTIME_ONLY,
      CHAIN_ID: process.env.CHAIN_ID,
      DON_VERIFIER_CONTRACT: process.env.DON_VERIFIER_CONTRACT
    };
    const originalFetch = globalThis.fetch;

    const wallets = [Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom()];
    const runtimeNodes: RuntimeNode[] = [
      { nodeId: "node-1", modelFamily: "gpt", modelName: "operator-gpt", operatorAddress: wallets[0]!.address },
      { nodeId: "node-2", modelFamily: "gemini", modelName: "operator-gemini", operatorAddress: wallets[1]!.address },
      { nodeId: "node-3", modelFamily: "claude", modelName: "operator-claude", operatorAddress: wallets[2]!.address },
      { nodeId: "node-4", modelFamily: "grok", modelName: "operator-grok", operatorAddress: wallets[3]!.address }
    ];
    const endpointByOperator = new Map(runtimeNodes.map((node, index) => [node.operatorAddress.toLowerCase(), `https://node-${index + 1}.example.com`]));
    const walletByEndpoint = new Map(
      runtimeNodes.map((node) => [endpointByOperator.get(node.operatorAddress.toLowerCase())!, wallets.find((w) => w.address === node.operatorAddress)!])
    );

    process.env.USE_DON_SIGNED_REPORTS = "true";
    process.env.NODE_ENDPOINT_VERIFY_ENABLED = "true";
    process.env.DON_ENDPOINT_BUNDLE_SIGNING_ENABLED = "true";
    process.env.REAL_RUNTIME_ONLY = "false";
    process.env.CHAIN_ID = "1";
    process.env.DON_VERIFIER_CONTRACT = "0x1111111111111111111111111111111111111111";

    const requestId = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const round = 1;
    const donDomain = buildDonDomain({
      name: "CRE-DON-Consensus",
      version: "1",
      chainId: 1,
      verifyingContract: process.env.DON_VERIFIER_CONTRACT
    });

    globalThis.fetch = (async (input, init) => {
      const url = new URL(String(input));
      const endpoint = `${url.protocol}//${url.host}`;
      const wallet = walletByEndpoint.get(endpoint);
      if (!wallet) {
        return new Response(JSON.stringify({ ok: false, error: "unknown_endpoint" }), { status: 404 });
      }

      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};

      if (url.pathname.endsWith("/healthz")) {
        return new Response(
          JSON.stringify({
            ok: true,
            runtimeNode: {
              promptTemplateHash: id("cre-prediction-market-prompt-template-v1")
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      if (url.pathname.endsWith("/verify")) {
        const node = (body.node as Record<string, unknown>) ?? {};
        const operator = String(node.operatorAddress ?? "");
        const runtimeNode = runtimeNodes.find((candidate) => candidate.operatorAddress.toLowerCase() === operator.toLowerCase());
        const modelFamily = runtimeNode?.modelFamily ?? "gpt";
        const modelName = runtimeNode?.modelName ?? String(node.modelName ?? "operator-node");
        const reportHash = id(`${requestId}:${operator}:report`);
        const generatedAt = "2026-01-01T00:00:00.000Z";

        const payload = {
          requestId,
          round,
          operator,
          modelFamily,
          modelNameHash: id(modelName),
          promptTemplateHash: id("cre-prediction-market-prompt-template-v1"),
          canonicalPromptHash: id(`canonical:${requestId}`),
          paramsHash: id("temperature=0|max_tokens=256"),
          responseHash: id(`response:${operator}`),
          executionReceiptHash: id(`execution:${operator}`),
          verdict: "PASS" as const,
          confidenceBps: 7000,
          reportHash,
          timestamp: 1767225600
        };
        const signature = await wallet.signTypedData(
          donDomain,
          DON_EIP712_TYPES.NODE_REPORT_TYPES,
          toNodeReportTypedDataValue(payload)
        );

        return new Response(
          JSON.stringify({
            ok: true,
            data: {
              report: {
                verdict: "PASS",
                confidence: 0.7,
                rationale: "operator verified",
                evidenceSummary: "operator evidence",
                generatedAt,
                reportHash
              },
              signedReport: {
                payload,
                signature
              },
              executionReceipt: {
                requestId,
                round,
                operator,
                modelFamily,
                modelNameHash: id(modelName),
                promptTemplateHash: id("cre-prediction-market-prompt-template-v1"),
                canonicalPromptHash: id(`canonical:${requestId}`),
                paramsHash: id("temperature=0|max_tokens=256"),
                responseHash: id(`response:${operator}`),
                confidentialAttestationHash: id(`attestation:${operator}`),
                providerRequestIdHash: id(`provider:${operator}`),
                startedAt: 1767225599,
                endedAt: 1767225600
              }
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      if (url.pathname.endsWith("/sign-bundle-approval")) {
        const signed = await signOperatorBundleApprovalByKey(
          donDomain,
          {
            bundleHash: String(body.bundleHash ?? ""),
            requestId: String(body.requestId ?? ""),
            round: Number(body.round ?? 1)
          },
          wallet.privateKey
        );

        return new Response(
          JSON.stringify({
            ok: true,
            data: {
              operator: signed.operator,
              signature: signed.signature
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      if (url.pathname.endsWith("/sign-consensus-bundle")) {
        const payload = body.payload as Record<string, unknown>;
        const signed = await signConsensusBundlePayloadByKey(
          donDomain,
          {
            requestId: String(payload.requestId ?? ""),
            requestHash: String(payload.requestHash ?? ""),
            round: Number(payload.round ?? 1),
            aggregateScoreBps: Number(payload.aggregateScoreBps ?? 0),
            finalVerdict: Boolean(payload.finalVerdict),
            responders: Number(payload.responders ?? 0),
            reportsMerkleRoot: String(payload.reportsMerkleRoot ?? ""),
            attestationRootHash: String(payload.attestationRootHash ?? ""),
            promptTemplateHash: String(payload.promptTemplateHash ?? ""),
            consensusTimestamp: Number(payload.consensusTimestamp ?? 0)
          },
          wallet.privateKey
        );

        return new Response(
          JSON.stringify({
            ok: true,
            data: {
              leader: signed.leader,
              leaderSignature: signed.leaderSignature
            }
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      return new Response(JSON.stringify({ ok: false, error: "unsupported_path" }), { status: 404 });
    }) as typeof fetch;

    try {
      const result = await runCreWorkflow({
        requestId,
        input: INPUT,
        activeNodes: runtimeNodes.map((node) => {
          const now = new Date().toISOString();
          return {
            registrationId: node.operatorAddress.toLowerCase(),
            walletAddress: node.operatorAddress.toLowerCase(),
            nodeId: node.nodeId,
            selectedModelFamilies: [node.modelFamily],
            modelName: node.modelName,
            endpointUrl: endpointByOperator.get(node.operatorAddress.toLowerCase())!,
            endpointStatus: "HEALTHY" as const,
            endpointFailureCount: 0,
            stakeAmount: "1000",
            participationEnabled: true,
            worldIdVerified: true,
            status: "ACTIVE" as const,
            registeredAt: now,
            updatedAt: now
          };
        }),
        runtimeNodes,
        submitOnchain: async () => ({
          txHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          blockNumber: 1,
          gasUsed: "100000",
          chainId: 1,
          simulated: false
        })
      });

      expect(result.signedNodeReports?.length).toBe(4);
      expect(result.quorumValidation?.quorumReached).toBe(true);
      expect(result.consensusBundle).not.toBeUndefined();
      expect(result.consensusBundle?.reportSignatures.length).toBe(4);
      expect(result.finalStatus).toBe("FINALIZED");
    } finally {
      globalThis.fetch = originalFetch;

      if (previousEnv.USE_DON_SIGNED_REPORTS === undefined) delete process.env.USE_DON_SIGNED_REPORTS;
      else process.env.USE_DON_SIGNED_REPORTS = previousEnv.USE_DON_SIGNED_REPORTS;
      if (previousEnv.NODE_ENDPOINT_VERIFY_ENABLED === undefined) delete process.env.NODE_ENDPOINT_VERIFY_ENABLED;
      else process.env.NODE_ENDPOINT_VERIFY_ENABLED = previousEnv.NODE_ENDPOINT_VERIFY_ENABLED;
      if (previousEnv.DON_ENDPOINT_BUNDLE_SIGNING_ENABLED === undefined) delete process.env.DON_ENDPOINT_BUNDLE_SIGNING_ENABLED;
      else process.env.DON_ENDPOINT_BUNDLE_SIGNING_ENABLED = previousEnv.DON_ENDPOINT_BUNDLE_SIGNING_ENABLED;
      if (previousEnv.REAL_RUNTIME_ONLY === undefined) delete process.env.REAL_RUNTIME_ONLY;
      else process.env.REAL_RUNTIME_ONLY = previousEnv.REAL_RUNTIME_ONLY;
      if (previousEnv.CHAIN_ID === undefined) delete process.env.CHAIN_ID;
      else process.env.CHAIN_ID = previousEnv.CHAIN_ID;
      if (previousEnv.DON_VERIFIER_CONTRACT === undefined) delete process.env.DON_VERIFIER_CONTRACT;
      else process.env.DON_VERIFIER_CONTRACT = previousEnv.DON_VERIFIER_CONTRACT;

      await rm(resolveProjectPath("reports", "artifacts", requestId), { recursive: true, force: true });
      await rm(resolveProjectPath("reports", `${requestId}.json`), { force: true });
    }
  });
});

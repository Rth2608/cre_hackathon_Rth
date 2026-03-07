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

  test("uses confidential verifier mode with bearer token when configured", async () => {
    const originalFetch = globalThis.fetch;
    const envKeys = [
      "RUNTIME_NODE_EXECUTION_MODE",
      "RUNTIME_NODE_CRE_VERIFY_URL",
      "RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN",
      "RUNTIME_NODE_CRE_VERIFY_URL_MAP_JSON",
      "RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN_MAP_JSON"
    ] as const;
    const envSnapshot = new Map<string, string | undefined>(envKeys.map((key) => [key, process.env[key]]));

    let requestedUrl = "";
    let requestedAuth = "";

    try {
      process.env.RUNTIME_NODE_EXECUTION_MODE = "cre_confidential_http";
      process.env.RUNTIME_NODE_CRE_VERIFY_URL = "https://verifier.example/verify";
      process.env.RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN = "worker-token";
      delete process.env.RUNTIME_NODE_CRE_VERIFY_URL_MAP_JSON;
      delete process.env.RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN_MAP_JSON;

      globalThis.fetch = (async (input, init) => {
        requestedUrl = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        const headers = new Headers((init?.headers as HeadersInit | undefined) ?? {});
        requestedAuth = headers.get("authorization") ?? "";

        return new Response(
          JSON.stringify({
            ok: true,
            data: {
              report: {
                verdict: "PASS",
                confidence: 0.91,
                rationale: "Confidential evaluator accepted the request.",
                evidenceSummary: "embedding similarity and policy checks passed.",
                generatedAt: "2026-03-06T00:00:00.000Z",
                reportHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              }
            }
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json"
            }
          }
        );
      }) as typeof fetch;

      const report = await runRuntimeNode("0xabc", input, runtimeNode);
      expect(report.verdict).toBe("PASS");
      expect(report.confidence).toBe(0.91);
      expect(report.reportHash).toBe("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      expect(requestedUrl).toBe("https://verifier.example/verify");
      expect(requestedAuth).toBe("Bearer worker-token");
    } finally {
      globalThis.fetch = originalFetch;
      for (const [key, value] of envSnapshot.entries()) {
        if (value === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = value;
        }
      }
    }
  });

  test("uses family map URL/token overrides in confidential verifier mode", async () => {
    const originalFetch = globalThis.fetch;
    const envKeys = [
      "RUNTIME_NODE_EXECUTION_MODE",
      "RUNTIME_NODE_CRE_VERIFY_URL",
      "RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN",
      "RUNTIME_NODE_CRE_VERIFY_URL_MAP_JSON",
      "RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN_MAP_JSON"
    ] as const;
    const envSnapshot = new Map<string, string | undefined>(envKeys.map((key) => [key, process.env[key]]));

    let requestedUrl = "";
    let requestedAuth = "";

    try {
      process.env.RUNTIME_NODE_EXECUTION_MODE = "cre_confidential_http";
      process.env.RUNTIME_NODE_CRE_VERIFY_URL = "https://fallback.example/verify";
      process.env.RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN = "fallback-token";
      process.env.RUNTIME_NODE_CRE_VERIFY_URL_MAP_JSON = JSON.stringify({
        gpt: "https://family-gpt.example/verify"
      });
      process.env.RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN_MAP_JSON = JSON.stringify({
        gpt: "family-token"
      });

      globalThis.fetch = (async (input, init) => {
        requestedUrl = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        const headers = new Headers((init?.headers as HeadersInit | undefined) ?? {});
        requestedAuth = headers.get("authorization") ?? "";

        return new Response(
          JSON.stringify({
            verdict: "FAIL",
            confidence: 0.22,
            rationale: "Policy screening rejected the request.",
            evidenceSummary: "duplicate/conflict risk detected."
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json"
            }
          }
        );
      }) as typeof fetch;

      const report = await runRuntimeNode("0xabc", input, runtimeNode);
      expect(report.verdict).toBe("FAIL");
      expect(report.confidence).toBe(0.22);
      expect(requestedUrl).toBe("https://family-gpt.example/verify");
      expect(requestedAuth).toBe("Bearer family-token");
    } finally {
      globalThis.fetch = originalFetch;
      for (const [key, value] of envSnapshot.entries()) {
        if (value === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = value;
        }
      }
    }
  });
});

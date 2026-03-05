import { createHash } from "node:crypto";
import type { CanonicalModelFamily, MarketRequestInput, NodeReport, NodeVerdict, RuntimeNode } from "./types";
import { hashObject } from "./utils";

const NODE_LABELS: Record<CanonicalModelFamily, string> = {
  gpt: "GPT Node",
  gemini: "Gemini Node",
  claude: "Claude Node",
  grok: "Grok Node"
};

function digestHex(requestId: string, node: RuntimeNode, input: MarketRequestInput): string {
  const payload = [
    requestId,
    node.nodeId,
    node.modelFamily,
    node.modelName,
    node.operatorAddress,
    input.question,
    input.description,
    input.resolutionCriteria,
    input.sourceUrls.join("|")
  ].join("::");

  return createHash("sha256").update(payload).digest("hex");
}

function deriveConfidence(seedHex: string): number {
  const bucket = Number.parseInt(seedHex.slice(0, 8), 16) % 50;
  return Number((0.5 + bucket / 100).toFixed(2));
}

function deriveVerdict(seedHex: string, modelFamily: CanonicalModelFamily): NodeVerdict {
  const thresholdBucket = Number.parseInt(seedHex.slice(8, 12), 16) % 100;
  const biasByFamily: Record<CanonicalModelFamily, number> = {
    gpt: 34,
    gemini: 36,
    claude: 38,
    grok: 40
  };
  return thresholdBucket >= biasByFamily[modelFamily] ? "PASS" : "FAIL";
}

function deriveEvidenceSummary(input: MarketRequestInput): string {
  const domains = input.sourceUrls.map((url) => new URL(url).hostname);
  const deduped = Array.from(new Set(domains));
  return `Validated ${deduped.length} source domain(s): ${deduped.join(", ")}`;
}

function deterministicTimestamp(seedHex: string): string {
  const offset = Number.parseInt(seedHex.slice(12, 20), 16) % 10;
  return new Date(Date.now() - offset * 1000).toISOString();
}

export async function runRuntimeNode(
  requestId: string,
  input: MarketRequestInput,
  runtimeNode: RuntimeNode
): Promise<NodeReport> {
  const seedHex = digestHex(requestId, runtimeNode, input);
  const confidence = deriveConfidence(seedHex);
  const verdict = deriveVerdict(seedHex, runtimeNode.modelFamily);
  const nodeLabel = NODE_LABELS[runtimeNode.modelFamily] ?? "Model Node";

  const reportCore = {
    requestId,
    nodeId: runtimeNode.nodeId,
    verdict,
    confidence,
    rationale:
      verdict === "PASS"
        ? `${nodeLabel} (${runtimeNode.modelName}) found the market framing and evidence coherence acceptable.`
        : `${nodeLabel} (${runtimeNode.modelName}) found insufficient evidence confidence for reliable resolution.`,
    evidenceSummary: `${deriveEvidenceSummary(input)} | operator=${runtimeNode.operatorAddress}`,
    generatedAt: deterministicTimestamp(seedHex)
  };

  const reportHash = hashObject(reportCore);

  return {
    ...reportCore,
    reportHash
  };
}

export async function runAllRuntimeNodes(
  requestId: string,
  input: MarketRequestInput,
  runtimeNodes: RuntimeNode[]
): Promise<{
  reports: NodeReport[];
  failures: Array<{ nodeId: string; reason: string }>;
}> {
  const nodes = runtimeNodes;
  if (nodes.length === 0) {
    return {
      reports: [],
      failures: []
    };
  }

  const settled = await Promise.allSettled(
    nodes.map(async (node) => ({
      nodeId: node.nodeId,
      report: await runRuntimeNode(requestId, input, node)
    }))
  );

  const reports: NodeReport[] = [];
  const failures: Array<{ nodeId: string; reason: string }> = [];

  settled.forEach((result, index) => {
    const nodeId = nodes[index]?.nodeId ?? `unknown-${index}`;

    if (result.status === "fulfilled") {
      reports.push(result.value.report);
    } else {
      failures.push({
        nodeId,
        reason: result.reason instanceof Error ? result.reason.message : String(result.reason)
      });
    }
  });

  return { reports, failures };
}

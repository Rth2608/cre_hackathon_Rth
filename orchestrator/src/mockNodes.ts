import { createHash } from "node:crypto";
import type { CanonicalModelFamily, MarketRequestInput, NodeId, NodeReport, NodeVerdict } from "./types";
import { hashObject } from "./utils";
import { DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID } from "./donOperatorKeys";

export interface RuntimeNode {
  nodeId: NodeId;
  modelFamily: CanonicalModelFamily;
  modelName: string;
  operatorAddress: string;
}

export const DEFAULT_RUNTIME_NODES: RuntimeNode[] = [
  {
    nodeId: "gpt",
    modelFamily: "gpt",
    modelName: "mock-gpt",
    operatorAddress: DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID.gpt ?? "0x1111111111111111111111111111111111111111"
  },
  {
    nodeId: "gemini",
    modelFamily: "gemini",
    modelName: "mock-gemini",
    operatorAddress: DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID.gemini ?? "0x2222222222222222222222222222222222222222"
  },
  {
    nodeId: "claude",
    modelFamily: "claude",
    modelName: "mock-claude",
    operatorAddress: DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID.claude ?? "0x3333333333333333333333333333333333333333"
  },
  {
    nodeId: "grok",
    modelFamily: "grok",
    modelName: "mock-grok",
    operatorAddress: DEFAULT_DON_OPERATOR_ADDRESS_BY_NODE_ID.grok ?? "0x4444444444444444444444444444444444444444"
  }
];

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
  const base = Date.UTC(2025, 0, 1, 0, 0, 0);
  const offset = Number.parseInt(seedHex.slice(12, 20), 16) % (30 * 24 * 3600);
  return new Date(base + offset * 1000).toISOString();
}

function deterministicLatency(seedHex: string): number {
  return 120 + (Number.parseInt(seedHex.slice(20, 24), 16) % 380);
}

function shouldFailNode(nodeId: NodeId): boolean {
  const raw = process.env.MOCK_FAIL_NODES ?? "";
  const failures = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  return failures.includes(nodeId);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runMockNode(requestId: string, input: MarketRequestInput, nodeId: NodeId): Promise<NodeReport> {
  const runtimeNode = DEFAULT_RUNTIME_NODES.find((node) => node.nodeId === nodeId) ?? {
    nodeId,
    modelFamily: "gpt",
    modelName: "mock-custom",
    operatorAddress: "0x0000000000000000000000000000000000000000"
  };
  return runRuntimeNode(requestId, input, runtimeNode);
}

export async function runRuntimeNode(
  requestId: string,
  input: MarketRequestInput,
  runtimeNode: RuntimeNode
): Promise<NodeReport> {
  if (shouldFailNode(runtimeNode.nodeId)) {
    throw new Error(`${runtimeNode.nodeId} simulated failure`);
  }

  const seedHex = digestHex(requestId, runtimeNode, input);
  const latencyMs = deterministicLatency(seedHex);

  if (process.env.MOCK_DISABLE_LATENCY !== "true") {
    await sleep(latencyMs);
  }

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

export async function runAllMockNodes(requestId: string, input: MarketRequestInput): Promise<{
  reports: NodeReport[];
  failures: Array<{ nodeId: NodeId; reason: string }>;
}> {
  return runAllRuntimeNodes(requestId, input, DEFAULT_RUNTIME_NODES);
}

export async function runAllRuntimeNodes(
  requestId: string,
  input: MarketRequestInput,
  runtimeNodes: RuntimeNode[]
): Promise<{
  reports: NodeReport[];
  failures: Array<{ nodeId: NodeId; reason: string }>;
}> {
  const nodes = runtimeNodes.length > 0 ? runtimeNodes : DEFAULT_RUNTIME_NODES;

  const settled = await Promise.allSettled(
    nodes.map(async (node) => ({
      nodeId: node.nodeId,
      report: await runRuntimeNode(requestId, input, node)
    }))
  );

  const reports: NodeReport[] = [];
  const failures: Array<{ nodeId: NodeId; reason: string }> = [];

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

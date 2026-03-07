import { createHash } from "node:crypto";
import type { CanonicalModelFamily, MarketRequestInput, NodeReport, NodeVerdict, RuntimeNode } from "./types";
import { hashObject } from "./utils";

const NODE_LABELS: Record<CanonicalModelFamily, string> = {
  gpt: "GPT Node",
  gemini: "Gemini Node",
  claude: "Claude Node",
  grok: "Grok Node"
};

type RuntimeNodeExecutionMode = "deterministic" | "cre_confidential_http";

interface RuntimeNodeVerifierConfig {
  mode: RuntimeNodeExecutionMode;
  timeoutMs: number;
  endpointUrl?: string;
  authToken?: string;
}

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
  const baseEpochMs = Date.UTC(2026, 0, 1, 0, 0, 0);
  const offsetSeconds = Number.parseInt(seedHex.slice(12, 20), 16) % (365 * 24 * 60 * 60);
  return new Date(baseEpochMs + offsetSeconds * 1000).toISOString();
}

function parseJsonStringMap(raw: string | undefined): Record<string, string> {
  if (!raw || !raw.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }

    const output: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof key !== "string") {
        continue;
      }
      if (typeof value !== "string") {
        continue;
      }

      const normalizedKey = key.trim().toLowerCase();
      const normalizedValue = value.trim();
      if (!normalizedKey || !normalizedValue) {
        continue;
      }
      output[normalizedKey] = normalizedValue;
    }
    return output;
  } catch {
    return {};
  }
}

function resolveRuntimeNodeExecutionMode(): RuntimeNodeExecutionMode {
  const raw = process.env.RUNTIME_NODE_EXECUTION_MODE?.trim().toLowerCase();
  if (raw === "cre_confidential_http" || raw === "cre") {
    return "cre_confidential_http";
  }
  return "deterministic";
}

function resolveTimeoutMs(): number {
  const parsed = Number.parseInt(process.env.RUNTIME_NODE_CRE_VERIFY_TIMEOUT_MS ?? "12000", 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 60_000) {
    return 12_000;
  }
  return parsed;
}

function resolveMappedValue(
  rawMap: string | undefined,
  runtimeNode: RuntimeNode
): string | undefined {
  const map = parseJsonStringMap(rawMap);
  const byNodeId = map[runtimeNode.nodeId.trim().toLowerCase()];
  if (byNodeId) {
    return byNodeId;
  }
  const byOperator = map[runtimeNode.operatorAddress.trim().toLowerCase()];
  if (byOperator) {
    return byOperator;
  }
  const byFamily = map[runtimeNode.modelFamily.trim().toLowerCase()];
  if (byFamily) {
    return byFamily;
  }
  return undefined;
}

function resolveRuntimeNodeVerifierConfig(runtimeNode: RuntimeNode): RuntimeNodeVerifierConfig {
  const mode = resolveRuntimeNodeExecutionMode();
  const timeoutMs = resolveTimeoutMs();
  if (mode === "deterministic") {
    return {
      mode,
      timeoutMs
    };
  }

  const endpointUrl =
    resolveMappedValue(process.env.RUNTIME_NODE_CRE_VERIFY_URL_MAP_JSON, runtimeNode) ??
    process.env.RUNTIME_NODE_CRE_VERIFY_URL?.trim();
  const authToken =
    resolveMappedValue(process.env.RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN_MAP_JSON, runtimeNode) ??
    process.env.RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN?.trim();

  return {
    mode,
    timeoutMs,
    endpointUrl: endpointUrl && endpointUrl.length > 0 ? endpointUrl : undefined,
    authToken: authToken && authToken.length > 0 ? authToken : undefined
  };
}

function normalizeGeneratedAt(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) {
    return new Date().toISOString();
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return new Date().toISOString();
  }
  return new Date(parsed).toISOString();
}

function extractReportPayload(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const top = value as Record<string, unknown>;
  const data =
    top.data && typeof top.data === "object" && !Array.isArray(top.data) ? (top.data as Record<string, unknown>) : top;
  const report =
    data.report && typeof data.report === "object" && !Array.isArray(data.report)
      ? (data.report as Record<string, unknown>)
      : data;
  return report;
}

function toAuditTrailSegment(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "";
  }
  const record = value as Record<string, unknown>;
  const providerRequestId =
    typeof record.providerRequestId === "string"
      ? record.providerRequestId
      : typeof record.provider_request_id === "string"
        ? record.provider_request_id
        : "";
  const policyVersion = typeof record.policyVersion === "string" ? record.policyVersion : "";
  const segments = [providerRequestId ? `providerRequestId=${providerRequestId}` : "", policyVersion ? `policyVersion=${policyVersion}` : ""].filter(
    Boolean
  );
  return segments.join(" ");
}

function parseConfidentialVerifierResponse(args: {
  requestId: string;
  runtimeNode: RuntimeNode;
  payload: unknown;
}): NodeReport {
  if (args.payload && typeof args.payload === "object" && !Array.isArray(args.payload)) {
    const topLevel = args.payload as Record<string, unknown>;
    const result = topLevel.result;
    if (result && typeof result === "object" && !Array.isArray(result)) {
      const status = String((result as Record<string, unknown>).status ?? "").toUpperCase();
      if (status === "ACCEPTED") {
        throw new Error(
          "confidential_verifier_async_gateway_response: CRE gateway accepted execution but did not return a report payload. Use an adapter endpoint that waits for execution output and returns { report: ... }."
        );
      }
    }
  }

  const reportPayload = extractReportPayload(args.payload);
  const verdictRaw = typeof reportPayload.verdict === "string" ? reportPayload.verdict.trim().toUpperCase() : "";
  if (verdictRaw !== "PASS" && verdictRaw !== "FAIL") {
    throw new Error(`confidential_verifier_invalid_verdict:${verdictRaw || "missing"}`);
  }
  const confidence = Number(reportPayload.confidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("confidential_verifier_invalid_confidence");
  }

  const rationaleRaw =
    typeof reportPayload.rationale === "string" && reportPayload.rationale.trim()
      ? reportPayload.rationale.trim()
      : `${NODE_LABELS[args.runtimeNode.modelFamily] ?? "Model Node"} returned no rationale.`;
  const evidenceRaw =
    typeof reportPayload.evidenceSummary === "string" && reportPayload.evidenceSummary.trim()
      ? reportPayload.evidenceSummary.trim()
      : "No evidence summary returned.";

  const auditTrail = toAuditTrailSegment(
    (args.payload as Record<string, unknown>)?.data && typeof (args.payload as Record<string, unknown>).data === "object"
      ? (args.payload as Record<string, unknown>).data
      : args.payload
  );
  const evidenceSummary = auditTrail ? `${evidenceRaw} | ${auditTrail}` : evidenceRaw;

  const baseReport = {
    requestId: args.requestId,
    nodeId: args.runtimeNode.nodeId,
    verdict: verdictRaw as NodeVerdict,
    confidence,
    rationale: rationaleRaw,
    evidenceSummary,
    generatedAt: normalizeGeneratedAt(reportPayload.generatedAt)
  };

  const reportHashCandidate = typeof reportPayload.reportHash === "string" ? reportPayload.reportHash.trim().toLowerCase() : "";
  const reportHash = /^0x[0-9a-f]{64}$/.test(reportHashCandidate) ? reportHashCandidate : hashObject(baseReport);

  return {
    ...baseReport,
    reportHash
  };
}

async function runRuntimeNodeDeterministic(
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

async function runRuntimeNodeViaConfidentialVerifier(
  requestId: string,
  input: MarketRequestInput,
  runtimeNode: RuntimeNode,
  config: RuntimeNodeVerifierConfig
): Promise<NodeReport> {
  if (!config.endpointUrl) {
    throw new Error("RUNTIME_NODE_CRE_VERIFY_URL (or *_URL_MAP_JSON) is required when RUNTIME_NODE_EXECUTION_MODE=cre_confidential_http");
  }

  const headers = new Headers({
    "Content-Type": "application/json",
    "X-Cre-Request-Id": requestId,
    "X-Cre-Operator-Address": runtimeNode.operatorAddress,
    "X-Cre-Node-Id": runtimeNode.nodeId,
    "X-Cre-Model-Family": runtimeNode.modelFamily
  });
  if (config.authToken) {
    headers.set("Authorization", `Bearer ${config.authToken}`);
  }

  const response = await fetch(config.endpointUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({
      requestId,
      input,
      node: {
        nodeId: runtimeNode.nodeId,
        modelFamily: runtimeNode.modelFamily,
        modelName: runtimeNode.modelName,
        operatorAddress: runtimeNode.operatorAddress
      }
    }),
    signal: AbortSignal.timeout(config.timeoutMs)
  });

  if (!response.ok) {
    throw new Error(`confidential_verifier_http_${response.status}`);
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("confidential_verifier_invalid_json");
  }

  return parseConfidentialVerifierResponse({
    requestId,
    runtimeNode,
    payload
  });
}

export async function runRuntimeNode(
  requestId: string,
  input: MarketRequestInput,
  runtimeNode: RuntimeNode
): Promise<NodeReport> {
  const config = resolveRuntimeNodeVerifierConfig(runtimeNode);
  if (config.mode === "cre_confidential_http") {
    return runRuntimeNodeViaConfidentialVerifier(requestId, input, runtimeNode, config);
  }
  return runRuntimeNodeDeterministic(requestId, input, runtimeNode);
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

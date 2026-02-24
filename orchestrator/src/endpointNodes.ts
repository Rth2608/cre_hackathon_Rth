import { getAddress } from "ethers";
import {
  buildDonDomain,
  verifyConsensusBundleLeaderSignature,
  verifyOperatorBundleApprovalSignature,
  type DonEip712Domain
} from "./donSignatures";
import type {
  ConsensusBundle,
  ExecutionReceipt,
  MarketRequestInput,
  NodeId,
  NodeReport,
  RegisteredNode,
  SignedNodeReport
} from "./types";
import { runRuntimeNode, type RuntimeNode } from "./mockNodes";
import { hashObject, nowIso } from "./utils";

interface EndpointDispatchParams {
  requestId: string;
  input: MarketRequestInput;
  runtimeNodes: RuntimeNode[];
  activeNodes: RegisteredNode[];
  timeoutMs: number;
  verifyPath: string;
  fallbackToMock: boolean;
  requireSignedReports?: boolean;
}

function normalizeNodeId(value: string): string {
  return value.trim().toLowerCase();
}

function resolveEndpointForRuntimeNode(runtimeNode: RuntimeNode, activeNodes: RegisteredNode[]): string | undefined {
  const operator = normalizeNodeId(runtimeNode.operatorAddress);
  const nodeId = normalizeNodeId(runtimeNode.nodeId);

  const byOperator = activeNodes.find((node) => normalizeNodeId(node.walletAddress) === operator && node.endpointUrl);
  if (byOperator?.endpointUrl) {
    return byOperator.endpointUrl;
  }

  const byNodeId = activeNodes.find((node) => normalizeNodeId(node.nodeId) === nodeId && node.endpointUrl);
  if (byNodeId?.endpointUrl) {
    return byNodeId.endpointUrl;
  }

  return undefined;
}

function ensureVerifyPath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed) return "/verify";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function buildEndpointUrl(endpointUrl: string, endpointPath: string): string {
  const parsed = new URL(endpointUrl.trim());
  const normalizedPath = ensureVerifyPath(endpointPath);

  if (parsed.pathname.endsWith(normalizedPath)) {
    return parsed.toString().replace(/\/$/, "");
  }

  const base = endpointUrl.endsWith("/") ? endpointUrl : `${endpointUrl}/`;
  return new URL(normalizedPath.replace(/^\//, ""), base).toString();
}

function parseReportFromEndpoint(args: {
  requestId: string;
  runtimeNode: RuntimeNode;
  payload: unknown;
}): NodeReport {
  const source = (args.payload as Record<string, unknown>) ?? {};
  const data = (source.data as Record<string, unknown>) ?? source;

  const verdictRaw = String(data.verdict ?? "").toUpperCase();
  if (verdictRaw !== "PASS" && verdictRaw !== "FAIL") {
    throw new Error(`invalid_verdict:${verdictRaw || "missing"}`);
  }

  const confidence = Number(data.confidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("invalid_confidence");
  }

  const rationale = String(data.rationale ?? "").trim() || "Endpoint node returned verdict without rationale.";
  const evidenceSummary = String(data.evidenceSummary ?? "").trim() || "Endpoint node returned no evidence summary.";
  const generatedAtRaw = String(data.generatedAt ?? "").trim();
  const generatedAt = Number.isNaN(Date.parse(generatedAtRaw)) ? nowIso() : new Date(generatedAtRaw).toISOString();

  const baseReport = {
    requestId: args.requestId,
    nodeId: args.runtimeNode.nodeId,
    verdict: verdictRaw as NodeReport["verdict"],
    confidence,
    rationale,
    evidenceSummary,
    generatedAt
  };

  const reportHashCandidate = String(data.reportHash ?? "").trim();
  const reportHash = /^0x[0-9a-fA-F]{64}$/.test(reportHashCandidate)
    ? reportHashCandidate.toLowerCase()
    : hashObject(baseReport);

  return {
    ...baseReport,
    reportHash
  };
}

function normalizeAddress(value: string): string {
  return getAddress(value).toLowerCase();
}

function parseSignedReportFromEndpoint(args: {
  requestId: string;
  runtimeNode: RuntimeNode;
  report: NodeReport;
  payload: unknown;
}): SignedNodeReport | undefined {
  if (!args.payload || typeof args.payload !== "object") {
    return undefined;
  }

  const candidate = args.payload as Record<string, unknown>;
  const payload = candidate.payload as Record<string, unknown> | undefined;
  const signatureRaw = candidate.signature;
  if (!payload || typeof signatureRaw !== "string") {
    return undefined;
  }

  const operatorRaw = String(payload.operator ?? "");
  const requestIdRaw = String(payload.requestId ?? "");
  const reportHashRaw = String(payload.reportHash ?? "");
  const modelFamilyRaw = String(payload.modelFamily ?? "").toLowerCase();

  if (requestIdRaw.toLowerCase() !== args.requestId.toLowerCase()) {
    throw new Error("signed_report_request_id_mismatch");
  }
  if (modelFamilyRaw !== args.runtimeNode.modelFamily) {
    throw new Error("signed_report_model_family_mismatch");
  }
  if (normalizeAddress(operatorRaw) !== normalizeAddress(args.runtimeNode.operatorAddress)) {
    throw new Error("signed_report_operator_mismatch");
  }
  if (reportHashRaw.toLowerCase() !== args.report.reportHash.toLowerCase()) {
    throw new Error("signed_report_hash_mismatch");
  }

  return candidate as unknown as SignedNodeReport;
}

function parseExecutionReceiptFromEndpoint(args: {
  requestId: string;
  runtimeNode: RuntimeNode;
  payload: unknown;
}): ExecutionReceipt | undefined {
  if (!args.payload || typeof args.payload !== "object") {
    return undefined;
  }

  const candidate = args.payload as Record<string, unknown>;
  const requestIdRaw = String(candidate.requestId ?? "");
  const operatorRaw = String(candidate.operator ?? "");
  const modelFamilyRaw = String(candidate.modelFamily ?? "").toLowerCase();

  if (requestIdRaw.toLowerCase() !== args.requestId.toLowerCase()) {
    throw new Error("execution_receipt_request_id_mismatch");
  }
  if (modelFamilyRaw !== args.runtimeNode.modelFamily) {
    throw new Error("execution_receipt_model_family_mismatch");
  }
  if (normalizeAddress(operatorRaw) !== normalizeAddress(args.runtimeNode.operatorAddress)) {
    throw new Error("execution_receipt_operator_mismatch");
  }

  return candidate as unknown as ExecutionReceipt;
}

function resolveDonDomainFromEnv(): DonEip712Domain {
  const chainId = Number.parseInt(process.env.CHAIN_ID ?? "1", 10);
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new Error("CHAIN_ID must be a positive integer");
  }

  const verifyingContract =
    process.env.DON_VERIFIER_CONTRACT?.trim() ||
    process.env.CONTRACT_ADDRESS?.trim() ||
    "0x0000000000000000000000000000000000000001";

  return buildDonDomain({
    name: process.env.DON_DOMAIN_NAME?.trim() || "CRE-DON-Consensus",
    version: process.env.DON_DOMAIN_VERSION?.trim() || "1",
    chainId,
    verifyingContract
  });
}

async function runEndpointNode(params: {
  requestId: string;
  input: MarketRequestInput;
  runtimeNode: RuntimeNode;
  endpointUrl: string;
  timeoutMs: number;
  verifyPath: string;
  requireSignedReports: boolean;
}): Promise<{ report: NodeReport; signedReport?: SignedNodeReport; executionReceipt?: ExecutionReceipt }> {
  const verifyUrl = buildEndpointUrl(params.endpointUrl, params.verifyPath);
  const response = await fetch(verifyUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Cre-Request-Id": params.requestId
    },
    body: JSON.stringify({
      requestId: params.requestId,
      input: params.input,
      node: {
        nodeId: params.runtimeNode.nodeId,
        modelFamily: params.runtimeNode.modelFamily,
        modelName: params.runtimeNode.modelName,
        operatorAddress: params.runtimeNode.operatorAddress
      }
    }),
    signal: AbortSignal.timeout(params.timeoutMs)
  });

  if (!response.ok) {
    throw new Error(`endpoint_http_${response.status}`);
  }

  const payloadRaw = (await response.json()) as unknown;
  const payloadRoot = (payloadRaw as Record<string, unknown>) ?? {};
  const data = ((payloadRoot.data as Record<string, unknown>) ?? payloadRoot) as Record<string, unknown>;

  const report = parseReportFromEndpoint({
    requestId: params.requestId,
    runtimeNode: params.runtimeNode,
    payload: (data.report as unknown) ?? data
  });
  const signedReport = parseSignedReportFromEndpoint({
    requestId: params.requestId,
    runtimeNode: params.runtimeNode,
    report,
    payload: (data.signedReport as unknown) ?? (data.signedNodeReport as unknown)
  });
  const executionReceipt = parseExecutionReceiptFromEndpoint({
    requestId: params.requestId,
    runtimeNode: params.runtimeNode,
    payload: data.executionReceipt as unknown
  });

  if (params.requireSignedReports && (!signedReport || !executionReceipt)) {
    throw new Error("missing_signed_artifacts");
  }

  return {
    report,
    signedReport,
    executionReceipt
  };
}

export async function runAllRuntimeNodesViaEndpoints(params: EndpointDispatchParams): Promise<{
  reports: NodeReport[];
  signedReports: SignedNodeReport[];
  executionReceipts: ExecutionReceipt[];
  failures: Array<{ nodeId: NodeId; reason: string }>;
}> {
  const nodes = params.runtimeNodes;
  const requireSignedReports = params.requireSignedReports === true;
  const settled = await Promise.allSettled(
    nodes.map(async (runtimeNode) => {
      const endpointUrl = resolveEndpointForRuntimeNode(runtimeNode, params.activeNodes);
      if (!endpointUrl) {
        if (params.fallbackToMock) {
          return {
            report: await runRuntimeNode(params.requestId, params.input, runtimeNode)
          };
        }
        throw new Error("endpoint_missing");
      }

      try {
        return await runEndpointNode({
          requestId: params.requestId,
          input: params.input,
          runtimeNode,
          endpointUrl,
          timeoutMs: params.timeoutMs,
          verifyPath: params.verifyPath,
          requireSignedReports
        });
      } catch (error) {
        if (params.fallbackToMock) {
          return {
            report: await runRuntimeNode(params.requestId, params.input, runtimeNode)
          };
        }
        throw error;
      }
    })
  );

  const reports: NodeReport[] = [];
  const signedReports: SignedNodeReport[] = [];
  const executionReceipts: ExecutionReceipt[] = [];
  const failures: Array<{ nodeId: NodeId; reason: string }> = [];

  settled.forEach((result, index) => {
    const nodeId = nodes[index]?.nodeId ?? `unknown-${index}`;
    if (result.status === "fulfilled") {
      reports.push(result.value.report);
      if (result.value.signedReport) {
        signedReports.push(result.value.signedReport);
      }
      if (result.value.executionReceipt) {
        executionReceipts.push(result.value.executionReceipt);
      }
      return;
    }
    failures.push({
      nodeId,
      reason: result.reason instanceof Error ? result.reason.message : String(result.reason)
    });
  });

  return { reports, signedReports, executionReceipts, failures };
}

function resolveEndpointForOperator(operator: string, activeNodes: RegisteredNode[]): string | undefined {
  const normalizedOperator = normalizeAddress(operator);
  return activeNodes.find((node) => normalizeNodeId(node.walletAddress) === normalizedOperator)?.endpointUrl;
}

async function postJson(endpointUrl: string, endpointPath: string, timeoutMs: number, body: unknown): Promise<unknown> {
  const url = buildEndpointUrl(endpointUrl, endpointPath);
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!response.ok) {
    throw new Error(`endpoint_http_${response.status}`);
  }
  return (await response.json()) as unknown;
}

export async function collectConsensusBundleSignaturesViaEndpoints(args: {
  bundle: ConsensusBundle;
  activeNodes: RegisteredNode[];
  timeoutMs: number;
  bundleApprovalPath?: string;
  leaderSignPath?: string;
  leaderOperator?: string;
}): Promise<ConsensusBundle> {
  const bundleApprovalPath = args.bundleApprovalPath ?? "/sign-bundle-approval";
  const leaderSignPath = args.leaderSignPath ?? "/sign-consensus-bundle";
  const domain = resolveDonDomainFromEnv();

  const includedOperators = args.bundle.includedOperators.map((item) => normalizeAddress(item));
  if (includedOperators.length === 0) {
    throw new Error("bundle_included_operators_empty");
  }

  const approvalPayload = {
    bundleHash: args.bundle.bundleHash,
    requestId: args.bundle.payload.requestId,
    round: args.bundle.payload.round
  };

  const reportSignatures = await Promise.all(
    includedOperators.map(async (operator) => {
      const endpointUrl = resolveEndpointForOperator(operator, args.activeNodes);
      if (!endpointUrl) {
        throw new Error(`bundle_approval_endpoint_missing:${operator}`);
      }

      const raw = await postJson(endpointUrl, bundleApprovalPath, args.timeoutMs, {
        bundleHash: approvalPayload.bundleHash,
        requestId: approvalPayload.requestId,
        round: approvalPayload.round,
        operator
      });
      const root = (raw as Record<string, unknown>) ?? {};
      const data = ((root.data as Record<string, unknown>) ?? root) as Record<string, unknown>;
      const signature = String(data.signature ?? "").trim();
      const returnedOperator = normalizeAddress(String(data.operator ?? operator));

      if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) {
        throw new Error(`bundle_approval_signature_invalid_format:${operator}`);
      }
      if (returnedOperator !== operator) {
        throw new Error(`bundle_approval_operator_mismatch:${operator}`);
      }

      const verified = verifyOperatorBundleApprovalSignature(domain, approvalPayload, signature, operator);
      if (!verified.ok) {
        throw new Error(`bundle_approval_signature_invalid:${operator}:${verified.reason ?? "invalid_signature"}`);
      }

      return signature;
    })
  );

  const selectedLeader = args.leaderOperator
    ? normalizeAddress(args.leaderOperator)
    : args.bundle.leader
      ? normalizeAddress(args.bundle.leader)
      : includedOperators[0]!;

  if (!includedOperators.includes(selectedLeader)) {
    throw new Error(`leader_not_included_operators:${selectedLeader}`);
  }

  const leaderEndpoint = resolveEndpointForOperator(selectedLeader, args.activeNodes);
  if (!leaderEndpoint) {
    throw new Error(`leader_endpoint_missing:${selectedLeader}`);
  }

  const leaderRaw = await postJson(leaderEndpoint, leaderSignPath, args.timeoutMs, {
    payload: args.bundle.payload,
    leader: selectedLeader
  });
  const leaderRoot = (leaderRaw as Record<string, unknown>) ?? {};
  const leaderData = ((leaderRoot.data as Record<string, unknown>) ?? leaderRoot) as Record<string, unknown>;
  const leader = normalizeAddress(String(leaderData.leader ?? selectedLeader));
  const leaderSignature = String(leaderData.leaderSignature ?? "").trim();

  if (leader !== selectedLeader) {
    throw new Error(`leader_signature_operator_mismatch:${selectedLeader}`);
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(leaderSignature)) {
    throw new Error("leader_signature_invalid_format");
  }

  const signedBundle: ConsensusBundle = {
    ...args.bundle,
    leader,
    leaderSignature,
    includedOperators,
    reportSignatures
  };

  const verifiedLeader = verifyConsensusBundleLeaderSignature(domain, signedBundle);
  if (!verifiedLeader.ok) {
    throw new Error(`leader_signature_invalid:${verifiedLeader.reason ?? "invalid_signature"}`);
  }

  return signedBundle;
}

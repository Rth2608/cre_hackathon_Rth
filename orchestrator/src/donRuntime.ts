import { Wallet, ZeroHash, getAddress, id } from "ethers";
import type { RuntimeNode } from "./mockNodes";
import {
  DON_EIP712_TYPES,
  buildDonDomain,
  computeReportsMerkleRoot,
  toNodeReportTypedDataValue,
  type DonEip712Domain
} from "./donSignatures";
import {
  getSignerAddressFromPrivateKey,
  parseDonOperatorPrivateKeyMap,
  resolveDonSignerPrivateKey
} from "./donOperatorKeys";
import type { ExecutionReceipt, MarketRequestInput, NodeReport, SignedNodeReport, SignedNodeReportPayload } from "./types";
import { hashObject } from "./utils";

export interface SignedRuntimeReportsResult {
  requestHash: string;
  promptTemplateHash: string;
  round: number;
  domain: DonEip712Domain;
  signedReports: SignedNodeReport[];
  executionReceipts: ExecutionReceipt[];
  attestationRootHash: string;
  signerKeyByOperator: Record<string, string>;
  failures: Array<{ nodeId: string; reason: string }>;
}

function normalizeHex32(value: string): string {
  const normalized = value.startsWith("0x") ? value : `0x${value}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    return normalized.toLowerCase();
  }
  return id(value);
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function resolveRound(): number {
  const parsed = Number.parseInt(process.env.DON_CONSENSUS_ROUND ?? "1", 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error("DON_CONSENSUS_ROUND must be a non-negative integer");
  }
  return parsed;
}

function buildRequestHash(input: MarketRequestInput): string {
  return id(
    JSON.stringify({
      question: input.question,
      description: input.description,
      sourceUrls: [...input.sourceUrls].sort((a, b) => a.localeCompare(b)),
      resolutionCriteria: input.resolutionCriteria,
      submitterAddress: input.submitterAddress.toLowerCase()
    })
  );
}

function buildCanonicalPromptHash(input: MarketRequestInput, promptTemplateHash: string): string {
  return id(
    JSON.stringify({
      promptTemplateHash,
      question: input.question,
      description: input.description,
      sourceUrls: [...input.sourceUrls].sort((a, b) => a.localeCompare(b)),
      resolutionCriteria: input.resolutionCriteria
    })
  );
}

function resolvePromptTemplateHash(): string {
  const fromEnv = process.env.DON_PROMPT_TEMPLATE_HASH?.trim();
  if (!fromEnv) {
    return id("cre-prediction-market-prompt-template-v1");
  }
  return normalizeHex32(fromEnv);
}

function resolveDonDomain(): DonEip712Domain {
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

function toConfidenceBps(confidence: number): number {
  if (!Number.isFinite(confidence)) return 0;
  const clamped = Math.max(0, Math.min(1, confidence));
  return Math.round(clamped * 10000);
}

function toUnixTimestampSeconds(value: string): number {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return Math.floor(Date.now() / 1000);
  }
  return Math.floor(parsed / 1000);
}

function buildExecutionReceipt(args: {
  requestId: string;
  round: number;
  runtimeNode: RuntimeNode;
  report: NodeReport;
  promptTemplateHash: string;
  canonicalPromptHash: string;
}): ExecutionReceipt {
  const endedAt = toUnixTimestampSeconds(args.report.generatedAt);
  const startedAt = Math.max(0, endedAt - 1);

  return {
    requestId: args.requestId,
    round: args.round,
    operator: args.runtimeNode.operatorAddress,
    modelFamily: args.runtimeNode.modelFamily,
    modelNameHash: id(args.runtimeNode.modelName),
    promptTemplateHash: args.promptTemplateHash,
    canonicalPromptHash: args.canonicalPromptHash,
    paramsHash: id("temperature=0|max_tokens=256"),
    responseHash: id(
      JSON.stringify({
        verdict: args.report.verdict,
        confidence: args.report.confidence,
        rationale: args.report.rationale,
        evidenceSummary: args.report.evidenceSummary,
        reportHash: args.report.reportHash
      })
    ),
    confidentialAttestationHash: id(`attestation:${args.requestId}:${args.runtimeNode.nodeId}:${args.report.reportHash}`),
    providerRequestIdHash: id(`provider:${args.requestId}:${args.runtimeNode.nodeId}`),
    startedAt,
    endedAt
  };
}

function buildSignedNodeReportPayload(args: {
  requestId: string;
  round: number;
  runtimeNode: RuntimeNode;
  report: NodeReport;
  promptTemplateHash: string;
  canonicalPromptHash: string;
  executionReceiptHash: string;
}): SignedNodeReportPayload {
  return {
    requestId: normalizeHex32(args.requestId),
    round: args.round,
    operator: normalizeAddress(args.runtimeNode.operatorAddress),
    modelFamily: args.runtimeNode.modelFamily,
    modelNameHash: id(args.runtimeNode.modelName),
    promptTemplateHash: args.promptTemplateHash,
    canonicalPromptHash: args.canonicalPromptHash,
    paramsHash: id("temperature=0|max_tokens=256"),
    responseHash: id(
      JSON.stringify({
        verdict: args.report.verdict,
        confidence: args.report.confidence,
        reportHash: args.report.reportHash
      })
    ),
    executionReceiptHash: args.executionReceiptHash,
    verdict: args.report.verdict,
    confidenceBps: toConfidenceBps(args.report.confidence),
    reportHash: normalizeHex32(args.report.reportHash),
    timestamp: toUnixTimestampSeconds(args.report.generatedAt)
  };
}

export async function buildSignedRuntimeReports(args: {
  requestId: string;
  input: MarketRequestInput;
  nodeReports: NodeReport[];
  runtimeNodes: RuntimeNode[];
}): Promise<SignedRuntimeReportsResult> {
  const round = resolveRound();
  const promptTemplateHash = resolvePromptTemplateHash();
  const requestHash = buildRequestHash(args.input);
  const canonicalPromptHash = buildCanonicalPromptHash(args.input, promptTemplateHash);
  const domain = resolveDonDomain();
  const customSignerMap = parseDonOperatorPrivateKeyMap(process.env.DON_OPERATOR_PRIVATE_KEYS_JSON);

  const runtimeNodeById = new Map(args.runtimeNodes.map((node) => [node.nodeId, node]));
  const signedReports: SignedNodeReport[] = [];
  const executionReceipts: ExecutionReceipt[] = [];
  const failures: Array<{ nodeId: string; reason: string }> = [];
  const signerKeyByOperator: Record<string, string> = {};

  for (const report of args.nodeReports) {
    const runtimeNode = runtimeNodeById.get(report.nodeId);
    if (!runtimeNode) {
      failures.push({
        nodeId: report.nodeId,
        reason: "runtime_node_not_found"
      });
      continue;
    }

    const signerKey = resolveDonSignerPrivateKey({
      nodeId: runtimeNode.nodeId,
      operatorAddress: runtimeNode.operatorAddress,
      customMap: customSignerMap
    });

    if (!signerKey) {
      failures.push({
        nodeId: runtimeNode.nodeId,
        reason: "missing_operator_private_key"
      });
      continue;
    }

    const signerAddress = getSignerAddressFromPrivateKey(signerKey).toLowerCase();
    const expectedOperator = normalizeAddress(runtimeNode.operatorAddress).toLowerCase();
    if (signerAddress !== expectedOperator) {
      failures.push({
        nodeId: runtimeNode.nodeId,
        reason: "operator_address_key_mismatch"
      });
      continue;
    }

    const executionReceipt = buildExecutionReceipt({
      requestId: normalizeHex32(args.requestId),
      round,
      runtimeNode,
      report,
      promptTemplateHash,
      canonicalPromptHash
    });
    const executionReceiptHash = normalizeHex32(hashObject(executionReceipt));
    const payload = buildSignedNodeReportPayload({
      requestId: normalizeHex32(args.requestId),
      round,
      runtimeNode,
      report,
      promptTemplateHash,
      canonicalPromptHash,
      executionReceiptHash
    });

    const wallet = new Wallet(signerKey);
    const signature = await wallet.signTypedData(domain, DON_EIP712_TYPES.NODE_REPORT_TYPES, toNodeReportTypedDataValue(payload));

    signedReports.push({
      payload,
      signature
    });
    executionReceipts.push(executionReceipt);
    signerKeyByOperator[payload.operator.toLowerCase()] = signerKey;
  }

  const attestationRootHash =
    executionReceipts.length > 0
      ? computeReportsMerkleRoot(executionReceipts.map((receipt) => normalizeHex32(receipt.confidentialAttestationHash)))
      : ZeroHash;

  return {
    requestHash,
    promptTemplateHash,
    round,
    domain,
    signedReports,
    executionReceipts,
    attestationRootHash,
    signerKeyByOperator,
    failures
  };
}

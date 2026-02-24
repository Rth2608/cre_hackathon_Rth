import {
  TypedDataEncoder,
  ZeroHash,
  Wallet,
  concat,
  getAddress,
  getBytes,
  id,
  keccak256,
  verifyTypedData,
  type TypedDataField
} from "ethers";
import type {
  CanonicalModelFamily,
  ConsensusBundle,
  ConsensusBundlePayload,
  QuorumValidationResult,
  SignedNodeReport,
  SignedNodeReportPayload
} from "./types";

export interface DonEip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

interface NodeReportTypedDataValue {
  requestId: string;
  round: number;
  operator: string;
  modelFamilyHash: string;
  modelNameHash: string;
  promptTemplateHash: string;
  canonicalPromptHash: string;
  paramsHash: string;
  responseHash: string;
  executionReceiptHash: string;
  verdict: number;
  confidenceBps: number;
  reportHash: string;
  timestamp: number;
}

interface OperatorApprovalTypedDataValue {
  bundleHash: string;
  requestId: string;
  round: number;
}

const MODEL_FAMILY_HASH: Record<CanonicalModelFamily, string> = {
  gpt: id("gpt"),
  gemini: id("gemini"),
  claude: id("claude"),
  grok: id("grok")
};

const NODE_REPORT_TYPES: Record<string, TypedDataField[]> = {
  NodeReport: [
    { name: "requestId", type: "bytes32" },
    { name: "round", type: "uint32" },
    { name: "operator", type: "address" },
    { name: "modelFamilyHash", type: "bytes32" },
    { name: "modelNameHash", type: "bytes32" },
    { name: "promptTemplateHash", type: "bytes32" },
    { name: "canonicalPromptHash", type: "bytes32" },
    { name: "paramsHash", type: "bytes32" },
    { name: "responseHash", type: "bytes32" },
    { name: "executionReceiptHash", type: "bytes32" },
    { name: "verdict", type: "uint8" },
    { name: "confidenceBps", type: "uint16" },
    { name: "reportHash", type: "bytes32" },
    { name: "timestamp", type: "uint64" }
  ]
};

const CONSENSUS_BUNDLE_TYPES: Record<string, TypedDataField[]> = {
  ConsensusBundle: [
    { name: "requestId", type: "bytes32" },
    { name: "requestHash", type: "bytes32" },
    { name: "round", type: "uint32" },
    { name: "aggregateScoreBps", type: "int16" },
    { name: "finalVerdict", type: "bool" },
    { name: "responders", type: "uint8" },
    { name: "reportsMerkleRoot", type: "bytes32" },
    { name: "attestationRootHash", type: "bytes32" },
    { name: "promptTemplateHash", type: "bytes32" },
    { name: "consensusTimestamp", type: "uint64" }
  ]
};

const OPERATOR_APPROVAL_TYPES: Record<string, TypedDataField[]> = {
  OperatorApproval: [
    { name: "bundleHash", type: "bytes32" },
    { name: "requestId", type: "bytes32" },
    { name: "round", type: "uint32" }
  ]
};

function normalizeBytes32(value: string, fieldName: string): string {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`Invalid bytes32 for ${fieldName}`);
  }
  return value.toLowerCase();
}

function normalizeAddress(value: string, fieldName: string): string {
  try {
    return getAddress(value);
  } catch {
    throw new Error(`Invalid address for ${fieldName}`);
  }
}

function normalizeUInt(value: number, max: number, fieldName: string): number {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new Error(`Invalid ${fieldName} range`);
  }
  return value;
}

function normalizeInt16(value: number, fieldName: string): number {
  if (!Number.isInteger(value) || value < -32768 || value > 32767) {
    throw new Error(`Invalid ${fieldName} range`);
  }
  return value;
}

function normalizeVerdict(verdict: SignedNodeReportPayload["verdict"]): number {
  return verdict === "PASS" ? 1 : 0;
}

export function toNodeReportTypedDataValue(payload: SignedNodeReportPayload): NodeReportTypedDataValue {
  return {
    requestId: normalizeBytes32(payload.requestId, "requestId"),
    round: normalizeUInt(payload.round, 2 ** 32 - 1, "round"),
    operator: normalizeAddress(payload.operator, "operator"),
    modelFamilyHash: MODEL_FAMILY_HASH[payload.modelFamily],
    modelNameHash: normalizeBytes32(payload.modelNameHash, "modelNameHash"),
    promptTemplateHash: normalizeBytes32(payload.promptTemplateHash, "promptTemplateHash"),
    canonicalPromptHash: normalizeBytes32(payload.canonicalPromptHash, "canonicalPromptHash"),
    paramsHash: normalizeBytes32(payload.paramsHash, "paramsHash"),
    responseHash: normalizeBytes32(payload.responseHash, "responseHash"),
    executionReceiptHash: normalizeBytes32(payload.executionReceiptHash, "executionReceiptHash"),
    verdict: normalizeVerdict(payload.verdict),
    confidenceBps: normalizeUInt(payload.confidenceBps, 10000, "confidenceBps"),
    reportHash: normalizeBytes32(payload.reportHash, "reportHash"),
    timestamp: normalizeUInt(payload.timestamp, Number.MAX_SAFE_INTEGER, "timestamp")
  };
}

export function toConsensusBundleTypedDataValue(payload: ConsensusBundlePayload): ConsensusBundlePayload {
  return {
    requestId: normalizeBytes32(payload.requestId, "requestId"),
    requestHash: normalizeBytes32(payload.requestHash, "requestHash"),
    round: normalizeUInt(payload.round, 2 ** 32 - 1, "round"),
    aggregateScoreBps: normalizeInt16(payload.aggregateScoreBps, "aggregateScoreBps"),
    finalVerdict: payload.finalVerdict,
    responders: normalizeUInt(payload.responders, 255, "responders"),
    reportsMerkleRoot: normalizeBytes32(payload.reportsMerkleRoot, "reportsMerkleRoot"),
    attestationRootHash: normalizeBytes32(payload.attestationRootHash, "attestationRootHash"),
    promptTemplateHash: normalizeBytes32(payload.promptTemplateHash, "promptTemplateHash"),
    consensusTimestamp: normalizeUInt(payload.consensusTimestamp, Number.MAX_SAFE_INTEGER, "consensusTimestamp")
  };
}

export function toOperatorApprovalTypedDataValue(payload: {
  bundleHash: string;
  requestId: string;
  round: number;
}): OperatorApprovalTypedDataValue {
  return {
    bundleHash: normalizeBytes32(payload.bundleHash, "bundleHash"),
    requestId: normalizeBytes32(payload.requestId, "requestId"),
    round: normalizeUInt(payload.round, 2 ** 32 - 1, "round")
  };
}

export function buildDonDomain(input: DonEip712Domain): DonEip712Domain {
  return {
    name: input.name.trim(),
    version: input.version.trim(),
    chainId: normalizeUInt(input.chainId, Number.MAX_SAFE_INTEGER, "chainId"),
    verifyingContract: normalizeAddress(input.verifyingContract, "verifyingContract")
  };
}

export function hashSignedNodeReportPayload(payload: SignedNodeReportPayload): string {
  return TypedDataEncoder.hashStruct("NodeReport", NODE_REPORT_TYPES, toNodeReportTypedDataValue(payload));
}

export function verifySignedNodeReport(
  domainInput: DonEip712Domain,
  signedReport: SignedNodeReport
): { ok: boolean; recoveredOperator?: string; reason?: string } {
  try {
    const domain = buildDonDomain(domainInput);
    const value = toNodeReportTypedDataValue(signedReport.payload);
    const recovered = verifyTypedData(domain, NODE_REPORT_TYPES, value, signedReport.signature);
    const recoveredOperator = normalizeAddress(recovered, "recoveredOperator");
    const expectedOperator = normalizeAddress(signedReport.payload.operator, "payload.operator");
    if (recoveredOperator.toLowerCase() !== expectedOperator.toLowerCase()) {
      return {
        ok: false,
        recoveredOperator,
        reason: "signature_mismatch_operator"
      };
    }

    return {
      ok: true,
      recoveredOperator
    };
  } catch (error) {
    return {
      ok: false,
      reason: error instanceof Error ? error.message : String(error)
    };
  }
}

export function validateSignedReportsForQuorum(
  domainInput: DonEip712Domain,
  reports: SignedNodeReport[],
  options?: { minResponders?: number; maxResponders?: number }
): QuorumValidationResult {
  const minResponders = options?.minResponders ?? 3;
  const maxResponders = options?.maxResponders ?? 4;
  const validReports: SignedNodeReport[] = [];
  const invalidReports: Array<{ operator: string; reason: string }> = [];
  const seenOperators = new Set<string>();

  for (const report of reports) {
    const verification = verifySignedNodeReport(domainInput, report);
    const operatorRaw = report.payload.operator || "0x0000000000000000000000000000000000000000";
    const operator = operatorRaw.toLowerCase();

    if (!verification.ok) {
      invalidReports.push({
        operator,
        reason: verification.reason || "invalid_signature"
      });
      continue;
    }

    if (seenOperators.has(operator)) {
      invalidReports.push({
        operator,
        reason: "duplicate_operator"
      });
      continue;
    }

    seenOperators.add(operator);
    validReports.push(report);
  }

  const responders = validReports.length;
  const quorumReached = responders >= minResponders && responders <= maxResponders;

  return {
    ok: invalidReports.length === 0 && quorumReached,
    quorumReached,
    responders,
    includedOperators: Array.from(seenOperators),
    validReports,
    invalidReports
  };
}

function merkleLevel(level: string[]): string[] {
  if (level.length === 1) return level;

  const next: string[] = [];
  for (let i = 0; i < level.length; i += 2) {
    const left = level[i]!;
    const right = level[i + 1] ?? left;
    next.push(keccak256(concat([getBytes(left), getBytes(right)])));
  }
  return next;
}

export function computeReportsMerkleRoot(reportHashes: string[]): string {
  const leaves = reportHashes.map((hash, index) => normalizeBytes32(hash, `reportHashes[${index}]`));
  if (leaves.length === 0) return ZeroHash;

  let level = leaves;
  while (level.length > 1) {
    level = merkleLevel(level);
  }
  return level[0]!;
}

export function computeReportsMerkleRootFromSignedReports(reports: SignedNodeReport[]): string {
  return computeReportsMerkleRoot(reports.map((report) => report.payload.reportHash));
}

export function hashConsensusBundlePayload(payload: ConsensusBundlePayload): string {
  return TypedDataEncoder.hashStruct("ConsensusBundle", CONSENSUS_BUNDLE_TYPES, toConsensusBundleTypedDataValue(payload));
}

export function verifyConsensusBundleLeaderSignature(
  domainInput: DonEip712Domain,
  bundle: ConsensusBundle
): { ok: boolean; recoveredLeader?: string; reason?: string } {
  try {
    const domain = buildDonDomain(domainInput);
    const payload = toConsensusBundleTypedDataValue(bundle.payload);
    const recovered = verifyTypedData(domain, CONSENSUS_BUNDLE_TYPES, payload, bundle.leaderSignature);
    const recoveredLeader = normalizeAddress(recovered, "recoveredLeader");
    const expectedLeader = normalizeAddress(bundle.leader, "leader");
    if (recoveredLeader.toLowerCase() !== expectedLeader.toLowerCase()) {
      return {
        ok: false,
        recoveredLeader,
        reason: "leader_signature_mismatch"
      };
    }

    return {
      ok: true,
      recoveredLeader
    };
  } catch (error) {
    return {
      ok: false,
      reason: error instanceof Error ? error.message : String(error)
    };
  }
}

export function hashOperatorBundleApprovalPayload(payload: {
  bundleHash: string;
  requestId: string;
  round: number;
}): string {
  return TypedDataEncoder.hashStruct(
    "OperatorApproval",
    OPERATOR_APPROVAL_TYPES,
    toOperatorApprovalTypedDataValue(payload)
  );
}

export function verifyOperatorBundleApprovalSignature(
  domainInput: DonEip712Domain,
  payload: {
    bundleHash: string;
    requestId: string;
    round: number;
  },
  signature: string,
  expectedOperator: string
): { ok: boolean; recoveredOperator?: string; reason?: string } {
  try {
    const domain = buildDonDomain(domainInput);
    const value = toOperatorApprovalTypedDataValue(payload);
    const recovered = verifyTypedData(domain, OPERATOR_APPROVAL_TYPES, value, signature);
    const recoveredOperator = normalizeAddress(recovered, "recoveredOperator");
    const normalizedExpected = normalizeAddress(expectedOperator, "expectedOperator");
    if (recoveredOperator.toLowerCase() !== normalizedExpected.toLowerCase()) {
      return {
        ok: false,
        recoveredOperator,
        reason: "operator_approval_signature_mismatch"
      };
    }

    return {
      ok: true,
      recoveredOperator
    };
  } catch (error) {
    return {
      ok: false,
      reason: error instanceof Error ? error.message : String(error)
    };
  }
}

export function buildConsensusBundleSkeleton(input: {
  payload: Omit<ConsensusBundlePayload, "reportsMerkleRoot"> & { reportsMerkleRoot?: string };
  leader: string;
  leaderSignature: string;
  includedOperators: string[];
  reportSignatures: string[];
}): ConsensusBundle {
  const reportsMerkleRoot =
    input.payload.reportsMerkleRoot && input.payload.reportsMerkleRoot !== ZeroHash
      ? normalizeBytes32(input.payload.reportsMerkleRoot, "reportsMerkleRoot")
      : ZeroHash;

  const payload: ConsensusBundlePayload = {
    ...input.payload,
    reportsMerkleRoot
  };

  const encodedPayload = toConsensusBundleTypedDataValue(payload);
  const bundleHash = hashConsensusBundlePayload(encodedPayload);

  return {
    payload: encodedPayload,
    bundleHash,
    leader: normalizeAddress(input.leader, "leader"),
    leaderSignature: input.leaderSignature,
    includedOperators: input.includedOperators.map((operator, index) =>
      normalizeAddress(operator, `includedOperators[${index}]`)
    ),
    reportSignatures: [...input.reportSignatures]
  };
}

export const DON_EIP712_TYPES = {
  NODE_REPORT_TYPES,
  CONSENSUS_BUNDLE_TYPES,
  OPERATOR_APPROVAL_TYPES
};

export async function signConsensusBundlePayloadByKey(
  domainInput: DonEip712Domain,
  payload: ConsensusBundlePayload,
  privateKey: string
): Promise<{ leader: string; leaderSignature: string }> {
  const domain = buildDonDomain(domainInput);
  const wallet = new Wallet(privateKey);
  const normalizedPayload = toConsensusBundleTypedDataValue(payload);
  const leaderSignature = await wallet.signTypedData(domain, CONSENSUS_BUNDLE_TYPES, normalizedPayload);
  return {
    leader: wallet.address,
    leaderSignature
  };
}

export async function signOperatorBundleApprovalByKey(
  domainInput: DonEip712Domain,
  payload: {
    bundleHash: string;
    requestId: string;
    round: number;
  },
  privateKey: string
): Promise<{ operator: string; signature: string }> {
  const domain = buildDonDomain(domainInput);
  const wallet = new Wallet(privateKey);
  const normalizedPayload = toOperatorApprovalTypedDataValue(payload);
  const signature = await wallet.signTypedData(domain, OPERATOR_APPROVAL_TYPES, normalizedPayload);
  return {
    operator: wallet.address,
    signature
  };
}

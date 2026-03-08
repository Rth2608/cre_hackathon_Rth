import { computeConsensus } from "./consensus";
import {
  buildConsensusBundleSkeleton,
  computeReportsMerkleRootFromSignedReports,
  validateSignedReportsForQuorum,
  type DonEip712Domain
} from "./donSignatures";
import type { ConsensusBundle, ConsensusResult, NodeReport, QuorumValidationResult, SignedNodeReport } from "./types";

export interface PrepareConsensusBundleInput {
  requestId: string;
  requestHash: string;
  promptTemplateHash: string;
  attestationRootHash: string;
  round: number;
  domain: DonEip712Domain;
  signedReports: SignedNodeReport[];
  leader: string;
  leaderSignature?: string;
  minResponders?: number;
  maxResponders?: number;
  consensusTimestamp?: number;
}

export interface PrepareConsensusBundleResult {
  quorum: QuorumValidationResult;
  consensus: ConsensusResult | null;
  bundle: ConsensusBundle | null;
  excludedNodeIds: string[];
}

function normalizeHash(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeOperator(value: string | undefined): string {
  return (value || "0x0000000000000000000000000000000000000000").toLowerCase();
}

function enforceSignedReportContextConsistency(args: {
  requestId: string;
  round: number;
  promptTemplateHash: string;
  reports: SignedNodeReport[];
}): {
  validReports: SignedNodeReport[];
  invalidReports: Array<{ operator: string; reason: string }>;
} {
  const validReports: SignedNodeReport[] = [];
  const invalidReports: Array<{ operator: string; reason: string }> = [];

  const expectedRequestId = normalizeHash(args.requestId);
  const expectedPromptTemplateHash = normalizeHash(args.promptTemplateHash);
  const expectedRound = args.round;

  const prefiltered: SignedNodeReport[] = [];
  for (const report of args.reports) {
    const operator = normalizeOperator(report.payload.operator);
    if (normalizeHash(report.payload.requestId) !== expectedRequestId) {
      invalidReports.push({ operator, reason: "signed_report_request_id_mismatch" });
      continue;
    }
    if (report.payload.round !== expectedRound) {
      invalidReports.push({ operator, reason: "signed_report_round_mismatch" });
      continue;
    }
    if (normalizeHash(report.payload.promptTemplateHash) !== expectedPromptTemplateHash) {
      invalidReports.push({ operator, reason: "signed_report_prompt_template_hash_mismatch" });
      continue;
    }
    prefiltered.push(report);
  }

  if (prefiltered.length === 0) {
    return { validReports, invalidReports };
  }

  const canonicalPromptHash = normalizeHash(prefiltered[0]!.payload.canonicalPromptHash);
  const paramsHash = normalizeHash(prefiltered[0]!.payload.paramsHash);

  for (const report of prefiltered) {
    const operator = normalizeOperator(report.payload.operator);
    if (normalizeHash(report.payload.canonicalPromptHash) !== canonicalPromptHash) {
      invalidReports.push({ operator, reason: "signed_report_canonical_prompt_hash_mismatch" });
      continue;
    }
    if (normalizeHash(report.payload.paramsHash) !== paramsHash) {
      invalidReports.push({ operator, reason: "signed_report_params_hash_mismatch" });
      continue;
    }
    validReports.push(report);
  }

  return {
    validReports,
    invalidReports
  };
}

function toLegacyNodeReport(signed: SignedNodeReport): NodeReport {
  return {
    requestId: signed.payload.requestId,
    nodeId: signed.payload.operator.toLowerCase(),
    verdict: signed.payload.verdict,
    confidence: Number((signed.payload.confidenceBps / 10000).toFixed(4)),
    rationale: `Signed DON report from ${signed.payload.operator}`,
    evidenceSummary: `executionReceiptHash=${signed.payload.executionReceiptHash}`,
    reportHash: signed.payload.reportHash,
    generatedAt: new Date(signed.payload.timestamp * 1000).toISOString()
  };
}

export function prepareConsensusBundleFromSignedReports(input: PrepareConsensusBundleInput): PrepareConsensusBundleResult {
  const minResponders = input.minResponders ?? 3;
  const maxResponders = input.maxResponders ?? 4;
  const signatureValidated = validateSignedReportsForQuorum(input.domain, input.signedReports, {
    minResponders,
    maxResponders
  });
  const consistencyValidated = enforceSignedReportContextConsistency({
    requestId: input.requestId,
    round: input.round,
    promptTemplateHash: input.promptTemplateHash,
    reports: signatureValidated.validReports
  });
  const responders = consistencyValidated.validReports.length;
  const quorumReached = responders >= minResponders && responders <= maxResponders;

  const quorum: QuorumValidationResult = {
    ok: signatureValidated.invalidReports.length === 0 && consistencyValidated.invalidReports.length === 0 && quorumReached,
    quorumReached,
    responders,
    includedOperators: consistencyValidated.validReports.map((report) => report.payload.operator.toLowerCase()),
    validReports: consistencyValidated.validReports,
    invalidReports: [...signatureValidated.invalidReports, ...consistencyValidated.invalidReports]
  };

  const nodeReports = quorum.validReports.map(toLegacyNodeReport);
  const consensus = computeConsensus(
    input.requestId,
    nodeReports,
    quorum.validReports.map((report) => report.payload.operator.toLowerCase())
  );
  const excludedNodeIds = quorum.invalidReports.map((entry) => entry.operator.toLowerCase());

  if (!quorum.quorumReached) {
    return {
      quorum,
      consensus,
      bundle: null,
      excludedNodeIds
    };
  }

  const reportsMerkleRoot = computeReportsMerkleRootFromSignedReports(quorum.validReports);

  const bundle = buildConsensusBundleSkeleton({
    payload: {
      requestId: input.requestId,
      requestHash: input.requestHash,
      round: input.round,
      aggregateScoreBps: consensus.aggregateScoreBps,
      finalVerdict: consensus.finalVerdict === "PASS",
      responders: consensus.responders,
      reportsMerkleRoot,
      attestationRootHash: input.attestationRootHash,
      promptTemplateHash: input.promptTemplateHash,
      consensusTimestamp: input.consensusTimestamp ?? Math.floor(Date.now() / 1000)
    },
    leader: input.leader,
    leaderSignature: input.leaderSignature ?? "0x",
    includedOperators: quorum.includedOperators,
    reportSignatures: quorum.validReports.map((report) => report.signature)
  });

  return {
    quorum,
    consensus,
    bundle,
    excludedNodeIds
  };
}

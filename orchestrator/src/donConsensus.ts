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
  const quorum = validateSignedReportsForQuorum(input.domain, input.signedReports, {
    minResponders: input.minResponders ?? 3,
    maxResponders: input.maxResponders ?? 4
  });

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

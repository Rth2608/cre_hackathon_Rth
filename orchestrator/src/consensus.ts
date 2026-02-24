import type { ConsensusResult, NodeId, NodeReport } from "./types";
import { clampNumber, hashObject } from "./utils";

const PASS_THRESHOLD = 0.6;
const DEFAULT_WEIGHT = 1;

function scoreOfReport(report: NodeReport): number {
  return report.verdict === "PASS" ? report.confidence : -report.confidence;
}

export function computeConsensus(requestId: string, reports: NodeReport[], expectedNodeIds: NodeId[] = []): ConsensusResult {
  const responders = reports.length;

  const includedNodes = reports.map((report) => report.nodeId);
  const excludedNodes = expectedNodeIds.filter((nodeId) => !includedNodes.includes(nodeId));

  if (responders < 3) {
    const fallbackHash = hashObject({
      requestId,
      responders,
      includedNodes,
      excludedNodes,
      status: "FAILED_NO_QUORUM"
    });

    return {
      requestId,
      responders,
      aggregateScore: 0,
      aggregateScoreBps: 0,
      finalVerdict: "FAIL",
      includedNodes,
      excludedNodes,
      finalReportHash: fallbackHash,
      status: "FAILED_NO_QUORUM"
    };
  }

  const weightByNode = new Map<NodeId, number>();
  reports.forEach((report) => {
    if (!weightByNode.has(report.nodeId)) {
      weightByNode.set(report.nodeId, DEFAULT_WEIGHT);
    }
  });

  const weightSum = reports.reduce((acc, report) => acc + (weightByNode.get(report.nodeId) ?? DEFAULT_WEIGHT), 0);

  const weightedScore = reports.reduce((acc, report) => {
    const normalizedWeight = (weightByNode.get(report.nodeId) ?? DEFAULT_WEIGHT) / weightSum;
    return acc + scoreOfReport(report) * normalizedWeight;
  }, 0);

  const aggregateScore = Number(clampNumber(weightedScore, -1, 1).toFixed(4));
  const aggregateScoreBps = Math.round(aggregateScore * 10000);
  const finalVerdict = aggregateScore >= PASS_THRESHOLD ? "PASS" : "FAIL";

  const finalReportHash = hashObject({
    requestId,
    reports,
    aggregateScore,
    aggregateScoreBps,
    finalVerdict,
    includedNodes,
    excludedNodes,
    threshold: PASS_THRESHOLD
  });

  return {
    requestId,
    responders,
    aggregateScore,
    aggregateScoreBps,
    finalVerdict,
    includedNodes,
    excludedNodes,
    finalReportHash,
    status: "OK"
  };
}

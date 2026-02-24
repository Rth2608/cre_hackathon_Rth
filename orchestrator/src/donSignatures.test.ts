import { describe, expect, test } from "bun:test";
import { Wallet, id } from "ethers";
import {
  DON_EIP712_TYPES,
  buildConsensusBundleSkeleton,
  buildDonDomain,
  computeReportsMerkleRootFromSignedReports,
  signOperatorBundleApprovalByKey,
  toConsensusBundleTypedDataValue,
  toNodeReportTypedDataValue,
  validateSignedReportsForQuorum,
  verifyOperatorBundleApprovalSignature,
  verifyConsensusBundleLeaderSignature,
  verifySignedNodeReport
} from "./donSignatures";
import type { SignedNodeReport, SignedNodeReportPayload } from "./types";

function samplePayload(walletAddress: string, requestId: string, reportHash: string): SignedNodeReportPayload {
  return {
    requestId,
    round: 1,
    operator: walletAddress,
    modelFamily: "gpt",
    modelNameHash: id("gpt-4.1"),
    promptTemplateHash: id("prompt-template-v1"),
    canonicalPromptHash: id("prompt-instance-1"),
    paramsHash: id("temperature=0|max_tokens=256"),
    responseHash: id("response-1"),
    executionReceiptHash: id("execution-1"),
    verdict: "PASS",
    confidenceBps: 8200,
    reportHash,
    timestamp: 1735689600
  };
}

describe("donSignatures", () => {
  test("verifies signed node report", async () => {
    const wallet = Wallet.createRandom();
    const domain = buildDonDomain({
      name: "CRE-DON-Consensus",
      version: "1",
      chainId: 1,
      verifyingContract: "0x0000000000000000000000000000000000000001"
    });
    const payload = samplePayload(wallet.address, id("req-1"), id("report-1"));
    const signature = await wallet.signTypedData(domain, DON_EIP712_TYPES.NODE_REPORT_TYPES, toNodeReportTypedDataValue(payload));
    const signedReport: SignedNodeReport = { payload, signature };

    const verified = verifySignedNodeReport(domain, signedReport);

    expect(verified.ok).toBe(true);
    expect(verified.recoveredOperator?.toLowerCase()).toBe(wallet.address.toLowerCase());
  });

  test("validates quorum with invalid signatures filtered", async () => {
    const domain = buildDonDomain({
      name: "CRE-DON-Consensus",
      version: "1",
      chainId: 1,
      verifyingContract: "0x0000000000000000000000000000000000000001"
    });

    const wallets = [Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom()];
    const signedReports: SignedNodeReport[] = [];

    for (let index = 0; index < wallets.length; index += 1) {
      const wallet = wallets[index]!;
      const payload = samplePayload(wallet.address, id("req-2"), id(`report-${index}`));
      const signature = await wallet.signTypedData(
        domain,
        DON_EIP712_TYPES.NODE_REPORT_TYPES,
        toNodeReportTypedDataValue(payload)
      );
      signedReports.push({ payload, signature });
    }

    signedReports[3] = {
      ...signedReports[3]!,
      signature: signedReports[0]!.signature
    };

    const result = validateSignedReportsForQuorum(domain, signedReports, { minResponders: 3, maxResponders: 4 });

    expect(result.quorumReached).toBe(true);
    expect(result.responders).toBe(3);
    expect(result.invalidReports.length).toBe(1);
    expect(result.ok).toBe(false);
    expect(computeReportsMerkleRootFromSignedReports(result.validReports)).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("verifies consensus bundle leader signature", async () => {
    const leader = Wallet.createRandom();
    const domain = buildDonDomain({
      name: "CRE-DON-Consensus",
      version: "1",
      chainId: 1,
      verifyingContract: "0x0000000000000000000000000000000000000001"
    });

    const payload = {
      requestId: id("req-3"),
      requestHash: id("request-hash-3"),
      round: 1,
      aggregateScoreBps: 7100,
      finalVerdict: true,
      responders: 3,
      reportsMerkleRoot: id("reports-root-3"),
      attestationRootHash: id("attestation-root-3"),
      promptTemplateHash: id("prompt-template-v1"),
      consensusTimestamp: 1735689601
    };

    const leaderSignature = await leader.signTypedData(
      domain,
      DON_EIP712_TYPES.CONSENSUS_BUNDLE_TYPES,
      toConsensusBundleTypedDataValue(payload)
    );

    const bundle = buildConsensusBundleSkeleton({
      payload,
      leader: leader.address,
      leaderSignature,
      includedOperators: [leader.address],
      reportSignatures: []
    });

    const verified = verifyConsensusBundleLeaderSignature(domain, bundle);
    expect(verified.ok).toBe(true);
    expect(bundle.bundleHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("verifies operator approval signature for a bundle", async () => {
    const operator = Wallet.createRandom();
    const domain = buildDonDomain({
      name: "CRE-DON-Consensus",
      version: "1",
      chainId: 1,
      verifyingContract: "0x0000000000000000000000000000000000000001"
    });

    const payload = {
      bundleHash: id("bundle-4"),
      requestId: id("request-4"),
      round: 2
    };
    const signed = await signOperatorBundleApprovalByKey(domain, payload, operator.privateKey);
    const verified = verifyOperatorBundleApprovalSignature(domain, payload, signed.signature, operator.address);

    expect(verified.ok).toBe(true);
    expect(verified.recoveredOperator?.toLowerCase()).toBe(operator.address.toLowerCase());
  });
});

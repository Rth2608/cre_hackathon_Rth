import { describe, expect, test } from "bun:test";
import { Wallet, id } from "ethers";
import { DON_EIP712_TYPES, buildDonDomain, toNodeReportTypedDataValue } from "./donSignatures";
import { prepareConsensusBundleFromSignedReports } from "./donConsensus";
import type { SignedNodeReport } from "./types";

describe("donConsensus skeleton", () => {
  test("prepares quorum and bundle from signed reports", async () => {
    const domain = buildDonDomain({
      name: "CRE-DON-Consensus",
      version: "1",
      chainId: 1,
      verifyingContract: "0x0000000000000000000000000000000000000001"
    });
    const wallets = [Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom()];

    const signedReports: SignedNodeReport[] = [];
    for (let index = 0; index < wallets.length; index += 1) {
      const wallet = wallets[index]!;
      const payload = {
        requestId: id("req-don-consensus"),
        round: 1,
        operator: wallet.address,
        modelFamily: "gpt" as const,
        modelNameHash: id("gpt-4.1"),
        promptTemplateHash: id("prompt-template-v1"),
        canonicalPromptHash: id("prompt-instance-1"),
        paramsHash: id("temperature=0|max_tokens=256"),
        responseHash: id(`response-${index}`),
        executionReceiptHash: id(`execution-${index}`),
        verdict: index % 2 === 0 ? ("PASS" as const) : ("FAIL" as const),
        confidenceBps: 7000 + index * 100,
        reportHash: id(`report-${index}`),
        timestamp: 1735689600 + index
      };
      const signature = await wallet.signTypedData(
        domain,
        DON_EIP712_TYPES.NODE_REPORT_TYPES,
        toNodeReportTypedDataValue(payload)
      );

      signedReports.push({ payload, signature });
    }

    const result = prepareConsensusBundleFromSignedReports({
      requestId: id("req-don-consensus"),
      requestHash: id("request-hash"),
      promptTemplateHash: id("prompt-template-v1"),
      attestationRootHash: id("attestation-root-1"),
      round: 1,
      domain,
      signedReports,
      leader: wallets[0]!.address
    });

    expect(result.quorum.quorumReached).toBe(true);
    expect(result.consensus).not.toBeNull();
    expect(result.bundle).not.toBeNull();
    expect(result.bundle?.includedOperators.length).toBe(3);
    expect(result.bundle?.payload.responders).toBe(3);
    expect(result.bundle?.payload.attestationRootHash).toBe(id("attestation-root-1"));
  });

  test("excludes reports that do not share canonical prompt hash/params hash", async () => {
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
      const payload = {
        requestId: id("req-don-consistency"),
        round: 1,
        operator: wallet.address,
        modelFamily: "gpt" as const,
        modelNameHash: id("gpt-4.1"),
        promptTemplateHash: id("prompt-template-v1"),
        canonicalPromptHash: index === 3 ? id("prompt-instance-mismatch") : id("prompt-instance-1"),
        paramsHash: index === 3 ? id("temperature=0.3|max_tokens=256") : id("temperature=0|max_tokens=256"),
        responseHash: id(`response-consistency-${index}`),
        executionReceiptHash: id(`execution-consistency-${index}`),
        verdict: "PASS" as const,
        confidenceBps: 8000,
        reportHash: id(`report-consistency-${index}`),
        timestamp: 1735689700 + index
      };
      const signature = await wallet.signTypedData(
        domain,
        DON_EIP712_TYPES.NODE_REPORT_TYPES,
        toNodeReportTypedDataValue(payload)
      );
      signedReports.push({ payload, signature });
    }

    const result = prepareConsensusBundleFromSignedReports({
      requestId: id("req-don-consistency"),
      requestHash: id("request-hash-consistency"),
      promptTemplateHash: id("prompt-template-v1"),
      attestationRootHash: id("attestation-root-consistency"),
      round: 1,
      domain,
      signedReports,
      leader: wallets[0]!.address
    });

    expect(result.quorum.quorumReached).toBe(true);
    expect(result.quorum.responders).toBe(3);
    expect(result.quorum.invalidReports.some((entry) => entry.reason === "signed_report_canonical_prompt_hash_mismatch")).toBe(true);
    expect(result.bundle).not.toBeNull();
    expect(result.bundle?.payload.responders).toBe(3);
  });
});

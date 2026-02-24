import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { ZeroHash, id } from "ethers";
import type {
  ConsensusBundle,
  ConsensusResult,
  ExecutionReceipt,
  MarketRequestInput,
  NodeReport,
  OnchainReceipt,
  QuorumValidationResult,
  RegisteredNode,
  RequestStatus,
  SignedNodeReport,
  VerificationPaymentReceipt,
  WorkflowRunResult,
  WorkflowStepLog
} from "./types";
import { computeConsensus } from "./consensus";
import { prepareConsensusBundleFromSignedReports } from "./donConsensus";
import { buildSignedRuntimeReports } from "./donRuntime";
import {
  computeReportsMerkleRoot,
  signConsensusBundlePayloadByKey,
  signOperatorBundleApprovalByKey,
  type DonEip712Domain
} from "./donSignatures";
import { collectConsensusBundleSignaturesViaEndpoints, runAllRuntimeNodesViaEndpoints } from "./endpointNodes";
import { runAllRuntimeNodes, type RuntimeNode } from "./mockNodes";
import { ensureDir, nowIso, resolveProjectPath, writeJsonFileAtomic } from "./utils";
import { validateMarketRequest } from "./validator";

const execFileAsync = promisify(execFile);

interface WorkflowParams {
  requestId: string;
  input: MarketRequestInput;
  activeNodes: RegisteredNode[];
  runtimeNodes: RuntimeNode[];
  usedDefaultNodes?: boolean;
  paymentReceipt?: VerificationPaymentReceipt;
  submitOnchain: (args: {
    requestId: string;
    input: MarketRequestInput;
    consensus: ConsensusResult;
    reportUri: string;
    consensusBundle?: ConsensusBundle;
  }) => Promise<OnchainReceipt>;
}

async function runExternalCre(requestArtifactPath: string): Promise<WorkflowRunResult["externalCreOutput"] | undefined> {
  if (process.env.CRE_CLI_ENABLED !== "true") {
    return undefined;
  }

  const command = process.env.CRE_COMMAND?.trim() || "cre";
  const argString = process.env.CRE_ARGS?.trim() || "workflow run";
  const args = argString.split(/\s+/).filter(Boolean);
  args.push("--input", requestArtifactPath);

  const { stdout, stderr } = await execFileAsync(command, args, {
    timeout: 30_000
  });

  return {
    command: `${command} ${args.join(" ")}`,
    stdout: stdout.trim(),
    stderr: stderr.trim()
  };
}

async function runStep(
  step: WorkflowStepLog["step"],
  logs: WorkflowStepLog[],
  fn: () => Promise<void>,
  options?: { skipped?: boolean; detail?: string }
): Promise<void> {
  const startedAt = nowIso();

  if (options?.skipped) {
    logs.push({
      step,
      status: "skipped",
      startedAt,
      endedAt: nowIso(),
      detail: options.detail
    });
    return;
  }

  try {
    await fn();
    logs.push({
      step,
      status: "ok",
      startedAt,
      endedAt: nowIso(),
      detail: options?.detail
    });
  } catch (error) {
    logs.push({
      step,
      status: "failed",
      startedAt,
      endedAt: nowIso(),
      detail: error instanceof Error ? error.message : String(error)
    });
    throw error;
  }
}

function resolveEndpointDispatchEnabled(): boolean {
  return process.env.NODE_ENDPOINT_VERIFY_ENABLED === "true";
}

function resolveEndpointDispatchTimeoutMs(): number {
  const parsed = Number.parseInt(process.env.NODE_ENDPOINT_VERIFY_TIMEOUT_MS ?? "8000", 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 60_000) {
    return 8000;
  }
  return parsed;
}

function resolveEndpointDispatchPath(): string {
  const raw = process.env.NODE_ENDPOINT_VERIFY_PATH?.trim();
  if (!raw) return "/verify";
  return raw.startsWith("/") ? raw : `/${raw}`;
}

function resolveEndpointDispatchFallback(): boolean {
  return process.env.NODE_ENDPOINT_VERIFY_FALLBACK_MOCK === "true";
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function resolveEndpointRequireSignedReports(useDonSignedReports: boolean, useEndpointDispatch: boolean): boolean {
  const fallback = useDonSignedReports && useEndpointDispatch;
  return parseBooleanEnv(process.env.NODE_ENDPOINT_REQUIRE_SIGNED_REPORTS, fallback);
}

function resolveEndpointBundleSigning(useDonSignedReports: boolean, useEndpointDispatch: boolean): boolean {
  const fallback = useDonSignedReports && useEndpointDispatch;
  return parseBooleanEnv(process.env.DON_ENDPOINT_BUNDLE_SIGNING_ENABLED, fallback);
}

function resolveEndpointBundleApprovalPath(): string {
  const raw = process.env.NODE_ENDPOINT_BUNDLE_APPROVAL_PATH?.trim();
  if (!raw) return "/sign-bundle-approval";
  return raw.startsWith("/") ? raw : `/${raw}`;
}

function resolveEndpointLeaderSignPath(): string {
  const raw = process.env.NODE_ENDPOINT_LEADER_SIGN_PATH?.trim();
  if (!raw) return "/sign-consensus-bundle";
  return raw.startsWith("/") ? raw : `/${raw}`;
}

function resolveDonRoundFromEnv(): number {
  const parsed = Number.parseInt(process.env.DON_CONSENSUS_ROUND ?? "1", 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return 1;
  }
  return parsed;
}

function resolvePromptTemplateHashFromEnv(): string {
  const fromEnv = process.env.DON_PROMPT_TEMPLATE_HASH?.trim();
  if (!fromEnv) {
    return id("cre-prediction-market-prompt-template-v1");
  }
  const normalized = fromEnv.startsWith("0x") ? fromEnv : `0x${fromEnv}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    return normalized.toLowerCase();
  }
  return id(fromEnv);
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

export async function runCreWorkflow(params: WorkflowParams): Promise<WorkflowRunResult> {
  const { requestId } = params;
  const artifactDir = resolveProjectPath("reports", "artifacts", requestId);
  const reportPath = resolveProjectPath("reports", `${requestId}.json`);

  await ensureDir(artifactDir);
  await ensureDir(resolveProjectPath("reports"));

  const stepLogs: WorkflowStepLog[] = [];

  let externalCreOutput: WorkflowRunResult["externalCreOutput"];
  let validatedInput: MarketRequestInput = params.input;
  let nodeReports: NodeReport[] = [];
  let signedNodeReports: SignedNodeReport[] = [];
  let executionReceipts: ExecutionReceipt[] = [];
  let nodeFailures: Array<{ nodeId: string; reason: string }> = [];
  let quorumValidation: QuorumValidationResult | undefined;
  let consensus: ConsensusResult | undefined;
  let consensusBundle: ConsensusBundle | undefined;
  let onchainReceipt: OnchainReceipt | undefined;
  let finalStatus: RequestStatus = "FAILED_ONCHAIN_SUBMISSION";
  const runtimeNodes = params.runtimeNodes;
  const useDonSignedReports = process.env.USE_DON_SIGNED_REPORTS === "true";
  const useEndpointDispatch = resolveEndpointDispatchEnabled();
  const endpointDispatchTimeoutMs = resolveEndpointDispatchTimeoutMs();
  const endpointDispatchPath = resolveEndpointDispatchPath();
  const endpointDispatchFallback = resolveEndpointDispatchFallback();
  const endpointRequireSignedReports = resolveEndpointRequireSignedReports(useDonSignedReports, useEndpointDispatch);
  const endpointBundleSigningEnabled = resolveEndpointBundleSigning(useDonSignedReports, useEndpointDispatch);
  const endpointBundleApprovalPath = resolveEndpointBundleApprovalPath();
  const endpointLeaderSignPath = resolveEndpointLeaderSignPath();
  const signerKeyByOperator: Record<string, string> = {};
  let donDomain: DonEip712Domain | undefined;
  let donRound = 1;
  let requestHash = "";
  let promptTemplateHash = "";
  let attestationRootHash = "";

  await runStep("validate_input", stepLogs, async () => {
    validatedInput = await validateMarketRequest(params.input);

    const requestArtifact = {
      requestId,
      input: validatedInput,
      activeNodes: params.activeNodes,
      usedDefaultNodes: params.usedDefaultNodes ?? false,
      paymentReceipt: params.paymentReceipt,
      createdAt: nowIso()
    };

    const requestPath = `${artifactDir}/request.json`;
    await writeJsonFileAtomic(requestPath, requestArtifact);

    externalCreOutput = await runExternalCre(requestPath);
  });

  await runStep("dispatch_nodes", stepLogs, async () => {
    const dispatchResult = useEndpointDispatch
      ? await runAllRuntimeNodesViaEndpoints({
          requestId,
          input: validatedInput,
          runtimeNodes,
          activeNodes: params.activeNodes,
          timeoutMs: endpointDispatchTimeoutMs,
          verifyPath: endpointDispatchPath,
          fallbackToMock: endpointDispatchFallback,
          requireSignedReports: endpointRequireSignedReports
        })
      : {
          ...(await runAllRuntimeNodes(requestId, validatedInput, runtimeNodes)),
          signedReports: [],
          executionReceipts: []
        };
    nodeReports = dispatchResult.reports;
    nodeFailures = dispatchResult.failures;

    if (useDonSignedReports) {
      if (useEndpointDispatch) {
        signedNodeReports = dispatchResult.signedReports ?? [];
        executionReceipts = dispatchResult.executionReceipts ?? [];
        donRound = resolveDonRoundFromEnv();
        requestHash = buildRequestHash(validatedInput);
        promptTemplateHash = resolvePromptTemplateHashFromEnv();
        attestationRootHash =
          executionReceipts.length > 0
            ? computeReportsMerkleRoot(executionReceipts.map((receipt) => receipt.confidentialAttestationHash))
            : ZeroHash;
        if (endpointRequireSignedReports) {
          if (signedNodeReports.length !== nodeReports.length || executionReceipts.length !== nodeReports.length) {
            throw new Error("signed_artifacts_missing_for_some_reports");
          }
        }
      } else {
        const signed = await buildSignedRuntimeReports({
          requestId,
          input: validatedInput,
          nodeReports,
          runtimeNodes
        });
        signedNodeReports = signed.signedReports;
        executionReceipts = signed.executionReceipts;
        nodeFailures = [...nodeFailures, ...signed.failures];
        Object.assign(signerKeyByOperator, signed.signerKeyByOperator);
        donDomain = signed.domain;
        donRound = signed.round;
        requestHash = signed.requestHash;
        promptTemplateHash = signed.promptTemplateHash;
        attestationRootHash = signed.attestationRootHash;
      }
    }
  });

  await runStep("collect_reports", stepLogs, async () => {
    const payload = {
      requestId,
      responders: nodeReports.length,
      reports: nodeReports,
      signedResponders: signedNodeReports.length,
      signedReports: signedNodeReports,
      executionReceipts,
      failures: nodeFailures,
      collectedAt: nowIso()
    };
    await writeJsonFileAtomic(`${artifactDir}/node-reports.json`, payload);
  });

  await runStep("compute_consensus", stepLogs, async () => {
    if (useDonSignedReports) {
      const activeDomain: DonEip712Domain = donDomain ?? {
        name: "CRE-DON-Consensus",
        version: "1",
        chainId: Number.parseInt(process.env.CHAIN_ID ?? "1", 10) || 1,
        verifyingContract: process.env.CONTRACT_ADDRESS || "0x0000000000000000000000000000000000000001"
      };
      const provisionalLeader =
        process.env.DON_LEADER_OPERATOR?.trim() ||
        signedNodeReports[0]?.payload.operator ||
        runtimeNodes[0]?.operatorAddress ||
        "0x0000000000000000000000000000000000000001";

      const prepared = prepareConsensusBundleFromSignedReports({
        requestId,
        requestHash,
        promptTemplateHash,
        attestationRootHash,
        round: donRound,
        domain: activeDomain,
        signedReports: signedNodeReports,
        leader: provisionalLeader
      });

      quorumValidation = prepared.quorum;
      consensus =
        prepared.consensus ??
        computeConsensus(
          requestId,
          [],
          runtimeNodes.map((node) => node.nodeId)
        );

      if (prepared.bundle) {
        const includedOperators = prepared.bundle.includedOperators.map((operator) => operator.toLowerCase());
        if (useEndpointDispatch && endpointBundleSigningEnabled) {
          const selectedLeader = process.env.DON_LEADER_OPERATOR?.trim();
          if (selectedLeader && !includedOperators.includes(selectedLeader.toLowerCase())) {
            throw new Error(`DON_LEADER_OPERATOR is not part of included operators: ${selectedLeader}`);
          }

          consensusBundle = await collectConsensusBundleSignaturesViaEndpoints({
            bundle: prepared.bundle,
            activeNodes: params.activeNodes,
            timeoutMs: endpointDispatchTimeoutMs,
            bundleApprovalPath: endpointBundleApprovalPath,
            leaderSignPath: endpointLeaderSignPath,
            leaderOperator: selectedLeader
          });
        } else {
          const leaderPrivateKeyOverride = process.env.DON_LEADER_PRIVATE_KEY?.trim();
          const selectedLeader = process.env.DON_LEADER_OPERATOR?.trim().toLowerCase();

          if (selectedLeader && !includedOperators.includes(selectedLeader)) {
            throw new Error(`DON_LEADER_OPERATOR is not part of included operators: ${selectedLeader}`);
          }

          let leaderPrivateKey: string | undefined;
          if (leaderPrivateKeyOverride) {
            leaderPrivateKey = leaderPrivateKeyOverride;
          } else if (selectedLeader && signerKeyByOperator[selectedLeader]) {
            leaderPrivateKey = signerKeyByOperator[selectedLeader];
          } else {
            const firstOperatorWithKey = includedOperators.find((operator) => signerKeyByOperator[operator]);
            if (!firstOperatorWithKey) {
              throw new Error("no leader private key found for included operators");
            }
            leaderPrivateKey = signerKeyByOperator[firstOperatorWithKey];
          }

          const leaderSigned = await signConsensusBundlePayloadByKey(activeDomain, prepared.bundle.payload, leaderPrivateKey);
          const approvalSignatures: string[] = [];

          for (const operator of includedOperators) {
            const operatorKey = signerKeyByOperator[operator];
            if (!operatorKey) {
              throw new Error(`missing operator private key for bundle approval: ${operator}`);
            }
            const approval = await signOperatorBundleApprovalByKey(
              activeDomain,
              {
                bundleHash: prepared.bundle.bundleHash,
                requestId: prepared.bundle.payload.requestId,
                round: prepared.bundle.payload.round
              },
              operatorKey
            );
            if (approval.operator.toLowerCase() !== operator) {
              throw new Error(`operator approval signer mismatch for ${operator}`);
            }
            approvalSignatures.push(approval.signature);
          }

          consensusBundle = {
            ...prepared.bundle,
            leader: leaderSigned.leader,
            leaderSignature: leaderSigned.leaderSignature,
            reportSignatures: approvalSignatures
          };
        }
      } else {
        consensusBundle = undefined;
      }
    } else {
      consensus = computeConsensus(
        requestId,
        nodeReports,
        runtimeNodes.map((node) => node.nodeId)
      );
    }

    await writeJsonFileAtomic(`${artifactDir}/consensus.json`, consensus);
  });

  const baseFinalReport = {
    requestId,
    input: validatedInput,
    activeNodes: params.activeNodes,
    usedDefaultNodes: params.usedDefaultNodes ?? false,
    paymentReceipt: params.paymentReceipt ?? null,
    nodeReports,
    signedNodeReports,
    executionReceipts,
    nodeFailures,
    quorumValidation,
    consensus,
    consensusBundle,
    onchainReceipt: null,
    externalCreOutput,
    generatedAt: nowIso(),
    stepLogs
  };

  await runStep("persist_offchain_report", stepLogs, async () => {
    await writeJsonFileAtomic(`${artifactDir}/final-report.json`, baseFinalReport);
    await writeJsonFileAtomic(reportPath, baseFinalReport);
  });

  if (!consensus) {
    throw new Error("consensus was not computed");
  }
  const computedConsensus: ConsensusResult = consensus;

  if (computedConsensus.status === "FAILED_NO_QUORUM") {
    finalStatus = "FAILED_NO_QUORUM";

    await runStep("submit_onchain", stepLogs, async () => {}, {
      skipped: true,
      detail: "insufficient quorum (<3 responders)"
    });
  } else {
    try {
      await runStep("submit_onchain", stepLogs, async () => {
        onchainReceipt = await params.submitOnchain({
          requestId,
          input: validatedInput,
          consensus: computedConsensus,
          reportUri: `report://local/${requestId}`,
          consensusBundle
        });
      });
      finalStatus = "FINALIZED";
    } catch (error) {
      finalStatus = "FAILED_ONCHAIN_SUBMISSION";

      const failureReport = {
        ...baseFinalReport,
        onchainReceipt: null,
        onchainError: error instanceof Error ? error.message : String(error),
        generatedAt: nowIso(),
        stepLogs
      };

      await writeJsonFileAtomic(`${artifactDir}/final-report.json`, failureReport);
      await writeJsonFileAtomic(reportPath, failureReport);

      await runStep("emit_run_summary", stepLogs, async () => {
        await writeJsonFileAtomic(`${artifactDir}/run-summary.json`, {
          requestId,
          finalStatus,
          stepLogs,
          generatedAt: nowIso()
        });
      });

      await writeJsonFileAtomic(`${artifactDir}/final-report.json`, {
        ...failureReport,
        stepLogs
      });
      await writeJsonFileAtomic(reportPath, {
        ...failureReport,
        stepLogs
      });

      return {
        requestId,
        nodeReports,
        signedNodeReports,
        executionReceipts,
        consensus: computedConsensus,
        consensusBundle,
        quorumValidation,
        finalStatus,
        stepLogs,
        artifactDir,
        reportPath,
        externalCreOutput
      };
    }
  }

  const finalReport = {
    ...baseFinalReport,
    onchainReceipt: onchainReceipt ?? null,
    generatedAt: nowIso(),
    stepLogs
  };

  await writeJsonFileAtomic(`${artifactDir}/final-report.json`, finalReport);
  await writeJsonFileAtomic(reportPath, finalReport);

  await runStep("emit_run_summary", stepLogs, async () => {
    await writeJsonFileAtomic(`${artifactDir}/run-summary.json`, {
      requestId,
      finalStatus,
      stepLogs,
      generatedAt: nowIso()
    });
  });

  await writeJsonFileAtomic(`${artifactDir}/final-report.json`, {
    ...finalReport,
    stepLogs
  });
  await writeJsonFileAtomic(reportPath, {
    ...finalReport,
    stepLogs
  });

  return {
    requestId,
    nodeReports,
    signedNodeReports,
    executionReceipts,
    consensus: computedConsensus,
    consensusBundle,
    quorumValidation,
    onchainReceipt,
    finalStatus,
    stepLogs,
    artifactDir,
    reportPath,
    externalCreOutput
  };
}

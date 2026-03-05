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
  RuntimeNode,
  RequestStatus,
  SignedNodeReport,
  VerificationPaymentReceipt,
  WorkflowRunResult,
  WorkflowStepLog
} from "./types";
import { computeConsensus } from "./consensus";
import { prepareConsensusBundleFromSignedReports } from "./donConsensus";
import {
  computeReportsMerkleRoot,
  type DonEip712Domain
} from "./donSignatures";
import { collectConsensusBundleSignaturesViaEndpoints, runAllRuntimeNodesViaEndpoints } from "./endpointNodes";
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

function splitCommandArgs(raw: string): string[] {
  const matched = raw.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
  return matched
    .map((token) => {
      if (token.length >= 2 && token.startsWith("\"") && token.endsWith("\"")) {
        return token.slice(1, -1);
      }
      return token;
    })
    .map((token) => token.trim())
    .filter(Boolean);
}

function hasFlag(args: string[], flag: string): boolean {
  return args.some((arg) => arg === flag || arg.startsWith(`${flag}=`));
}

function normalizeLegacyCreArgs(args: string[]): string[] {
  if (args.length >= 2 && args[0] === "workflow" && args[1] === "run") {
    // CRE v1.2 removed `workflow run`; map legacy config to simulate mode.
    return ["workflow", "simulate", ...args.slice(2)];
  }
  return args;
}

function resolveExternalCreTimeoutMs(): number {
  const parsed = Number.parseInt(process.env.CRE_TIMEOUT_MS?.trim() ?? "", 10);
  if (!Number.isInteger(parsed) || parsed < 1_000 || parsed > 300_000) {
    return 30_000;
  }
  return parsed;
}

function buildExternalCreArgs(requestArtifactPath: string): string[] {
  const rawArgs = process.env.CRE_ARGS?.trim() || "workflow simulate";
  let args = normalizeLegacyCreArgs(splitCommandArgs(rawArgs));
  if (args.length === 0) {
    args = ["workflow", "simulate"];
  }

  const isWorkflowSimulate = args[0] === "workflow" && args[1] === "simulate";
  if (!isWorkflowSimulate) {
    return args;
  }

  const hasWorkflowFolderPath = args.slice(2).some((arg) => !arg.startsWith("-"));
  if (!hasWorkflowFolderPath) {
    const workflowPath = process.env.CRE_WORKFLOW_PATH?.trim() || ".";
    args.splice(2, 0, workflowPath);
  }

  if (!hasFlag(args, "--http-payload")) {
    args.push("--http-payload", requestArtifactPath);
  }

  if (!hasFlag(args, "--non-interactive")) {
    args.push("--non-interactive");
  }

  const triggerIndex = process.env.CRE_TRIGGER_INDEX?.trim() || "0";
  if (/^\d+$/.test(triggerIndex) && !hasFlag(args, "--trigger-index")) {
    args.push("--trigger-index", triggerIndex);
  }

  return args;
}

async function runExternalCre(requestArtifactPath: string): Promise<WorkflowRunResult["externalCreOutput"] | undefined> {
  if (process.env.CRE_CLI_ENABLED !== "true") {
    return undefined;
  }

  const command = process.env.CRE_COMMAND?.trim() || "cre";
  const args = buildExternalCreArgs(requestArtifactPath);
  const timeoutMs = resolveExternalCreTimeoutMs();

  const { stdout, stderr } = await execFileAsync(command, args, {
    timeout: timeoutMs
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
  if (!useEndpointDispatch) {
    throw new Error("NODE_ENDPOINT_VERIFY_ENABLED=true is required. Local runtime dispatch has been removed.");
  }
  const endpointRequireSignedReports = resolveEndpointRequireSignedReports(useDonSignedReports, useEndpointDispatch);
  const endpointBundleSigningEnabled = resolveEndpointBundleSigning(useDonSignedReports, useEndpointDispatch);
  const endpointBundleApprovalPath = resolveEndpointBundleApprovalPath();
  const endpointLeaderSignPath = resolveEndpointLeaderSignPath();
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
    const dispatchResult = await runAllRuntimeNodesViaEndpoints({
      requestId,
      input: validatedInput,
      runtimeNodes,
      activeNodes: params.activeNodes,
      timeoutMs: endpointDispatchTimeoutMs,
      verifyPath: endpointDispatchPath,
      requireSignedReports: endpointRequireSignedReports
    });
    nodeReports = dispatchResult.reports;
    nodeFailures = dispatchResult.failures;

    if (useDonSignedReports) {
      signedNodeReports = dispatchResult.signedReports ?? [];
      executionReceipts = dispatchResult.executionReceipts ?? [];
      donRound = resolveDonRoundFromEnv();
      requestHash = buildRequestHash(validatedInput);
      promptTemplateHash = resolvePromptTemplateHashFromEnv();
      attestationRootHash =
        executionReceipts.length > 0 ? computeReportsMerkleRoot(executionReceipts.map((receipt) => receipt.confidentialAttestationHash)) : ZeroHash;
      if (endpointRequireSignedReports) {
        if (signedNodeReports.length !== nodeReports.length || executionReceipts.length !== nodeReports.length) {
          throw new Error("signed_artifacts_missing_for_some_reports");
        }
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
      const chainId = Number.parseInt(process.env.CHAIN_ID ?? "", 10);
      const verifyingContract = process.env.DON_VERIFIER_CONTRACT?.trim() || process.env.CONTRACT_ADDRESS?.trim();
      if (!Number.isInteger(chainId) || chainId <= 0) {
        throw new Error("CHAIN_ID must be set to a positive integer when USE_DON_SIGNED_REPORTS=true");
      }
      if (!verifyingContract) {
        throw new Error("DON_VERIFIER_CONTRACT or CONTRACT_ADDRESS is required when USE_DON_SIGNED_REPORTS=true");
      }

      const activeDomain: DonEip712Domain = {
        name: process.env.DON_DOMAIN_NAME?.trim() || "CRE-DON-Consensus",
        version: process.env.DON_DOMAIN_VERSION?.trim() || "1",
        chainId,
        verifyingContract
      };
      const provisionalLeader =
        process.env.DON_LEADER_OPERATOR?.trim() ||
        signedNodeReports[0]?.payload.operator ||
        runtimeNodes[0]?.operatorAddress;
      if (!provisionalLeader) {
        throw new Error("unable to determine DON leader operator from reports or runtime nodes");
      }

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
        if (!endpointBundleSigningEnabled) {
          throw new Error(
            "DON_ENDPOINT_BUNDLE_SIGNING_ENABLED=true is required. Local/private-key bundle signing path has been removed."
          );
        }

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

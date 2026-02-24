import { readFile } from "node:fs/promises";
import { getAddress, verifyMessage } from "ethers";
import type { MarketRequestInput, OnchainReceipt, RequestStatus, StoredRequest } from "./types";
import { runCreWorkflow } from "./creRunner";
import { selectRuntimeNodesForRequest } from "./matcher";
import {
  activateNodeRegistrationChallenge,
  createNodeRegistrationChallenge,
  listRegisteredNodes,
  refreshNodeEndpointHealth,
  registerOrUpdateNode,
  touchNodeHeartbeat
} from "./nodeRegistry";
import { getRequestFromOnchain, listNodesFromOnchain, listRequestsFromOnchain } from "./onchainReader";
import { submitConsensusOnchain, submitNodeLifecycleOnchain, submitPorProofOnchain } from "./onchainWriter";
import { buildNextPorProofInput, getPorStatusSnapshot } from "./por";
import { getRequest, listRequests, saveRequest } from "./storage";
import { generateRequestId, hashObject, nowIso, resolveProjectPath } from "./utils";
import { ValidationError, validateMarketRequest } from "./validator";
import { issueWorldIdSessionFromProof, isWorldIdAssumeEnabled, validateWorldIdSessionToken } from "./worldId";
import { enforceX402Payment } from "./x402";

const PORT = Number.parseInt(process.env.PORT ?? "8787", 10);
const MAX_RUN_ATTEMPTS = 2;
const CORS_ALLOW_HEADERS = "Content-Type, X-Wallet-Address, X-Payment, Payment-Signature, X-World-ID-Token";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS
    }
  });
}

function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS
    }
  });
}

async function parseJsonBody<T>(req: Request): Promise<T> {
  const text = await req.text();
  if (!text) {
    throw new Error("Request body is empty");
  }
  return JSON.parse(text) as T;
}

function buildRequestResponse(record: StoredRequest): Record<string, unknown> {
  return {
    requestId: record.requestId,
    status: record.status,
    runAttempts: record.runAttempts,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    input: record.input,
    nodeReports: record.nodeReports,
    signedNodeReports: record.signedNodeReports,
    executionReceipts: record.executionReceipts,
    quorumValidation: record.quorumValidation,
    consensus: record.consensus,
    consensusBundle: record.consensusBundle,
    onchainReceipt: record.onchainReceipt,
    activeNodes: record.activeNodes,
    paymentReceipt: record.paymentReceipt,
    lastError: record.lastError
  };
}

function parseRequestIdFromPath(pathname: string, regex: RegExp): string | null {
  const matched = pathname.match(regex);
  return matched ? decodeURIComponent(matched[1]) : null;
}

function resolveRequestVerificationPrice(): string {
  return process.env.X402_PRICE_REQUEST_CREATE?.trim() || process.env.X402_PRICE_RUN_VERIFICATION?.trim() || "$0.05";
}

function resolveNodeRegistrationPrice(): string {
  return process.env.X402_PRICE_NODE_REGISTRATION?.trim() || "$0.01";
}

function resolveNodeLifecycleOnchainEnabled(): boolean {
  return parseBooleanEnv(process.env.NODE_LIFECYCLE_ONCHAIN_ENABLED, false);
}

function resolvePorAutoRecordEnabled(): boolean {
  return parseBooleanEnv(process.env.POR_ONCHAIN_AUTO_RECORD_ENABLED, true);
}

function resolvePorAutoRecordStrict(): boolean {
  return parseBooleanEnv(process.env.POR_ONCHAIN_AUTO_RECORD_STRICT, false);
}

function resolveOnchainReadEnabled(): boolean {
  return parseBooleanEnv(process.env.ONCHAIN_READ_ENABLED, true);
}

function resolveOnchainReadStrict(): boolean {
  return parseBooleanEnv(process.env.ONCHAIN_READ_STRICT, true);
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function resolveHeartbeatTtlSeconds(): number | undefined {
  const raw = process.env.NODE_HEARTBEAT_TTL_SECONDS?.trim();
  if (!raw) return undefined;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 30 || parsed > 86_400) {
    return undefined;
  }
  return parsed;
}

function resolveDistributedDonMode(): boolean {
  const fallback = process.env.USE_DON_SIGNED_REPORTS === "true" && process.env.NODE_ENDPOINT_VERIFY_ENABLED === "true";
  return parseBooleanEnv(process.env.DON_DISTRIBUTED_MODE, fallback);
}

async function requireWorldIdForWallet(
  req: Request,
  walletAddress: string
): Promise<{ ok: true } | { ok: false; status: number; error: string; detail?: string }> {
  if (isWorldIdAssumeEnabled()) {
    return { ok: true };
  }

  const token = req.headers.get("x-world-id-token")?.trim() ?? "";
  if (!token) {
    return {
      ok: false,
      status: 403,
      error: "world_id_token_required",
      detail: "Verify with World ID first and resend with x-world-id-token header."
    };
  }

  const validation = await validateWorldIdSessionToken({
    token,
    walletAddress
  });
  if (!validation.ok) {
    return {
      ok: false,
      status: 403,
      error: "world_id_token_invalid",
      detail: validation.reason
    };
  }

  return { ok: true };
}

function normalizeAddress(value: string): string {
  return getAddress(value).toLowerCase();
}

function tryNormalizeAddress(value: string): string | null {
  try {
    return normalizeAddress(value);
  } catch {
    return null;
  }
}

function normalizeFamilyList(values: string[] | undefined): string[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return Array.from(
    new Set(
      values
        .map((value) => value.trim().toLowerCase())
        .filter((value) => value === "gpt" || value === "gemini" || value === "claude" || value === "grok")
    )
  );
}

function resolveAutoModelName(walletAddress: string, selectedModelFamilies: string[], provided?: string): string {
  if (provided && provided.trim()) {
    return provided.trim();
  }
  const prefix = process.env.NODE_DEFAULT_MODEL_NAME_PREFIX?.trim() || "operator";
  const familyPart = selectedModelFamilies.length > 0 ? selectedModelFamilies.join("-") : "generic";
  const walletPart = walletAddress.slice(2, 8).toLowerCase();
  return `${prefix}-${familyPart}-${walletPart}`;
}

function parseNodeEndpointMap(): Record<string, string> {
  const raw = process.env.NODE_ENDPOINT_URL_MAP_JSON?.trim();
  if (!raw) {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== "string") continue;
    const normalized = tryNormalizeAddress(key);
    if (!normalized) continue;
    result[normalized] = value.trim();
  }
  return result;
}

function parseNodeEndpointByFamilyMap(): Record<string, string> {
  const raw = process.env.NODE_ENDPOINT_URL_BY_FAMILY_JSON?.trim();
  if (!raw) {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== "string") continue;
    const family = key.trim().toLowerCase();
    if (family !== "gpt" && family !== "gemini" && family !== "claude" && family !== "grok") {
      continue;
    }
    result[family] = value.trim();
  }

  return result;
}

function resolveAutoEndpointUrl(walletAddress: string, selectedModelFamilies: string[], provided?: string): string | undefined {
  if (provided && provided.trim()) {
    return provided.trim();
  }

  const map = parseNodeEndpointMap();
  const mapped = map[walletAddress];
  if (mapped) {
    return mapped;
  }

  const familyMap = parseNodeEndpointByFamilyMap();
  for (const family of selectedModelFamilies) {
    const byFamily = familyMap[family];
    if (byFamily) {
      return byFamily;
    }
  }

  const fallback = process.env.NODE_DEFAULT_ENDPOINT_URL?.trim();
  if (fallback) {
    return fallback;
  }

  return undefined;
}

function buildNodeHeartbeatMessage(input: { walletAddress: string; endpointUrl: string; timestamp: number }): string {
  return [
    "CRE Node Heartbeat",
    `walletAddress: ${input.walletAddress}`,
    `endpointUrl: ${input.endpointUrl}`,
    `timestamp: ${input.timestamp}`
  ].join("\n");
}

async function handleGetRequest(requestId: string): Promise<Response> {
  if (resolveOnchainReadEnabled()) {
    try {
      const onchainRecord = await getRequestFromOnchain(requestId);
      if (onchainRecord) {
        return jsonResponse({
          ok: true,
          data: buildRequestResponse(onchainRecord)
        });
      }
    } catch (error) {
      if (resolveOnchainReadStrict()) {
        return jsonResponse(
          {
            ok: false,
            error: "onchain_read_failed",
            detail: error instanceof Error ? error.message : String(error)
          },
          502
        );
      }
    }
  }

  const record = await getRequest(requestId);
  if (!record) {
    return jsonResponse({ ok: false, error: "request_not_found" }, 404);
  }

  return jsonResponse({
    ok: true,
    data: buildRequestResponse(record)
  });
}

async function executeVerificationForRecord(
  req: Request,
  existing: StoredRequest,
  options?: {
    paymentResource?: string;
    paymentPrice?: string;
    paymentReceipt?: StoredRequest["paymentReceipt"];
  }
): Promise<Response> {
  if (existing.runAttempts >= MAX_RUN_ATTEMPTS) {
    return jsonResponse(
      {
        ok: false,
        error: "max_attempts_exceeded",
        maxAttempts: MAX_RUN_ATTEMPTS
      },
      409
    );
  }

  if (existing.status === "FINALIZED") {
    return jsonResponse({ ok: false, error: "already_finalized" }, 409);
  }

  if (existing.status === "RUNNING") {
    return jsonResponse({ ok: false, error: "request_already_running" }, 409);
  }

  const requestId = existing.requestId;

  const paymentResult =
    options?.paymentReceipt !== undefined
      ? {
          ok: true,
          receipt: options.paymentReceipt
        }
      : await enforceX402Payment(req, {
          resource: options?.paymentResource ?? `/api/requests/${requestId}/run-verification`,
          price: options?.paymentPrice ?? resolveRequestVerificationPrice(),
          walletAddress: existing.input.submitterAddress
        });

  if (!paymentResult.ok || !paymentResult.receipt) {
    return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
  }

  const distributedDonMode = resolveDistributedDonMode();
  const minNodeStake = process.env.MIN_NODE_STAKE?.trim() || "0";
  const requireRegisteredNodes = parseBooleanEnv(process.env.REQUIRE_REGISTERED_NODES, distributedDonMode);
  const allowDefaultNodes = parseBooleanEnv(process.env.ALLOW_DEFAULT_NODES, !distributedDonMode);
  const refreshHealthBeforeMatch = parseBooleanEnv(process.env.NODE_REFRESH_HEALTH_BEFORE_MATCH, false);
  const requireEndpointUrl = parseBooleanEnv(process.env.REQUIRE_NODE_ENDPOINT_URL, distributedDonMode);
  const requireHealthyEndpoint = parseBooleanEnv(process.env.REQUIRE_HEALTHY_NODE_ENDPOINTS, distributedDonMode);
  const heartbeatTtlSeconds = resolveHeartbeatTtlSeconds();

  const nodesSource = refreshHealthBeforeMatch
    ? await refreshNodeEndpointHealth()
    : await listRegisteredNodes({ status: "ACTIVE" });
  const activeNodes = nodesSource.filter((node) => node.status === "ACTIVE");
  const match = selectRuntimeNodesForRequest(activeNodes, {
    desiredNodes: 4,
    minStakeAmount: minNodeStake,
    allowDefaultNodes,
    requireEndpointUrl,
    requireHealthyEndpoint,
    heartbeatTtlSeconds
  });

  if (requireRegisteredNodes && match.selectedNodes.length < 3) {
    const failedRecord: StoredRequest = {
      ...existing,
      runAttempts: existing.runAttempts + 1,
      status: "FAILED_NO_QUORUM",
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      updatedAt: nowIso(),
      lastError: "insufficient_registered_nodes"
    };

    await saveRequest(failedRecord);

    return jsonResponse(
      {
        ok: false,
        error: "insufficient_registered_nodes",
        detail: "at least 3 ACTIVE/eligible registered nodes are required",
        data: buildRequestResponse(failedRecord)
      },
      409
    );
  }

  if (match.runtimeNodes.length < 3) {
    const failedRecord: StoredRequest = {
      ...existing,
      runAttempts: existing.runAttempts + 1,
      status: "FAILED_NO_QUORUM",
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      updatedAt: nowIso(),
      lastError: "insufficient_runtime_nodes"
    };
    await saveRequest(failedRecord);

    return jsonResponse(
      {
        ok: false,
        error: "insufficient_runtime_nodes",
        detail: "matched runtime nodes are fewer than quorum (3)"
      },
      409
    );
  }

  const runningRecord: StoredRequest = {
    ...existing,
    runAttempts: existing.runAttempts + 1,
    status: "RUNNING",
    activeNodes: match.selectedNodes,
    paymentReceipt: paymentResult.receipt,
    updatedAt: nowIso(),
    lastError: undefined
  };

  await saveRequest(runningRecord);

  try {
    const workflow = await runCreWorkflow({
      requestId,
      input: existing.input,
      activeNodes: match.selectedNodes,
      runtimeNodes: match.runtimeNodes,
      usedDefaultNodes: match.usedDefaultNodes,
      paymentReceipt: paymentResult.receipt,
      submitOnchain: submitConsensusOnchain
    });

    const finalStatus: RequestStatus = workflow.finalStatus;
    let porOnchainReceipt: OnchainReceipt | undefined;
    let porOnchainError: string | undefined;

    if (finalStatus === "FINALIZED" && resolvePorAutoRecordEnabled()) {
      try {
        const nextPorProof = await buildNextPorProofInput({
          requestId,
          verificationTxHash: workflow.onchainReceipt?.txHash
        });
        porOnchainReceipt = await submitPorProofOnchain(nextPorProof);
      } catch (error) {
        porOnchainError = error instanceof Error ? error.message : String(error);
        if (resolvePorAutoRecordStrict()) {
          throw error;
        }
      }
    }

    const finalized: StoredRequest = {
      ...runningRecord,
      status: finalStatus,
      nodeReports: workflow.nodeReports,
      signedNodeReports: workflow.signedNodeReports,
      executionReceipts: workflow.executionReceipts,
      quorumValidation: workflow.quorumValidation,
      consensus: workflow.consensus,
      consensusBundle: workflow.consensusBundle,
      onchainReceipt: workflow.onchainReceipt,
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      updatedAt: nowIso(),
      lastError: finalStatus === "FAILED_ONCHAIN_SUBMISSION" ? "onchain submission failed" : undefined
    };

    await saveRequest(finalized);

    return jsonResponse({
      ok: true,
      data: {
        ...buildRequestResponse(finalized),
        workflow: {
          artifactDir: workflow.artifactDir,
          reportPath: workflow.reportPath,
          stepLogs: workflow.stepLogs,
          quorumValidation: workflow.quorumValidation,
          consensusBundle: workflow.consensusBundle,
          externalCreOutput: workflow.externalCreOutput,
          porOnchainReceipt,
          porOnchainError
        }
      }
    });
  } catch (error) {
    const failed: StoredRequest = {
      ...runningRecord,
      status: "FAILED_ONCHAIN_SUBMISSION",
      activeNodes: match.selectedNodes,
      paymentReceipt: paymentResult.receipt,
      updatedAt: nowIso(),
      lastError: error instanceof Error ? error.message : String(error)
    };
    await saveRequest(failed);

    return jsonResponse(
      {
        ok: false,
        error: "verification_failed",
        detail: failed.lastError
      },
      500
    );
  }
}

async function handleCreateRequest(req: Request): Promise<Response> {
  try {
    const body = await parseJsonBody<MarketRequestInput>(req);
    const validated = await validateMarketRequest(body);

    const paymentResult = await enforceX402Payment(req, {
      resource: "/api/requests",
      price: resolveRequestVerificationPrice(),
      walletAddress: validated.submitterAddress
    });
    if (!paymentResult.ok) {
      return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
    }

    const timestamp = nowIso();

    const record: StoredRequest = {
      requestId: generateRequestId(),
      input: validated,
      createdAt: timestamp,
      updatedAt: timestamp,
      status: "PENDING",
      runAttempts: 0
    };

    await saveRequest(record);

    return executeVerificationForRecord(req, record, {
      paymentResource: "/api/requests",
      paymentPrice: resolveRequestVerificationPrice(),
      paymentReceipt: paymentResult.receipt
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return jsonResponse(
        {
          ok: false,
          error: "validation_failed",
          issues: error.issues
        },
        400
      );
    }

    return jsonResponse(
      {
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

async function handleRunVerification(req: Request, requestId: string): Promise<Response> {
  const existing = await getRequest(requestId);
  if (!existing) {
    return jsonResponse({ ok: false, error: "request_not_found" }, 404);
  }
  return executeVerificationForRecord(req, existing);
}

async function handleGetReport(requestId: string): Promise<Response> {
  const record = await getRequest(requestId);
  if (!record) {
    return jsonResponse({ ok: false, error: "request_not_found" }, 404);
  }

  const reportPath = resolveProjectPath("reports", `${requestId}.json`);

  try {
    const raw = await readFile(reportPath, "utf8");
    const report = JSON.parse(raw) as unknown;

    return jsonResponse({
      ok: true,
      data: report
    });
  } catch {
    return jsonResponse({ ok: false, error: "report_not_found" }, 404);
  }
}

interface VerifyWorldIdBody {
  walletAddress: string;
  proof: unknown;
}

async function handleVerifyWorldId(req: Request): Promise<Response> {
  let body: VerifyWorldIdBody;
  try {
    body = await parseJsonBody<VerifyWorldIdBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  try {
    const normalizedWalletAddress = normalizeAddress(body.walletAddress);
    const headerWalletAddress = req.headers.get("x-wallet-address")?.trim();
    if (headerWalletAddress) {
      const normalizedHeaderWalletAddress = normalizeAddress(headerWalletAddress);
      if (normalizedHeaderWalletAddress !== normalizedWalletAddress) {
        return jsonResponse(
          {
            ok: false,
            error: "wallet_header_mismatch"
          },
          400
        );
      }
    }

    const session = await issueWorldIdSessionFromProof({
      walletAddress: normalizedWalletAddress,
      rawProof: (body.proof ?? {}) as Record<string, unknown>
    });

    return jsonResponse({
      ok: true,
      data: {
        session
      }
    });
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "world_id_verify_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

interface RegisterNodeBody {
  walletAddress: string;
  selectedModelFamilies: string[];
  modelName?: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
}

async function handleRegisterNode(req: Request): Promise<Response> {
  let body: RegisterNodeBody;

  try {
    body = await parseJsonBody<RegisterNodeBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  let normalizedWalletAddress: string;
  try {
    normalizedWalletAddress = normalizeAddress(body.walletAddress);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_wallet_address",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  const worldIdAuth = await requireWorldIdForWallet(req, normalizedWalletAddress);
  if (!worldIdAuth.ok) {
    return jsonResponse(
      {
        ok: false,
        error: worldIdAuth.error,
        detail: worldIdAuth.detail
      },
      worldIdAuth.status
    );
  }

  const paymentResult = await enforceX402Payment(req, {
    resource: "/api/nodes/register",
    price: resolveNodeRegistrationPrice(),
    walletAddress: normalizedWalletAddress
  });
  if (!paymentResult.ok) {
    return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
  }

  try {
    const normalizedFamilies = normalizeFamilyList(body.selectedModelFamilies);
    const modelName = resolveAutoModelName(normalizedWalletAddress, normalizedFamilies, body.modelName);
    const endpointUrl = resolveAutoEndpointUrl(normalizedWalletAddress, normalizedFamilies, body.endpointUrl);

    const node = await registerOrUpdateNode({
      walletAddress: normalizedWalletAddress,
      selectedModelFamilies: normalizedFamilies,
      modelName,
      endpointUrl,
      peerId: body.peerId,
      tlsCertFingerprint: body.tlsCertFingerprint,
      stakeAmount: body.stakeAmount,
      participationEnabled: body.participationEnabled,
      worldIdVerified: true
    });

    return jsonResponse(
      {
        ok: true,
        data: {
          node,
          paymentReceipt: paymentResult.receipt
        }
      },
      201
    );
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "node_registration_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

interface CreateNodeChallengeBody {
  walletAddress: string;
  selectedModelFamilies: string[];
  modelName?: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
}

async function handleCreateNodeChallenge(req: Request): Promise<Response> {
  let body: CreateNodeChallengeBody;
  try {
    body = await parseJsonBody<CreateNodeChallengeBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  let normalizedWalletAddress: string;
  try {
    normalizedWalletAddress = normalizeAddress(body.walletAddress);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_wallet_address",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  const worldIdAuth = await requireWorldIdForWallet(req, normalizedWalletAddress);
  if (!worldIdAuth.ok) {
    return jsonResponse(
      {
        ok: false,
        error: worldIdAuth.error,
        detail: worldIdAuth.detail
      },
      worldIdAuth.status
    );
  }

  const paymentResult = await enforceX402Payment(req, {
    resource: "/api/nodes/challenge",
    price: resolveNodeRegistrationPrice(),
    walletAddress: normalizedWalletAddress
  });
  if (!paymentResult.ok) {
    return paymentResult.response ?? jsonResponse({ ok: false, error: "payment_failed" }, 402);
  }

  try {
    const normalizedFamilies = normalizeFamilyList(body.selectedModelFamilies);
    const modelName = resolveAutoModelName(normalizedWalletAddress, normalizedFamilies, body.modelName);
    const endpointUrl = resolveAutoEndpointUrl(normalizedWalletAddress, normalizedFamilies, body.endpointUrl);
    if (!endpointUrl) {
      return jsonResponse(
        {
          ok: false,
          error: "endpoint_not_configured_for_wallet",
          detail:
            "set NODE_ENDPOINT_URL_MAP_JSON, NODE_ENDPOINT_URL_BY_FAMILY_JSON, or NODE_DEFAULT_ENDPOINT_URL"
        },
        400
      );
    }

    const challenge = await createNodeRegistrationChallenge({
      walletAddress: normalizedWalletAddress,
      selectedModelFamilies: normalizedFamilies,
      modelName,
      endpointUrl,
      peerId: body.peerId,
      tlsCertFingerprint: body.tlsCertFingerprint,
      stakeAmount: body.stakeAmount,
      participationEnabled: body.participationEnabled,
      worldIdVerified: true
    });

    return jsonResponse(
      {
        ok: true,
        data: {
          challenge,
          paymentReceipt: paymentResult.receipt
        }
      },
      201
    );
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "node_challenge_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

interface ActivateNodeChallengeBody {
  challengeId: string;
  walletAddress: string;
  signature: string;
}

async function handleActivateNodeChallenge(req: Request): Promise<Response> {
  let body: ActivateNodeChallengeBody;
  try {
    body = await parseJsonBody<ActivateNodeChallengeBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  try {
    const result = await activateNodeRegistrationChallenge({
      challengeId: body.challengeId,
      walletAddress: body.walletAddress,
      signature: body.signature
    });

    const lifecycleOnchainReceipt =
      resolveNodeLifecycleOnchainEnabled() && result.node.endpointUrl
        ? await submitNodeLifecycleOnchain({
            nodeId: result.node.walletAddress,
            action: "ACTIVATED",
            endpointUrl: result.node.endpointUrl,
            payloadHash: result.challenge.challengeId,
            payloadUri: `node://challenge/${result.challenge.challengeId}`,
            lifecycleId: hashObject({
              kind: "ACTIVATED",
              challengeId: result.challenge.challengeId
            })
          })
        : undefined;

    return jsonResponse(
      {
        ok: true,
        data: {
          ...result,
          lifecycleOnchainReceipt
        }
      },
      200
    );
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "node_activation_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

interface NodeHeartbeatBody {
  walletAddress: string;
  endpointUrl?: string;
  timestamp: number;
  signature: string;
}

async function handleNodeHeartbeat(req: Request): Promise<Response> {
  let body: NodeHeartbeatBody;
  try {
    body = await parseJsonBody<NodeHeartbeatBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }

  const timestamp = Number.isFinite(body.timestamp) ? Math.trunc(body.timestamp) : NaN;
  if (!Number.isFinite(timestamp)) {
    return jsonResponse({ ok: false, error: "invalid_heartbeat_timestamp" }, 400);
  }

  const nowMs = Date.now();
  if (Math.abs(nowMs - timestamp) > 5 * 60_000) {
    return jsonResponse({ ok: false, error: "heartbeat_timestamp_out_of_window" }, 400);
  }

  const endpointUrl = body.endpointUrl?.trim() || "";
  if (endpointUrl.length === 0) {
    return jsonResponse({ ok: false, error: "endpointUrl_required" }, 400);
  }

  try {
    const normalizedWallet = normalizeAddress(body.walletAddress);
    const heartbeatMessage = buildNodeHeartbeatMessage({
      walletAddress: normalizedWallet,
      endpointUrl,
      timestamp
    });
    const recovered = normalizeAddress(verifyMessage(heartbeatMessage, body.signature));
    if (recovered !== normalizedWallet) {
      return jsonResponse({ ok: false, error: "heartbeat_signature_invalid" }, 401);
    }

    const result = await touchNodeHeartbeat({
      walletAddress: normalizedWallet,
      endpointUrl
    });

    const lifecycleOnchainReceipt =
      resolveNodeLifecycleOnchainEnabled() && result.node.endpointUrl
        ? await submitNodeLifecycleOnchain({
            nodeId: result.node.walletAddress,
            action: "HEARTBEAT",
            endpointUrl: result.node.endpointUrl,
            payloadHash: hashObject({
              walletAddress: normalizedWallet,
              endpointUrl,
              timestamp,
              signature: body.signature
            }),
            payloadUri: `node://heartbeat/${normalizedWallet}/${timestamp}`,
            lifecycleId: hashObject({
              kind: "HEARTBEAT",
              walletAddress: normalizedWallet,
              endpointUrl,
              timestamp
            })
          })
        : undefined;

    return jsonResponse({
      ok: true,
      data: {
        node: result.node,
        endpointProbe: result.endpointProbe,
        heartbeatMessage,
        lifecycleOnchainReceipt
      }
    });
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "node_heartbeat_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

async function handleListNodes(): Promise<Response> {
  if (resolveOnchainReadEnabled()) {
    try {
      const nodes = await listNodesFromOnchain();
      return jsonResponse({
        ok: true,
        data: nodes
      });
    } catch (error) {
      if (resolveOnchainReadStrict()) {
        return jsonResponse(
          {
            ok: false,
            error: "onchain_read_failed",
            detail: error instanceof Error ? error.message : String(error)
          },
          502
        );
      }
    }
  }

  const localNodes = await listRegisteredNodes();
  return jsonResponse({
    ok: true,
    data: localNodes
  });
}

async function router(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { pathname } = url;
  const requestPathRegex = /^\/api\/requests\/([^/]+)$/;
  const runPathRegex = /^\/api\/requests\/([^/]+)\/run-verification$/;
  const reportPathRegex = /^\/api\/requests\/([^/]+)\/report$/;

  if (req.method === "OPTIONS") {
    return corsPreflight();
  }

  if (req.method === "GET" && pathname === "/healthz") {
    return jsonResponse({ ok: true, service: "orchestrator", timestamp: nowIso() });
  }

  if (req.method === "GET" && pathname === "/api/requests") {
    let items: StoredRequest[];
    if (resolveOnchainReadEnabled()) {
      try {
        items = await listRequestsFromOnchain();
      } catch (error) {
        if (resolveOnchainReadStrict()) {
          return jsonResponse(
            {
              ok: false,
              error: "onchain_read_failed",
              detail: error instanceof Error ? error.message : String(error)
            },
            502
          );
        }
        items = await listRequests();
      }
    } else {
      items = await listRequests();
    }
    return jsonResponse({
      ok: true,
      data: items.map((record) => buildRequestResponse(record))
    });
  }

  if (req.method === "GET" && pathname === "/api/por/status") {
    const status = await getPorStatusSnapshot();
    return jsonResponse({
      ok: true,
      data: status
    });
  }

  if (req.method === "GET" && pathname === "/api/nodes") {
    return handleListNodes();
  }

  if (req.method === "POST" && pathname === "/api/world-id/verify") {
    return handleVerifyWorldId(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/register") {
    return handleRegisterNode(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/challenge") {
    return handleCreateNodeChallenge(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/activate") {
    return handleActivateNodeChallenge(req);
  }

  if (req.method === "POST" && pathname === "/api/nodes/heartbeat") {
    return handleNodeHeartbeat(req);
  }

  if (req.method === "POST" && pathname === "/api/requests") {
    return handleCreateRequest(req);
  }

  if (req.method === "GET") {
    const requestId = parseRequestIdFromPath(pathname, requestPathRegex);
    if (requestId) {
      return handleGetRequest(requestId);
    }
  }

  if (req.method === "POST") {
    const requestId = parseRequestIdFromPath(pathname, runPathRegex);
    if (requestId) {
      return handleRunVerification(req, requestId);
    }
  }

  if (req.method === "GET") {
    const requestId = parseRequestIdFromPath(pathname, reportPathRegex);
    if (requestId) {
      return handleGetReport(requestId);
    }
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

Bun.serve({
  port: PORT,
  fetch: router
});

console.log(`[orchestrator] listening on http://localhost:${PORT}`);

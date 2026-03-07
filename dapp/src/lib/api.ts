import { signMessage } from "thirdweb/utils";
import type { Account } from "thirdweb/wallets";
import { MiniKit } from "@worldcoin/minikit-js";

export type NodeId = string;

export interface MarketRequestInput {
  question: string;
  description: string;
  sourceUrls: string[];
  resolutionCriteria: string;
  submitterAddress: string;
}

export interface RequestRecord {
  requestId: string;
  status:
    | "PENDING"
    | "RUNNING"
    | "FINALIZED"
    | "REJECTED_DUPLICATE"
    | "REJECTED_CONFLICT"
    | "FAILED_NO_QUORUM"
    | "FAILED_ONCHAIN_SUBMISSION";
  vectorSync?: {
    state: "PENDING" | "APPLYING" | "APPLIED" | "FAILED";
    vectorStatus: "QUEUED" | "VERIFYING" | "APPROVED_PENDING_OPEN" | "OPEN" | "REJECTED";
    attempts: number;
    updatedAt: string;
    lastError?: string;
  };
  queuePriority?: number;
  queueDecision?: {
    decision: "allow" | "reject_duplicate" | "reject_conflict";
    reason?: string;
    dedupeKey: string;
    conflictKey: string;
    source: "heuristic" | "screening_service" | "heuristic+screening_service";
    evaluatedAt: string;
  };
  runAttempts: number;
  createdAt: string;
  updatedAt: string;
  input: MarketRequestInput;
  consensus?: {
    aggregateScore: number;
    aggregateScoreBps: number;
    responders: number;
    finalVerdict: "PASS" | "FAIL";
    finalReportHash: string;
    status: "OK" | "FAILED_NO_QUORUM";
  };
  onchainReceipt?: {
    txHash: string;
    blockNumber: number;
    gasUsed: string;
    chainId: number;
    explorerUrl?: string;
    simulated: boolean;
    idempotencyKey?: string;
    idempotencyReused?: boolean;
    submissionAttempts?: number;
  };
  activeNodes?: RegisteredNode[];
  paymentReceipt?: VerificationPaymentReceipt;
  workflowStepLogs?: WorkflowStepLog[];
  lastError?: string;
}

export interface WorkflowStepLog {
  step:
    | "validate_input"
    | "dispatch_nodes"
    | "collect_reports"
    | "compute_consensus"
    | "persist_offchain_report"
    | "submit_onchain"
    | "emit_run_summary";
  status: "ok" | "failed" | "skipped";
  startedAt: string;
  endedAt: string;
  detail?: string;
}

export interface VerificationPaymentReceipt {
  x402Enabled: boolean;
  required: boolean;
  paid: boolean;
  payerAddress: string;
  resource: string;
  price: string;
  paymentRef: string;
  settledAt: string;
}

export interface RegisteredNode {
  registrationId: string;
  walletAddress: string;
  nodeId: string;
  selectedModelFamilies: Array<"gpt" | "gemini" | "claude" | "grok">;
  modelName: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  endpointStatus: "UNKNOWN" | "HEALTHY" | "UNHEALTHY";
  endpointLastCheckedAt?: string;
  endpointLastHeartbeatAt?: string;
  endpointLatencyMs?: number;
  endpointFailureCount: number;
  endpointLastError?: string;
  endpointVerifiedAt?: string;
  stakeAmount: string;
  participationEnabled: boolean;
  worldIdVerified: boolean;
  status: "ACTIVE" | "INACTIVE";
  registeredAt: string;
  updatedAt: string;
}

export interface NodeRegistrationChallenge {
  challengeId: string;
  walletAddress: string;
  nodeId: string;
  selectedModelFamilies: Array<"gpt" | "gemini" | "claude" | "grok">;
  modelName: string;
  endpointUrl: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount: string;
  participationEnabled: boolean;
  worldIdVerified: boolean;
  challengeMessage: string;
  nonce: string;
  createdAt: string;
  expiresAt: string;
  status: "PENDING" | "USED" | "EXPIRED";
  signature?: string;
  usedAt?: string;
}

export interface NodeEndpointProbe {
  ok: boolean;
  checkedAt: string;
  latencyMs?: number;
  error?: string;
}

export interface PorProofSnapshot {
  marketId: number;
  epoch: number;
  assetsMicroUsdc: string;
  liabilitiesMicroUsdc: string;
  coverageBps: number;
  healthy: boolean;
  proofHash: string;
  proofUri?: string;
  txHash?: string;
  updatedAt: string;
}

export interface PorStatus {
  mode: "FILE" | "ONCHAIN";
  source: string;
  latest: PorProofSnapshot;
  history: PorProofSnapshot[];
}

export interface WorldIdProofInput {
  protocol_version?: string;
  nonce?: string;
  signal?: string;
  max_age?: number;
  metadata?: Record<string, unknown>;
  status?: string;
  created_at?: string;
  updated_at?: string;
  responses?: Array<Record<string, unknown>>;
  result?: Record<string, unknown>;
  action?: string;
  nullifier_hash?: string;
  verification_level?: string;
  // Keep forward compatibility with additional World ID 4.0 fields.
  [key: string]: unknown;
}

export interface WorldIdSession {
  token: string;
  walletAddress: string;
  nullifierHash: string;
  appId: string;
  action: string;
  verificationLevel?: string;
  profileId?: string;
  clientSource?: "miniapp" | "external" | "manual";
  issuedAt: string;
  expiresAt: string;
  source: "world_id_cloud";
}

interface ApiEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: string;
  detail?: string;
}

interface ApiRequestErrorOptions {
  status: number;
  errorCode?: string;
  detail?: string;
  traceId?: string;
}

export class ApiRequestError extends Error {
  readonly status: number;
  readonly errorCode?: string;
  readonly detail?: string;
  readonly traceId?: string;

  constructor(message: string, options: ApiRequestErrorOptions) {
    super(message);
    this.name = "ApiRequestError";
    this.status = options.status;
    this.errorCode = options.errorCode;
    this.detail = options.detail;
    this.traceId = options.traceId;
  }
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").trim().replace(/\/$/, "");
const API_TIMEOUT_MS = (() => {
  const raw = Number(import.meta.env.VITE_API_TIMEOUT_MS ?? "");
  if (!Number.isFinite(raw) || raw <= 0) {
    return 30_000;
  }
  return Math.floor(raw);
})();
const REQUIRE_WALLET_AUTH_SIGNATURE = (() => {
  const raw = String(import.meta.env.VITE_REQUIRE_WALLET_AUTH_SIGNATURE ?? "").trim();
  if (!raw) return true;
  const normalized = raw.toLowerCase();
  if (["false", "0", "no", "off"].includes(normalized)) return false;
  if (["true", "1", "yes", "on"].includes(normalized)) return true;
  return true;
})();

const WALLET_AUTH_SIGNATURE_HEADER = "x-wallet-auth-signature";
const WALLET_AUTH_TIMESTAMP_HEADER = "x-wallet-auth-timestamp";

function toLowerAddress(value: string): string {
  return value.trim().toLowerCase();
}

function isLikelyEvmAddress(value: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(value.trim());
}

function resolveAuthWalletAddress(walletAddress: string, account?: Account): string {
  const accountWalletRaw =
    typeof (account as { address?: unknown } | undefined)?.address === "string"
      ? ((account as { address?: string }).address ?? "")
      : "";
  if (isLikelyEvmAddress(accountWalletRaw)) {
    return toLowerAddress(accountWalletRaw);
  }
  const miniWalletRaw = MiniKit.user?.walletAddress;
  if (typeof miniWalletRaw === "string" && isLikelyEvmAddress(miniWalletRaw)) {
    return toLowerAddress(miniWalletRaw);
  }
  return toLowerAddress(walletAddress);
}

function buildWalletAuthMessage(input: {
  walletAddress: string;
  method: string;
  path: string;
  timestamp: string;
}): string {
  return [
    "CRE Wallet Auth v1",
    `wallet: ${toLowerAddress(input.walletAddress)}`,
    `method: ${input.method.toUpperCase()}`,
    `path: ${input.path}`,
    `timestamp: ${input.timestamp}`
  ].join("\n");
}

function toError(value: unknown): Error {
  if (value instanceof Error) {
    return value;
  }
  return new Error(String(value));
}

function shouldFallbackToMiniKitSign(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /Missing or invalid\.\s*request\(\)\s*chainId/i.test(message);
}

async function signWithMiniKitFallback(input: {
  message: string;
}): Promise<{ signature: string; signerAddress?: string }> {
  if (typeof window === "undefined") {
    throw new Error("minikit_sign_unavailable: no_window");
  }
  if (!MiniKit.isInstalled()) {
    throw new Error("minikit_sign_unavailable: not_installed");
  }

  const { finalPayload } = await MiniKit.commandsAsync.signMessage({
    message: input.message
  });
  const payload = finalPayload as Record<string, unknown> | null;
  if (!payload || payload.status !== "success") {
    const detail = payload && typeof payload.error_code === "string" ? payload.error_code : "unknown";
    throw new Error(`minikit_sign_failed: ${detail}`);
  }
  const signature = typeof payload.signature === "string" ? payload.signature.trim() : "";
  if (!signature) {
    throw new Error("minikit_sign_failed: empty_signature");
  }
  const signerAddressRaw = typeof payload.address === "string" ? payload.address.trim() : "";
  const signerAddress = isLikelyEvmAddress(signerAddressRaw) ? toLowerAddress(signerAddressRaw) : undefined;
  return {
    signature,
    signerAddress
  };
}

async function buildWalletAuthHeaders(input: {
  account: Account;
  walletAddress: string;
  method: string;
  path: string;
}): Promise<{ headers: Record<string, string>; walletAddress: string }> {
  const requestedWalletAddress = resolveAuthWalletAddress(input.walletAddress, input.account);
  if (!REQUIRE_WALLET_AUTH_SIGNATURE) {
    return {
      headers: {
        "x-wallet-address": requestedWalletAddress
      },
      walletAddress: requestedWalletAddress
    };
  }

  const timestamp = String(Date.now());
  let effectiveWalletAddress = requestedWalletAddress;
  let message = buildWalletAuthMessage({
    walletAddress: effectiveWalletAddress,
    method: input.method,
    path: input.path,
    timestamp
  });
  let signature: string;
  try {
    signature = await signMessage({
      account: input.account,
      message
    });
  } catch (error) {
    if (!shouldFallbackToMiniKitSign(error)) {
      throw toError(error);
    }
    const fallback = await signWithMiniKitFallback({ message });
    if (fallback.signerAddress && fallback.signerAddress !== effectiveWalletAddress) {
      effectiveWalletAddress = fallback.signerAddress;
      message = buildWalletAuthMessage({
        walletAddress: effectiveWalletAddress,
        method: input.method,
        path: input.path,
        timestamp
      });
      const corrected = await signWithMiniKitFallback({ message });
      signature = corrected.signature;
    } else {
      signature = fallback.signature;
    }
  }

  return {
    headers: {
      "x-wallet-address": effectiveWalletAddress,
      [WALLET_AUTH_SIGNATURE_HEADER]: signature,
      [WALLET_AUTH_TIMESTAMP_HEADER]: timestamp
    },
    walletAddress: effectiveWalletAddress
  };
}

function buildApiUrl(path: string): string {
  return API_BASE_URL ? `${API_BASE_URL}${path}` : path;
}

function appendWorldIdTokenHeader(headers: Record<string, string>, worldIdToken?: string): Record<string, string> {
  const token = worldIdToken?.trim();
  if (!token) {
    return headers;
  }
  return {
    ...headers,
    "x-world-id-token": token
  };
}

async function requestJson<T>(path: string, options?: RequestInit): Promise<T> {
  const requestUrl = buildApiUrl(path);
  const headers = new Headers(options?.headers);
  const hasBody = options?.body !== undefined && options?.body !== null;
  if (hasBody && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const timeoutController = new AbortController();
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  const externalSignal = options?.signal;
  const forwardAbort = () => timeoutController.abort();
  if (externalSignal) {
    if (externalSignal.aborted) {
      timeoutController.abort();
    } else {
      externalSignal.addEventListener("abort", forwardAbort, { once: true });
    }
  }
  timeoutId = setTimeout(() => {
    timeoutController.abort();
  }, API_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(requestUrl, {
      ...options,
      headers,
      signal: timeoutController.signal
    });
  } catch (error) {
    if (externalSignal) {
      externalSignal.removeEventListener("abort", forwardAbort);
    }
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    if (error instanceof Error && error.name === "AbortError") {
      throw new ApiRequestError(`network_timeout: request to '${requestUrl}' exceeded ${API_TIMEOUT_MS}ms`, {
        status: 0,
        errorCode: "network_timeout",
        detail: `timeout_ms=${API_TIMEOUT_MS}`
      });
    }
    const detail = error instanceof Error ? error.message : String(error);
    throw new ApiRequestError(`network_error: request to '${requestUrl}' failed (${detail})`, {
      status: 0,
      errorCode: "network_error",
      detail
    });
  }

  let payload: ApiEnvelope<T>;
  try {
    payload = (await response.json()) as ApiEnvelope<T>;
  } catch {
    if (externalSignal) {
      externalSignal.removeEventListener("abort", forwardAbort);
    }
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    throw new Error(`invalid_api_response: '${requestUrl}' returned non-JSON (HTTP ${response.status})`);
  }

  if (externalSignal) {
    externalSignal.removeEventListener("abort", forwardAbort);
  }
  if (timeoutId) {
    clearTimeout(timeoutId);
  }

  if (!response.ok || !payload.ok || !payload.data) {
    const payloadRecord = payload as unknown as Record<string, unknown>;
    const errorCode = typeof payloadRecord.error === "string" ? payloadRecord.error.trim() : "";
    const detail = typeof payloadRecord.detail === "string" ? payloadRecord.detail.trim() : "";
    const traceId = typeof payloadRecord.traceId === "string" ? payloadRecord.traceId.trim() : undefined;
    const message = errorCode ? (detail ? `${errorCode}: ${detail}` : errorCode) : `HTTP ${response.status}`;
    throw new ApiRequestError(message, {
      status: response.status,
      errorCode: errorCode || undefined,
      detail: detail || undefined,
      traceId
    });
  }

  return payload.data;
}

export interface RunVerificationResult extends RequestRecord {
  traceId?: string;
  workflow?: {
    traceId?: string;
    stepLogs?: WorkflowStepLog[];
    [key: string]: unknown;
  };
}

export async function createRequest(input: MarketRequestInput): Promise<RequestRecord> {
  return requestJson<RequestRecord>("/api/requests", {
    method: "POST",
    body: JSON.stringify(input)
  });
}

export async function createRequestForWallet(
  input: MarketRequestInput,
  walletAddress: string,
  worldIdToken?: string,
  account?: Account
): Promise<RequestRecord> {
  if (!account) {
    throw new Error("wallet_account_required");
  }
  const authWalletAddress = resolveAuthWalletAddress(walletAddress, account);
  const auth = await buildWalletAuthHeaders({
    account,
    walletAddress: authWalletAddress,
    method: "POST",
    path: "/api/requests"
  });
  const requestInput: MarketRequestInput = {
    ...input,
    submitterAddress: auth.walletAddress
  };
  return requestJson<RequestRecord>("/api/requests", {
    method: "POST",
    headers: appendWorldIdTokenHeader(
      {
        ...auth.headers,
        "payment-signature": auth.headers[WALLET_AUTH_SIGNATURE_HEADER] ?? ""
      },
      worldIdToken
    ),
    body: JSON.stringify(requestInput)
  });
}

export async function listRequests(): Promise<RequestRecord[]> {
  return requestJson<RequestRecord[]>("/api/requests");
}

export async function getRequest(requestId: string): Promise<RequestRecord> {
  return requestJson<RequestRecord>(`/api/requests/${encodeURIComponent(requestId)}`);
}

export async function runVerification(requestId: string): Promise<RequestRecord> {
  const data = await requestJson<{
    requestId: string;
    status: RequestRecord["status"];
    queuePriority?: number;
    queueDecision?: RequestRecord["queueDecision"];
    runAttempts: number;
    createdAt: string;
    updatedAt: string;
    input: MarketRequestInput;
    consensus?: RequestRecord["consensus"];
    onchainReceipt?: RequestRecord["onchainReceipt"];
    activeNodes?: RequestRecord["activeNodes"];
    paymentReceipt?: RequestRecord["paymentReceipt"];
    lastError?: string;
  }>(`/api/requests/${encodeURIComponent(requestId)}/run-verification`, {
    method: "POST"
  });

  return data;
}

export async function runVerificationForWallet(
  requestId: string,
  walletAddress: string,
  worldIdToken?: string,
  account?: Account
): Promise<RunVerificationResult> {
  if (!account) {
    throw new Error("wallet_account_required");
  }
  const authWalletAddress = resolveAuthWalletAddress(walletAddress, account);
  const path = `/api/requests/${encodeURIComponent(requestId)}/run-verification`;
  const auth = await buildWalletAuthHeaders({
    account,
    walletAddress: authWalletAddress,
    method: "POST",
    path
  });
  const data = await requestJson<RunVerificationResult>(path, {
    method: "POST",
    headers: appendWorldIdTokenHeader(
      {
        ...auth.headers,
        "payment-signature": auth.headers[WALLET_AUTH_SIGNATURE_HEADER] ?? ""
      },
      worldIdToken
    )
  });

  return data;
}

export async function getReport(requestId: string): Promise<{
  requestId: string;
  nodeReports: Array<{
    nodeId: NodeId;
    verdict: "PASS" | "FAIL";
    confidence: number;
    rationale: string;
    evidenceSummary: string;
    reportHash: string;
    generatedAt: string;
  }>;
  consensus?: RequestRecord["consensus"];
  onchainReceipt?: RequestRecord["onchainReceipt"];
  nodeFailures?: Array<{ nodeId: string; reason: string }>;
  generatedAt: string;
}> {
  return requestJson(`/api/requests/${encodeURIComponent(requestId)}/report`);
}

export async function getPorStatus(): Promise<PorStatus> {
  return requestJson<PorStatus>("/api/por/status");
}

export async function listNodes(): Promise<RegisteredNode[]> {
  return requestJson<RegisteredNode[]>("/api/nodes");
}

export async function registerNode(input: {
  walletAddress: string;
  selectedModelFamilies: Array<"gpt" | "gemini" | "claude" | "grok">;
  modelName: string;
  endpointUrl?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
  worldIdToken?: string;
  account?: Account;
}): Promise<{ node: RegisteredNode; paymentReceipt: VerificationPaymentReceipt }> {
  const account = input.account;
  if (!account) {
    throw new Error("wallet_account_required");
  }
  const authWalletAddress = resolveAuthWalletAddress(input.walletAddress, account);
  const auth = await buildWalletAuthHeaders({
    account,
    walletAddress: authWalletAddress,
    method: "POST",
    path: "/api/nodes/register"
  });
  const requestInput = {
    ...input,
    walletAddress: auth.walletAddress
  };
  return requestJson<{ node: RegisteredNode; paymentReceipt: VerificationPaymentReceipt }>("/api/nodes/register", {
    method: "POST",
    headers: appendWorldIdTokenHeader(
      {
        ...auth.headers,
        "payment-signature": auth.headers[WALLET_AUTH_SIGNATURE_HEADER] ?? ""
      },
      requestInput.worldIdToken
    ),
    body: JSON.stringify(requestInput)
  });
}

export async function requestNodeChallenge(input: {
  walletAddress: string;
  selectedModelFamilies: Array<"gpt" | "gemini" | "claude" | "grok">;
  modelName?: string;
  endpointUrl?: string;
  peerId?: string;
  tlsCertFingerprint?: string;
  stakeAmount?: string;
  participationEnabled?: boolean;
  worldIdToken?: string;
  account?: Account;
}): Promise<{ challenge: NodeRegistrationChallenge; paymentReceipt: VerificationPaymentReceipt }> {
  const account = input.account;
  if (!account) {
    throw new Error("wallet_account_required");
  }
  const authWalletAddress = resolveAuthWalletAddress(input.walletAddress, account);
  const auth = await buildWalletAuthHeaders({
    account,
    walletAddress: authWalletAddress,
    method: "POST",
    path: "/api/nodes/challenge"
  });
  const requestInput = {
    ...input,
    walletAddress: auth.walletAddress
  };
  return requestJson<{ challenge: NodeRegistrationChallenge; paymentReceipt: VerificationPaymentReceipt }>(
    "/api/nodes/challenge",
    {
      method: "POST",
      headers: appendWorldIdTokenHeader(
        {
          ...auth.headers,
          "payment-signature": auth.headers[WALLET_AUTH_SIGNATURE_HEADER] ?? ""
        },
        requestInput.worldIdToken
      ),
      body: JSON.stringify(requestInput)
    }
  );
}

export async function verifyWorldIdForWallet(input: {
  walletAddress: string;
  proof: WorldIdProofInput;
  appId?: string;
  action?: string;
  clientSource?: "miniapp" | "external" | "manual";
  account?: Account;
}): Promise<{ session: WorldIdSession }> {
  if (!input.account) {
    throw new Error("wallet_account_required");
  }
  const authWalletAddress = resolveAuthWalletAddress(input.walletAddress, input.account);
  const auth = await buildWalletAuthHeaders({
    account: input.account,
    walletAddress: authWalletAddress,
    method: "POST",
    path: "/api/world-id/verify"
  });
  return requestJson<{ session: WorldIdSession }>("/api/world-id/verify", {
    method: "POST",
    headers: auth.headers,
    body: JSON.stringify({
      walletAddress: auth.walletAddress,
      proof: input.proof,
      appId: input.appId,
      action: input.action,
      clientSource: input.clientSource
    })
  });
}

export async function activateNodeChallenge(input: {
  challengeId: string;
  walletAddress: string;
  signature: string;
  account?: Account;
}): Promise<{
  node: RegisteredNode;
  challenge: NodeRegistrationChallenge;
  endpointProbe: NodeEndpointProbe;
  lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
}> {
  const account = input.account;
  if (!account) {
    throw new Error("wallet_account_required");
  }
  const authWalletAddress = resolveAuthWalletAddress(input.walletAddress, account);
  const auth = await buildWalletAuthHeaders({
    account,
    walletAddress: authWalletAddress,
    method: "POST",
    path: "/api/nodes/activate"
  });
  const requestInput = {
    ...input,
    walletAddress: auth.walletAddress
  };
  return requestJson<{
    node: RegisteredNode;
    challenge: NodeRegistrationChallenge;
    endpointProbe: NodeEndpointProbe;
    lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
  }>("/api/nodes/activate", {
    method: "POST",
    headers: auth.headers,
    body: JSON.stringify(requestInput)
  });
}

export async function sendNodeHeartbeat(input: {
  walletAddress: string;
  endpointUrl: string;
  timestamp: number;
  signature: string;
  account?: Account;
}): Promise<{
  node: RegisteredNode;
  endpointProbe?: NodeEndpointProbe;
  heartbeatMessage: string;
  lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
}> {
  const account = input.account;
  if (!account) {
    throw new Error("wallet_account_required");
  }
  const authWalletAddress = resolveAuthWalletAddress(input.walletAddress, account);
  const auth = await buildWalletAuthHeaders({
    account,
    walletAddress: authWalletAddress,
    method: "POST",
    path: "/api/nodes/heartbeat"
  });
  const requestInput = {
    ...input,
    walletAddress: auth.walletAddress
  };
  return requestJson<{
    node: RegisteredNode;
    endpointProbe?: NodeEndpointProbe;
    heartbeatMessage: string;
    lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
  }>(
    "/api/nodes/heartbeat",
    {
      method: "POST",
      headers: auth.headers,
      body: JSON.stringify(requestInput)
    }
  );
}

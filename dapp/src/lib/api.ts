import { signMessage } from "thirdweb/utils";
import type { Account } from "thirdweb/wallets";
import { MiniKit } from "@worldcoin/minikit-js";

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
    vectorStatus: "QUEUED" | "VERIFYING" | "APPROVED_PENDING_OPEN" | "OPEN" | "CLOSED" | "REJECTED";
    attempts: number;
    updatedAt: string;
    lastError?: string;
  };
  queuePriority?: number;
  queueDecision?: {
    decision: "allow" | "reject_duplicate" | "reject_conflict";
    reason?: string;
    matchedRequestId?: string;
    similarity?: number;
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
  vectorOnchain?: {
    state: "PENDING" | "APPLYING" | "APPLIED" | "FAILED";
    vectorStatus: "QUEUED" | "VERIFYING" | "APPROVED_PENDING_OPEN" | "OPEN" | "CLOSED" | "REJECTED";
    queueDecision: "allow" | "reject_duplicate" | "reject_conflict";
    vectorStatusCode: number;
    queueDecisionCode: number;
    screeningHash: string;
    reasonHash: string;
    similarityBps: number;
    matchedRequestId?: string;
    evidenceUri: string;
    attempts: number;
    updatedAt: string;
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
    lastError?: string;
  };
  paymentReceipt?: {
    x402Enabled: boolean;
    required: boolean;
    paid: boolean;
    payerAddress: string;
    resource: string;
    price: string;
    paymentRef: string;
    settledAt: string;
  };
  lastError?: string;
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
  issues?: string[];
}

interface ApiRequestErrorOptions {
  status: number;
  errorCode?: string;
  detail?: string;
  traceId?: string;
  issues?: string[];
}

export class ApiRequestError extends Error {
  readonly status: number;
  readonly errorCode?: string;
  readonly detail?: string;
  readonly traceId?: string;
  readonly issues?: string[];

  constructor(message: string, options: ApiRequestErrorOptions) {
    super(message);
    this.name = "ApiRequestError";
    this.status = options.status;
    this.errorCode = options.errorCode;
    this.detail = options.detail;
    this.traceId = options.traceId;
    this.issues = options.issues;
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
const WALLET_AUTH_SIWE_MESSAGE_HEADER = "x-wallet-auth-siwe-message";
const WALLET_AUTH_SIWE_SIGNATURE_HEADER = "x-wallet-auth-siwe-signature";
const WALLET_AUTH_SIWE_ADDRESS_HEADER = "x-wallet-auth-siwe-address";
const WALLET_AUTH_SIWE_REQUEST_ID_HEADER = "x-wallet-auth-siwe-request-id";
const WALLET_AUTH_SIWE_VERSION_HEADER = "x-wallet-auth-siwe-version";

function toLowerAddress(value: string): string {
  return value.trim().toLowerCase();
}

function isLikelyEvmAddress(value: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(value.trim());
}

function extractEvmAddress(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  if (isLikelyEvmAddress(trimmed)) {
    return toLowerAddress(trimmed);
  }
  const match = trimmed.match(/0x[a-fA-F0-9]{40}/);
  if (match && isLikelyEvmAddress(match[0])) {
    return toLowerAddress(match[0]);
  }
  return undefined;
}

function normalizeHexSignature(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  return trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
}

function encodeBase64Utf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function resolveAuthWalletAddress(walletAddress: string, account?: Account): string {
  const accountWallet =
    typeof (account as { address?: unknown } | undefined)?.address === "string"
      ? ((account as { address?: string }).address ?? "")
      : "";
  const normalizedAccountWallet = extractEvmAddress(accountWallet);
  if (normalizedAccountWallet) {
    return normalizedAccountWallet;
  }

  if (MiniKit.isInstalled()) {
    const miniWallet = extractEvmAddress(MiniKit.user?.walletAddress);
    if (miniWallet) {
      return miniWallet;
    }
  }

  return extractEvmAddress(walletAddress) ?? toLowerAddress(walletAddress);
}

export function resolveWalletAddressForAuth(walletAddress: string, account?: Account): string {
  return resolveAuthWalletAddress(walletAddress, account);
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
  const signerAddress = extractEvmAddress(payload.address);
  return {
    signature: normalizeHexSignature(signature),
    signerAddress
  };
}

async function walletAuthWithMiniKit(input: {
  nonce: string;
}): Promise<{ message: string; signature: string; walletAddress?: string; version?: number }> {
  if (typeof window === "undefined") {
    throw new Error("minikit_wallet_auth_unavailable: no_window");
  }
  if (!MiniKit.isInstalled()) {
    throw new Error("minikit_wallet_auth_unavailable: not_installed");
  }

  const { finalPayload } = await MiniKit.commandsAsync.walletAuth({
    nonce: input.nonce,
    statement: "CRE Wallet Auth v1"
  });
  const payload = finalPayload as Record<string, unknown> | null;
  if (!payload || payload.status !== "success") {
    const detail = payload && typeof payload.error_code === "string" ? payload.error_code : "unknown";
    throw new Error(`minikit_wallet_auth_failed: ${detail}`);
  }

  const message = typeof payload.message === "string" ? payload.message : "";
  const signatureRaw = typeof payload.signature === "string" ? payload.signature : "";
  const signature = normalizeHexSignature(signatureRaw);
  if (!message.trim()) {
    throw new Error("minikit_wallet_auth_failed: empty_message");
  }
  if (!signature) {
    throw new Error("minikit_wallet_auth_failed: empty_signature");
  }

  return {
    message,
    signature,
    walletAddress: extractEvmAddress(payload.address),
    version: typeof payload.version === "number" && Number.isFinite(payload.version) ? payload.version : undefined
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

  const signWithMiniKitAndAlign = async (): Promise<string> => {
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
      return corrected.signature;
    }
    return fallback.signature;
  };

  let walletAuthFailedInMiniKit = false;
  if (MiniKit.isInstalled()) {
    try {
      const walletAuth = await walletAuthWithMiniKit({
        nonce: timestamp
      });
      if (walletAuth.walletAddress) {
        effectiveWalletAddress = walletAuth.walletAddress;
      }
      return {
        headers: {
          "x-wallet-address": effectiveWalletAddress,
          [WALLET_AUTH_TIMESTAMP_HEADER]: timestamp,
          [WALLET_AUTH_SIWE_MESSAGE_HEADER]: encodeBase64Utf8(walletAuth.message),
          [WALLET_AUTH_SIWE_SIGNATURE_HEADER]: walletAuth.signature,
          [WALLET_AUTH_SIWE_ADDRESS_HEADER]: walletAuth.walletAddress ?? effectiveWalletAddress,
          ...(walletAuth.version ? { [WALLET_AUTH_SIWE_VERSION_HEADER]: String(walletAuth.version) } : {})
        },
        walletAddress: effectiveWalletAddress
      };
    } catch {
      walletAuthFailedInMiniKit = true;
    }
  }

  let signature: string;
  if (walletAuthFailedInMiniKit) {
    signature = await signWithMiniKitAndAlign();
  } else {
    try {
      signature = await signMessage({
        account: input.account,
        message
      });
    } catch (error) {
      if (!shouldFallbackToMiniKitSign(error)) {
        throw toError(error);
      }
      signature = await signWithMiniKitAndAlign();
    }
  }
  signature = normalizeHexSignature(signature);

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
    const issues = Array.isArray(payloadRecord.issues)
      ? payloadRecord.issues.filter((item): item is string => typeof item === "string").map((item) => item.trim())
      : [];
    const normalizedDetail = detail || (issues.length > 0 ? issues.join(" | ") : "");
    const traceId = typeof payloadRecord.traceId === "string" ? payloadRecord.traceId.trim() : undefined;
    const message = errorCode ? (normalizedDetail ? `${errorCode}: ${normalizedDetail}` : errorCode) : `HTTP ${response.status}`;
    throw new ApiRequestError(message, {
      status: response.status,
      errorCode: errorCode || undefined,
      detail: normalizedDetail || undefined,
      traceId,
      issues: issues.length > 0 ? issues : undefined
    });
  }

  return payload.data;
}

export interface RunVerificationResult extends RequestRecord {
  traceId?: string;
  workflow?: {
    traceId?: string;
    [key: string]: unknown;
  };
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

  return requestJson<RunVerificationResult>(path, {
    method: "POST",
    headers: appendWorldIdTokenHeader(
      {
        ...auth.headers,
        "payment-signature": auth.headers[WALLET_AUTH_SIGNATURE_HEADER] ?? ""
      },
      worldIdToken
    )
  });
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

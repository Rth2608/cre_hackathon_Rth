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
    | "FAILED_NO_QUORUM"
    | "FAILED_ONCHAIN_SUBMISSION";
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
  };
  activeNodes?: RegisteredNode[];
  paymentReceipt?: VerificationPaymentReceipt;
  lastError?: string;
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
  mode: "MOCK" | "FILE" | "ONCHAIN";
  source: string;
  latest: PorProofSnapshot;
  history: PorProofSnapshot[];
}

export interface WorldIdProofInput {
  merkle_root?: string;
  nullifier_hash?: string;
  proof?: string | string[];
  verification_level?: string;
  signal_hash?: string;
  action?: string;
  responses?: Array<Record<string, unknown>>;
  protocol_version?: string;
}

export interface WorldIdSession {
  token: string;
  walletAddress: string;
  nullifierHash: string;
  appId: string;
  action: string;
  verificationLevel?: string;
  issuedAt: string;
  expiresAt: string;
  source: "world_id_cloud" | "assume";
}

interface ApiEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: string;
  detail?: string;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").trim().replace(/\/$/, "");

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
  const response = await fetch(buildApiUrl(path), {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {})
    }
  });

  const payload = (await response.json()) as ApiEnvelope<T>;

  if (!response.ok || !payload.ok || !payload.data) {
    const detail = typeof payload.detail === "string" ? payload.detail.trim() : "";
    const message = payload.error ? (detail ? `${payload.error}: ${detail}` : payload.error) : `HTTP ${response.status}`;
    throw new Error(message);
  }

  return payload.data;
}

export async function createRequest(input: MarketRequestInput): Promise<RequestRecord> {
  return requestJson<RequestRecord>("/api/requests", {
    method: "POST",
    body: JSON.stringify(input)
  });
}

export async function createRequestForWallet(input: MarketRequestInput, walletAddress: string): Promise<RequestRecord> {
  return requestJson<RequestRecord>("/api/requests", {
    method: "POST",
    headers: {
      "x-wallet-address": walletAddress,
      "payment-signature": `mock-${walletAddress}-${Date.now()}`
    },
    body: JSON.stringify(input)
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

export async function runVerificationForWallet(requestId: string, walletAddress: string): Promise<RequestRecord> {
  const data = await requestJson<{
    requestId: string;
    status: RequestRecord["status"];
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
    method: "POST",
    headers: {
      "x-wallet-address": walletAddress,
      "payment-signature": `mock-${walletAddress}-${Date.now()}`
    }
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
}): Promise<{ node: RegisteredNode; paymentReceipt: VerificationPaymentReceipt }> {
  return requestJson<{ node: RegisteredNode; paymentReceipt: VerificationPaymentReceipt }>("/api/nodes/register", {
    method: "POST",
    headers: appendWorldIdTokenHeader(
      {
        "x-wallet-address": input.walletAddress,
        "payment-signature": `mock-${input.walletAddress}-${Date.now()}`
      },
      input.worldIdToken
    ),
    body: JSON.stringify(input)
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
}): Promise<{ challenge: NodeRegistrationChallenge; paymentReceipt: VerificationPaymentReceipt }> {
  return requestJson<{ challenge: NodeRegistrationChallenge; paymentReceipt: VerificationPaymentReceipt }>(
    "/api/nodes/challenge",
    {
      method: "POST",
      headers: appendWorldIdTokenHeader(
        {
          "x-wallet-address": input.walletAddress,
          "payment-signature": `mock-${input.walletAddress}-${Date.now()}`
        },
        input.worldIdToken
      ),
      body: JSON.stringify(input)
    }
  );
}

export async function verifyWorldIdForWallet(input: {
  walletAddress: string;
  proof: WorldIdProofInput;
}): Promise<{ session: WorldIdSession }> {
  return requestJson<{ session: WorldIdSession }>("/api/world-id/verify", {
    method: "POST",
    headers: {
      "x-wallet-address": input.walletAddress
    },
    body: JSON.stringify(input)
  });
}

export async function activateNodeChallenge(input: {
  challengeId: string;
  walletAddress: string;
  signature: string;
}): Promise<{
  node: RegisteredNode;
  challenge: NodeRegistrationChallenge;
  endpointProbe: NodeEndpointProbe;
  lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
}> {
  return requestJson<{
    node: RegisteredNode;
    challenge: NodeRegistrationChallenge;
    endpointProbe: NodeEndpointProbe;
    lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
  }>("/api/nodes/activate", {
    method: "POST",
    headers: {
      "x-wallet-address": input.walletAddress
    },
    body: JSON.stringify(input)
  });
}

export async function sendNodeHeartbeat(input: {
  walletAddress: string;
  endpointUrl: string;
  timestamp: number;
  signature: string;
}): Promise<{
  node: RegisteredNode;
  endpointProbe?: NodeEndpointProbe;
  heartbeatMessage: string;
  lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
}> {
  return requestJson<{
    node: RegisteredNode;
    endpointProbe?: NodeEndpointProbe;
    heartbeatMessage: string;
    lifecycleOnchainReceipt?: RequestRecord["onchainReceipt"];
  }>(
    "/api/nodes/heartbeat",
    {
      method: "POST",
      headers: {
        "x-wallet-address": input.walletAddress
      },
      body: JSON.stringify(input)
    }
  );
}

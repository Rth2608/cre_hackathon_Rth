export type NodeId = string;
export type NodeVerdict = "PASS" | "FAIL";

export type RequestStatus =
  | "PENDING"
  | "RUNNING"
  | "FINALIZED"
  | "FAILED_NO_QUORUM"
  | "FAILED_ONCHAIN_SUBMISSION";

export interface MarketRequestInput {
  question: string;
  description: string;
  sourceUrls: string[];
  resolutionCriteria: string;
  submitterAddress: string;
}

export interface NodeReport {
  requestId: string;
  nodeId: NodeId;
  verdict: NodeVerdict;
  confidence: number;
  rationale: string;
  evidenceSummary: string;
  reportHash: string;
  generatedAt: string;
}

export interface ConsensusResult {
  requestId: string;
  responders: number;
  aggregateScore: number;
  aggregateScoreBps: number;
  finalVerdict: NodeVerdict;
  includedNodes: NodeId[];
  excludedNodes: NodeId[];
  finalReportHash: string;
  status: "OK" | "FAILED_NO_QUORUM";
}

export type CanonicalModelFamily = "gpt" | "gemini" | "claude" | "grok";

export interface ExecutionReceipt {
  requestId: string;
  round: number;
  operator: string;
  modelFamily: CanonicalModelFamily;
  modelNameHash: string;
  promptTemplateHash: string;
  canonicalPromptHash: string;
  paramsHash: string;
  responseHash: string;
  confidentialAttestationHash: string;
  providerRequestIdHash: string;
  startedAt: number;
  endedAt: number;
}

export interface SignedNodeReportPayload {
  requestId: string;
  round: number;
  operator: string;
  modelFamily: CanonicalModelFamily;
  modelNameHash: string;
  promptTemplateHash: string;
  canonicalPromptHash: string;
  paramsHash: string;
  responseHash: string;
  executionReceiptHash: string;
  verdict: NodeVerdict;
  confidenceBps: number;
  reportHash: string;
  timestamp: number;
}

export interface SignedNodeReport {
  payload: SignedNodeReportPayload;
  signature: string;
}

export interface ConsensusBundlePayload {
  requestId: string;
  requestHash: string;
  round: number;
  aggregateScoreBps: number;
  finalVerdict: boolean;
  responders: number;
  reportsMerkleRoot: string;
  attestationRootHash: string;
  promptTemplateHash: string;
  consensusTimestamp: number;
}

export interface ConsensusBundle {
  payload: ConsensusBundlePayload;
  bundleHash: string;
  leader: string;
  leaderSignature: string;
  includedOperators: string[];
  reportSignatures: string[];
}

export interface QuorumValidationResult {
  ok: boolean;
  quorumReached: boolean;
  responders: number;
  includedOperators: string[];
  validReports: SignedNodeReport[];
  invalidReports: Array<{ operator: string; reason: string }>;
}

export interface RegisteredNode {
  registrationId: string;
  walletAddress: string;
  nodeId: string;
  selectedModelFamilies: CanonicalModelFamily[];
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
  selectedModelFamilies: CanonicalModelFamily[];
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

export interface OnchainReceipt {
  txHash: string;
  blockNumber: number;
  gasUsed: string;
  chainId: number;
  explorerUrl?: string;
  simulated: boolean;
}

export interface StoredRequest {
  requestId: string;
  input: MarketRequestInput;
  createdAt: string;
  status: RequestStatus;
  runAttempts: number;
  nodeReports?: NodeReport[];
  signedNodeReports?: SignedNodeReport[];
  executionReceipts?: ExecutionReceipt[];
  consensus?: ConsensusResult;
  consensusBundle?: ConsensusBundle;
  quorumValidation?: QuorumValidationResult;
  onchainReceipt?: OnchainReceipt;
  activeNodes?: RegisteredNode[];
  paymentReceipt?: VerificationPaymentReceipt;
  lastError?: string;
  updatedAt: string;
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

export interface WorkflowRunResult {
  requestId: string;
  nodeReports: NodeReport[];
  signedNodeReports?: SignedNodeReport[];
  executionReceipts?: ExecutionReceipt[];
  consensus: ConsensusResult;
  consensusBundle?: ConsensusBundle;
  quorumValidation?: QuorumValidationResult;
  onchainReceipt?: OnchainReceipt;
  finalStatus: RequestStatus;
  stepLogs: WorkflowStepLog[];
  artifactDir: string;
  reportPath: string;
  externalCreOutput?: {
    command: string;
    stdout: string;
    stderr: string;
  };
}

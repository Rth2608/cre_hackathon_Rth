import { AbiCoder, Contract, JsonRpcProvider, Wallet, getAddress, id } from "ethers";
import type { ConsensusBundle, ConsensusResult, MarketRequestInput, OnchainReceipt } from "./types";
import { hashObject, readJsonFile, resolveProjectPath, writeJsonFileAtomic } from "./utils";
import { hashConsensusBundlePayload } from "./donSignatures";
import { DON_CONSENSUS_ABI, LEGACY_REGISTRY_ABI } from "./contractAbi";

interface SubmitOnchainParams {
  requestId: string;
  input: MarketRequestInput;
  consensus: ConsensusResult;
  reportUri: string;
  consensusBundle?: ConsensusBundle;
}

interface SubmitNodeLifecycleParams {
  nodeId: string;
  action: "ACTIVATED" | "HEARTBEAT";
  endpointUrl: string;
  payloadHash: string;
  payloadUri: string;
  lifecycleId?: string;
}

export interface SubmitVectorScreeningParams {
  requestId: string;
  vectorStatusCode: number;
  queueDecisionCode: number;
  similarityBps: number;
  matchedRequestId?: string;
  screeningHash: string;
  reasonHash: string;
  evidenceUri: string;
}

export interface SubmitPorProofParams {
  marketId: number;
  epoch: number;
  assetsMicroUsdc: string;
  liabilitiesMicroUsdc: string;
  proofHash: string;
  proofUri: string;
}

interface OnchainSubmissionDbSchema {
  receipts: Record<string, OnchainReceipt>;
}

const ONCHAIN_SUBMISSION_DB_PATH = resolveProjectPath("data", "onchain-submissions.json");
const DEFAULT_ONCHAIN_SUBMIT_MAX_ATTEMPTS = 3;
const DEFAULT_ONCHAIN_SUBMIT_RETRY_DELAY_MS = 1200;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function resolveOnchainSubmitMaxAttempts(): number {
  const raw = process.env.ONCHAIN_SUBMIT_MAX_ATTEMPTS?.trim();
  if (!raw) return DEFAULT_ONCHAIN_SUBMIT_MAX_ATTEMPTS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 8) {
    return DEFAULT_ONCHAIN_SUBMIT_MAX_ATTEMPTS;
  }
  return parsed;
}

function resolveOnchainSubmitRetryDelayMs(): number {
  const raw = process.env.ONCHAIN_SUBMIT_RETRY_DELAY_MS?.trim();
  if (!raw) return DEFAULT_ONCHAIN_SUBMIT_RETRY_DELAY_MS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 100 || parsed > 30_000) {
    return DEFAULT_ONCHAIN_SUBMIT_RETRY_DELAY_MS;
  }
  return parsed;
}

function isRetryableOnchainError(error: unknown): boolean {
  const message = stringifyError(error).toLowerCase();
  if (!message) {
    return false;
  }

  if (
    message.includes("execution reverted") ||
    message.includes("reverted") ||
    message.includes("invalid opcode") ||
    message.includes("insufficient funds")
  ) {
    return false;
  }

  return (
    message.includes("network") ||
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("socket") ||
    message.includes("econnreset") ||
    message.includes("econnrefused") ||
    message.includes("503") ||
    message.includes("502") ||
    message.includes("504") ||
    message.includes("rate limit") ||
    message.includes("temporarily unavailable") ||
    message.includes("load failed")
  );
}

async function waitMs(delayMs: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function readOnchainSubmissionDb(): Promise<OnchainSubmissionDbSchema> {
  const fallback: OnchainSubmissionDbSchema = { receipts: {} };
  const parsed = await readJsonFile<OnchainSubmissionDbSchema>(ONCHAIN_SUBMISSION_DB_PATH, fallback);
  if (!parsed || typeof parsed !== "object") {
    return fallback;
  }
  if (!parsed.receipts || typeof parsed.receipts !== "object") {
    return fallback;
  }
  return parsed;
}

async function writeOnchainSubmissionDb(db: OnchainSubmissionDbSchema): Promise<void> {
  await writeJsonFileAtomic(ONCHAIN_SUBMISSION_DB_PATH, db);
}

function buildConsensusIdempotencyKey(input: {
  contractAddress: string;
  chainIdFromEnv?: number;
  params: SubmitOnchainParams;
  useBundleFinalize: boolean;
}): string {
  return hashObject({
    scope: "submit_consensus_onchain",
    contractAddress: input.contractAddress.toLowerCase(),
    chainId: input.chainIdFromEnv ?? null,
    mode: input.useBundleFinalize ? "bundle" : "legacy",
    requestId: input.params.requestId.toLowerCase(),
    requestHash: buildRequestHash(input.params.input),
    reportUri: input.params.reportUri,
    consensus: {
      aggregateScoreBps: input.params.consensus.aggregateScoreBps,
      finalVerdict: input.params.consensus.finalVerdict,
      responders: input.params.consensus.responders,
      finalReportHash: input.params.consensus.finalReportHash
    },
    bundleHash: input.params.consensusBundle?.bundleHash ?? null
  });
}

function buildVectorScreeningIdempotencyKey(input: {
  contractAddress: string;
  chainIdFromEnv?: number;
  params: SubmitVectorScreeningParams;
}): string {
  return hashObject({
    scope: "submit_vector_screening_onchain",
    contractAddress: input.contractAddress.toLowerCase(),
    chainId: input.chainIdFromEnv ?? null,
    requestId: input.params.requestId.toLowerCase(),
    vectorStatusCode: input.params.vectorStatusCode,
    queueDecisionCode: input.params.queueDecisionCode,
    similarityBps: input.params.similarityBps,
    matchedRequestId: input.params.matchedRequestId?.toLowerCase() ?? null,
    screeningHash: input.params.screeningHash.toLowerCase(),
    reasonHash: input.params.reasonHash.toLowerCase(),
    evidenceUri: input.params.evidenceUri
  });
}

function toBytes32(hexOrString: string): string {
  const normalized = hexOrString.startsWith("0x") ? hexOrString : `0x${hexOrString}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    return normalized;
  }
  return id(hexOrString);
}

const ZERO_BYTES32 = `0x${"0".repeat(64)}`;

function buildSourcesHash(sourceUrls: string[]): string {
  const sorted = [...sourceUrls].sort((a, b) => a.localeCompare(b));
  return id(JSON.stringify(sorted));
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

function normalizeAddressList(addresses: string[], fieldName: string): string[] {
  return addresses.map((address, index) => {
    try {
      return getAddress(address);
    } catch {
      throw new Error(`Invalid address at ${fieldName}[${index}]`);
    }
  });
}

const DON_FINALIZE_INPUT_TUPLE =
  "tuple(bytes32 requestId,bytes32 requestHash,uint32 round,int16 aggregateScoreBps,bool verdict,uint8 responders,bytes32 reportsMerkleRoot,bytes32 attestationRootHash,bytes32 bundleHash,bytes32 promptTemplateHash,uint64 consensusTimestamp,address leader,address[] includedOperators,bytes[] reportSignatures,bytes leaderSignature,string reportUri)";

function encodeDonFinalizeInput(params: SubmitOnchainParams): string {
  if (!params.consensusBundle) {
    throw new Error("consensusBundle is required for DON finalize input");
  }
  const bundle = params.consensusBundle;
  const abiCoder = AbiCoder.defaultAbiCoder();
  return abiCoder.encode(
    [DON_FINALIZE_INPUT_TUPLE],
    [
      {
        requestId: toBytes32(params.requestId),
        requestHash: toBytes32(bundle.payload.requestHash || buildRequestHash(params.input)),
        round: bundle.payload.round,
        aggregateScoreBps: bundle.payload.aggregateScoreBps,
        verdict: bundle.payload.finalVerdict,
        responders: bundle.payload.responders,
        reportsMerkleRoot: toBytes32(bundle.payload.reportsMerkleRoot),
        attestationRootHash: toBytes32(bundle.payload.attestationRootHash),
        bundleHash: toBytes32(bundle.bundleHash || hashConsensusBundlePayload(bundle.payload)),
        promptTemplateHash: toBytes32(bundle.payload.promptTemplateHash),
        consensusTimestamp: bundle.payload.consensusTimestamp,
        leader: getAddress(bundle.leader),
        includedOperators: normalizeAddressList(bundle.includedOperators, "includedOperators"),
        reportSignatures: bundle.reportSignatures,
        leaderSignature: bundle.leaderSignature,
        reportUri: params.reportUri
      }
    ]
  );
}

function toNodeActionCode(action: SubmitNodeLifecycleParams["action"]): number {
  return action === "ACTIVATED" ? 1 : 2;
}

function resolveNodeLifecycleId(params: SubmitNodeLifecycleParams): string {
  if (params.lifecycleId && params.lifecycleId.trim().length > 0) {
    return toBytes32(params.lifecycleId.trim());
  }
  return toBytes32(
    hashObject({
      nodeId: params.nodeId.toLowerCase(),
      action: params.action,
      endpointUrl: params.endpointUrl,
      payloadHash: params.payloadHash,
      payloadUri: params.payloadUri
    })
  );
}

export async function submitConsensusOnchain(params: SubmitOnchainParams): Promise<OnchainReceipt> {
  const rpcUrl = requireEnv("RPC_URL");
  const contractAddress = getAddress(requireEnv("CONTRACT_ADDRESS"));
  const privateKey = requireEnv("COORDINATOR_PRIVATE_KEY");

  const chainIdFromEnv = process.env.CHAIN_ID ? Number.parseInt(process.env.CHAIN_ID, 10) : undefined;
  const provider = new JsonRpcProvider(rpcUrl, chainIdFromEnv);
  const wallet = new Wallet(privateKey, provider);

  const shouldUseBundleFinalize = process.env.USE_DON_BUNDLE_FINALIZE === "true";
  if (shouldUseBundleFinalize && params.consensusBundle === undefined) {
    throw new Error("USE_DON_BUNDLE_FINALIZE=true but consensusBundle is missing");
  }
  const useBundleFinalize = shouldUseBundleFinalize && params.consensusBundle !== undefined;
  const contract = new Contract(contractAddress, useBundleFinalize ? DON_CONSENSUS_ABI : LEGACY_REGISTRY_ABI, wallet);
  const idempotencyKey = buildConsensusIdempotencyKey({
    contractAddress,
    chainIdFromEnv,
    params,
    useBundleFinalize
  });
  const retryMaxAttempts = resolveOnchainSubmitMaxAttempts();
  const retryDelayMs = resolveOnchainSubmitRetryDelayMs();

  const db = await readOnchainSubmissionDb();
  const cachedReceipt = db.receipts[idempotencyKey];
  if (cachedReceipt) {
    return {
      ...cachedReceipt,
      idempotencyKey,
      idempotencyReused: true
    };
  }

  let lastError: unknown;
  for (let attempt = 1; attempt <= retryMaxAttempts; attempt += 1) {
    try {
      const tx = useBundleFinalize
        ? await contract.finalizeWithBundle(encodeDonFinalizeInput(params))
        : await contract.finalizeVerification(
            toBytes32(params.requestId),
            id(params.input.question),
            buildSourcesHash(params.input.sourceUrls),
            params.consensus.aggregateScoreBps,
            params.consensus.finalVerdict === "PASS",
            params.consensus.responders,
            toBytes32(params.consensus.finalReportHash),
            params.reportUri
          );

      const receipt = await tx.wait();
      const chainId = Number((await provider.getNetwork()).chainId);

      const onchainReceipt: OnchainReceipt = {
        txHash: tx.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        chainId,
        explorerUrl: process.env.TENDERLY_TX_BASE_URL
          ? `${process.env.TENDERLY_TX_BASE_URL.replace(/\/$/, "")}/${tx.hash}`
          : undefined,
        simulated: false,
        idempotencyKey,
        idempotencyReused: false,
        submissionAttempts: attempt
      };

      db.receipts[idempotencyKey] = onchainReceipt;
      await writeOnchainSubmissionDb(db);
      return onchainReceipt;
    } catch (error) {
      lastError = error;
      const retryable = isRetryableOnchainError(error);
      if (!retryable || attempt >= retryMaxAttempts) {
        break;
      }
      console.warn(
        `${new Date().toISOString()} onchain.submit.retry ${JSON.stringify({
          requestId: params.requestId,
          attempt,
          maxAttempts: retryMaxAttempts,
          retryDelayMs,
          error: stringifyError(error)
        })}`
      );
      await waitMs(retryDelayMs * attempt);
    }
  }

  throw new Error(
    `onchain_submit_failed: ${stringifyError(lastError)} (requestId=${params.requestId}, attempts=${retryMaxAttempts})`
  );
}

export async function submitVectorScreeningOnchain(params: SubmitVectorScreeningParams): Promise<OnchainReceipt> {
  if (!Number.isInteger(params.vectorStatusCode) || params.vectorStatusCode < 0 || params.vectorStatusCode > 255) {
    throw new Error("vectorStatusCode must be an integer between 0 and 255");
  }
  if (!Number.isInteger(params.queueDecisionCode) || params.queueDecisionCode < 0 || params.queueDecisionCode > 255) {
    throw new Error("queueDecisionCode must be an integer between 0 and 255");
  }
  if (!Number.isInteger(params.similarityBps) || params.similarityBps < 0 || params.similarityBps > 10000) {
    throw new Error("similarityBps must be an integer between 0 and 10000");
  }

  const rpcUrl = requireEnv("RPC_URL");
  const contractAddress = getAddress(requireEnv("CONTRACT_ADDRESS"));
  const privateKey = requireEnv("COORDINATOR_PRIVATE_KEY");

  const chainIdFromEnv = process.env.CHAIN_ID ? Number.parseInt(process.env.CHAIN_ID, 10) : undefined;
  const provider = new JsonRpcProvider(rpcUrl, chainIdFromEnv);
  const wallet = new Wallet(privateKey, provider);

  const useBundleFinalize = process.env.USE_DON_BUNDLE_FINALIZE === "true";
  const contract = new Contract(contractAddress, useBundleFinalize ? DON_CONSENSUS_ABI : LEGACY_REGISTRY_ABI, wallet);
  const idempotencyKey = buildVectorScreeningIdempotencyKey({
    contractAddress,
    chainIdFromEnv,
    params
  });
  const retryMaxAttempts = resolveOnchainSubmitMaxAttempts();
  const retryDelayMs = resolveOnchainSubmitRetryDelayMs();

  const db = await readOnchainSubmissionDb();
  const cachedReceipt = db.receipts[idempotencyKey];
  if (cachedReceipt) {
    return {
      ...cachedReceipt,
      idempotencyKey,
      idempotencyReused: true
    };
  }

  let lastError: unknown;
  for (let attempt = 1; attempt <= retryMaxAttempts; attempt += 1) {
    try {
      const tx = await contract.recordVectorScreening(
        toBytes32(params.requestId),
        params.vectorStatusCode,
        params.queueDecisionCode,
        params.similarityBps,
        params.matchedRequestId ? toBytes32(params.matchedRequestId) : ZERO_BYTES32,
        toBytes32(params.screeningHash),
        toBytes32(params.reasonHash),
        params.evidenceUri
      );
      const receipt = await tx.wait();
      const chainId = Number((await provider.getNetwork()).chainId);

      const onchainReceipt: OnchainReceipt = {
        txHash: tx.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        chainId,
        explorerUrl: process.env.TENDERLY_TX_BASE_URL
          ? `${process.env.TENDERLY_TX_BASE_URL.replace(/\/$/, "")}/${tx.hash}`
          : undefined,
        simulated: false,
        idempotencyKey,
        idempotencyReused: false,
        submissionAttempts: attempt
      };

      db.receipts[idempotencyKey] = onchainReceipt;
      await writeOnchainSubmissionDb(db);
      return onchainReceipt;
    } catch (error) {
      lastError = error;
      const retryable = isRetryableOnchainError(error);
      if (!retryable || attempt >= retryMaxAttempts) {
        break;
      }
      console.warn(
        `${new Date().toISOString()} onchain.vector_screening.retry ${JSON.stringify({
          requestId: params.requestId,
          attempt,
          maxAttempts: retryMaxAttempts,
          retryDelayMs,
          error: stringifyError(error)
        })}`
      );
      await waitMs(retryDelayMs * attempt);
    }
  }

  throw new Error(
    `onchain_vector_submit_failed: ${stringifyError(lastError)} (requestId=${params.requestId}, attempts=${retryMaxAttempts})`
  );
}

export async function submitNodeLifecycleOnchain(params: SubmitNodeLifecycleParams): Promise<OnchainReceipt> {
  const rpcUrl = requireEnv("RPC_URL");
  const contractAddress = requireEnv("CONTRACT_ADDRESS");
  const privateKey = requireEnv("COORDINATOR_PRIVATE_KEY");

  const chainIdFromEnv = process.env.CHAIN_ID ? Number.parseInt(process.env.CHAIN_ID, 10) : undefined;
  const provider = new JsonRpcProvider(rpcUrl, chainIdFromEnv);
  const wallet = new Wallet(privateKey, provider);

  const useBundleFinalize = process.env.USE_DON_BUNDLE_FINALIZE === "true";
  const contract = new Contract(contractAddress, useBundleFinalize ? DON_CONSENSUS_ABI : LEGACY_REGISTRY_ABI, wallet);

  const lifecycleId = resolveNodeLifecycleId(params);
  const tx = await contract.recordNodeLifecycle(
    lifecycleId,
    getAddress(params.nodeId),
    toNodeActionCode(params.action),
    id(params.endpointUrl),
    toBytes32(params.payloadHash),
    params.endpointUrl,
    params.payloadUri
  );

  const receipt = await tx.wait();
  const chainId = Number((await provider.getNetwork()).chainId);

  return {
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    gasUsed: receipt.gasUsed.toString(),
    chainId,
    explorerUrl: process.env.TENDERLY_TX_BASE_URL
      ? `${process.env.TENDERLY_TX_BASE_URL.replace(/\/$/, "")}/${tx.hash}`
      : undefined,
    simulated: false
  };
}

export async function submitPorProofOnchain(params: SubmitPorProofParams): Promise<OnchainReceipt> {
  const rpcUrl = requireEnv("RPC_URL");
  const contractAddress = requireEnv("CONTRACT_ADDRESS");
  const privateKey = requireEnv("COORDINATOR_PRIVATE_KEY");

  const chainIdFromEnv = process.env.CHAIN_ID ? Number.parseInt(process.env.CHAIN_ID, 10) : undefined;
  const provider = new JsonRpcProvider(rpcUrl, chainIdFromEnv);
  const wallet = new Wallet(privateKey, provider);

  const useBundleFinalize = process.env.USE_DON_BUNDLE_FINALIZE === "true";
  const contract = new Contract(contractAddress, useBundleFinalize ? DON_CONSENSUS_ABI : LEGACY_REGISTRY_ABI, wallet);

  const tx = await contract.recordPorProof(
    params.marketId,
    params.epoch,
    BigInt(params.assetsMicroUsdc),
    BigInt(params.liabilitiesMicroUsdc),
    toBytes32(params.proofHash),
    params.proofUri
  );

  const receipt = await tx.wait();
  const chainId = Number((await provider.getNetwork()).chainId);

  return {
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    gasUsed: receipt.gasUsed.toString(),
    chainId,
    explorerUrl: process.env.TENDERLY_TX_BASE_URL
      ? `${process.env.TENDERLY_TX_BASE_URL.replace(/\/$/, "")}/${tx.hash}`
      : undefined,
    simulated: false
  };
}

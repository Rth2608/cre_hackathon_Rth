import { AbiCoder, Contract, JsonRpcProvider, Wallet, getAddress, id } from "ethers";
import type { ConsensusBundle, ConsensusResult, MarketRequestInput, OnchainReceipt } from "./types";
import { hashObject } from "./utils";
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

export interface SubmitPorProofParams {
  marketId: number;
  epoch: number;
  assetsMicroUsdc: string;
  liabilitiesMicroUsdc: string;
  proofHash: string;
  proofUri: string;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

function toBytes32(hexOrString: string): string {
  const normalized = hexOrString.startsWith("0x") ? hexOrString : `0x${hexOrString}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    return normalized;
  }
  return id(hexOrString);
}

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

function buildMockReceipt(params: SubmitOnchainParams): OnchainReceipt {
  const txHash = toBytes32(
    hashObject({
      requestId: params.requestId,
      verdict: params.consensus.finalVerdict,
      aggregateScoreBps: params.consensus.aggregateScoreBps,
      reportUri: params.reportUri,
      bundleHash: params.consensusBundle?.bundleHash
    })
  );

  return {
    txHash,
    blockNumber: 0,
    gasUsed: "0",
    chainId: Number.parseInt(process.env.CHAIN_ID ?? "0", 10) || 0,
    explorerUrl: process.env.TENDERLY_TX_BASE_URL
      ? `${process.env.TENDERLY_TX_BASE_URL.replace(/\/$/, "")}/${txHash}`
      : undefined,
    simulated: true
  };
}

function buildMockNodeLifecycleReceipt(params: SubmitNodeLifecycleParams): OnchainReceipt {
  const txHash = toBytes32(
    hashObject({
      nodeId: params.nodeId.toLowerCase(),
      action: params.action,
      endpointUrl: params.endpointUrl,
      payloadHash: params.payloadHash,
      payloadUri: params.payloadUri,
      lifecycleId: params.lifecycleId ?? null
    })
  );

  return {
    txHash,
    blockNumber: 0,
    gasUsed: "0",
    chainId: Number.parseInt(process.env.CHAIN_ID ?? "0", 10) || 0,
    explorerUrl: process.env.TENDERLY_TX_BASE_URL
      ? `${process.env.TENDERLY_TX_BASE_URL.replace(/\/$/, "")}/${txHash}`
      : undefined,
    simulated: true
  };
}

function buildMockPorReceipt(params: SubmitPorProofParams): OnchainReceipt {
  const txHash = toBytes32(
    hashObject({
      marketId: params.marketId,
      epoch: params.epoch,
      assetsMicroUsdc: params.assetsMicroUsdc,
      liabilitiesMicroUsdc: params.liabilitiesMicroUsdc,
      proofHash: params.proofHash,
      proofUri: params.proofUri
    })
  );

  return {
    txHash,
    blockNumber: 0,
    gasUsed: "0",
    chainId: Number.parseInt(process.env.CHAIN_ID ?? "0", 10) || 0,
    explorerUrl: process.env.TENDERLY_TX_BASE_URL
      ? `${process.env.TENDERLY_TX_BASE_URL.replace(/\/$/, "")}/${txHash}`
      : undefined,
    simulated: true
  };
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
  if (process.env.USE_MOCK_ONCHAIN === "true") {
    return buildMockReceipt(params);
  }

  const rpcUrl = requireEnv("RPC_URL");
  const contractAddress = requireEnv("CONTRACT_ADDRESS");
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

export async function submitNodeLifecycleOnchain(params: SubmitNodeLifecycleParams): Promise<OnchainReceipt> {
  if (process.env.USE_MOCK_ONCHAIN === "true") {
    return buildMockNodeLifecycleReceipt(params);
  }

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
  if (process.env.USE_MOCK_ONCHAIN === "true") {
    return buildMockPorReceipt(params);
  }

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

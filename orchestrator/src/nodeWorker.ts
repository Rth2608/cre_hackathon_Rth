import { Wallet, getAddress, id } from "ethers";
import {
  DON_EIP712_TYPES,
  buildDonDomain,
  hashConsensusBundlePayload,
  toConsensusBundleTypedDataValue,
  toNodeReportTypedDataValue,
  toOperatorApprovalTypedDataValue
} from "./donSignatures";
import { runRuntimeNode, type RuntimeNode } from "./mockNodes";
import type {
  CanonicalModelFamily,
  ConsensusBundlePayload,
  ExecutionReceipt,
  MarketRequestInput,
  SignedNodeReportPayload
} from "./types";
import { hashObject, nowIso } from "./utils";

const PORT = Number.parseInt(process.env.PORT ?? "19000", 10);

const SUPPORTED_FAMILIES: CanonicalModelFamily[] = ["gpt", "gemini", "claude", "grok"];

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Cre-Request-Id"
    }
  });
}

function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Cre-Request-Id"
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

function resolveRuntimeNodeFromEnv(): RuntimeNode {
  const nodeId = (process.env.WORKER_NODE_ID ?? "").trim();
  const modelFamilyRaw = (process.env.WORKER_MODEL_FAMILY ?? "gpt").trim().toLowerCase();
  const modelName = (process.env.WORKER_MODEL_NAME ?? "worker-node").trim();
  const operatorAddress = (process.env.WORKER_OPERATOR_ADDRESS ?? "").trim();

  if (!nodeId) {
    throw new Error("WORKER_NODE_ID is required");
  }
  if (!SUPPORTED_FAMILIES.includes(modelFamilyRaw as CanonicalModelFamily)) {
    throw new Error(`Unsupported WORKER_MODEL_FAMILY: ${modelFamilyRaw}`);
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(operatorAddress)) {
    throw new Error("WORKER_OPERATOR_ADDRESS must be 0x-prefixed 20-byte address");
  }

  return {
    nodeId,
    modelFamily: modelFamilyRaw as CanonicalModelFamily,
    modelName: modelName || "worker-node",
    operatorAddress
  };
}

function normalizeHex32(value: string): string {
  const normalized = value.startsWith("0x") ? value : `0x${value}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    return normalized.toLowerCase();
  }
  return id(value);
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function resolveRound(): number {
  const parsed = Number.parseInt(process.env.DON_CONSENSUS_ROUND ?? "1", 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error("DON_CONSENSUS_ROUND must be a non-negative integer");
  }
  return parsed;
}

function resolvePromptTemplateHash(): string {
  const fromEnv = process.env.DON_PROMPT_TEMPLATE_HASH?.trim();
  if (!fromEnv) {
    return id("cre-prediction-market-prompt-template-v1");
  }
  return normalizeHex32(fromEnv);
}

function buildDonDomainFromEnv() {
  const chainId = Number.parseInt(process.env.CHAIN_ID ?? "1", 10);
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new Error("CHAIN_ID must be a positive integer");
  }

  const verifyingContract =
    process.env.DON_VERIFIER_CONTRACT?.trim() ||
    process.env.CONTRACT_ADDRESS?.trim() ||
    "0x0000000000000000000000000000000000000001";

  return buildDonDomain({
    name: process.env.DON_DOMAIN_NAME?.trim() || "CRE-DON-Consensus",
    version: process.env.DON_DOMAIN_VERSION?.trim() || "1",
    chainId,
    verifyingContract
  });
}

function buildCanonicalPromptHash(input: MarketRequestInput, promptTemplateHash: string): string {
  return id(
    JSON.stringify({
      promptTemplateHash,
      question: input.question,
      description: input.description,
      sourceUrls: [...input.sourceUrls].sort((a, b) => a.localeCompare(b)),
      resolutionCriteria: input.resolutionCriteria
    })
  );
}

function toConfidenceBps(confidence: number): number {
  if (!Number.isFinite(confidence)) return 0;
  const clamped = Math.max(0, Math.min(1, confidence));
  return Math.round(clamped * 10000);
}

function toUnixTimestampSeconds(value: string): number {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return Math.floor(Date.now() / 1000);
  }
  return Math.floor(parsed / 1000);
}

function buildExecutionReceipt(args: {
  requestId: string;
  round: number;
  runtimeNode: RuntimeNode;
  promptTemplateHash: string;
  canonicalPromptHash: string;
  report: {
    verdict: "PASS" | "FAIL";
    confidence: number;
    rationale: string;
    evidenceSummary: string;
    reportHash: string;
    generatedAt: string;
  };
}): ExecutionReceipt {
  const endedAt = toUnixTimestampSeconds(args.report.generatedAt);
  const startedAt = Math.max(0, endedAt - 1);

  return {
    requestId: args.requestId,
    round: args.round,
    operator: args.runtimeNode.operatorAddress,
    modelFamily: args.runtimeNode.modelFamily,
    modelNameHash: id(args.runtimeNode.modelName),
    promptTemplateHash: args.promptTemplateHash,
    canonicalPromptHash: args.canonicalPromptHash,
    paramsHash: id("temperature=0|max_tokens=256"),
    responseHash: id(
      JSON.stringify({
        verdict: args.report.verdict,
        confidence: args.report.confidence,
        rationale: args.report.rationale,
        evidenceSummary: args.report.evidenceSummary,
        reportHash: args.report.reportHash
      })
    ),
    confidentialAttestationHash: id(`attestation:${args.requestId}:${args.runtimeNode.nodeId}:${args.report.reportHash}`),
    providerRequestIdHash: id(`provider:${args.requestId}:${args.runtimeNode.nodeId}`),
    startedAt,
    endedAt
  };
}

function buildSignedNodeReportPayload(args: {
  requestId: string;
  round: number;
  runtimeNode: RuntimeNode;
  promptTemplateHash: string;
  canonicalPromptHash: string;
  executionReceiptHash: string;
  report: {
    verdict: "PASS" | "FAIL";
    confidence: number;
    reportHash: string;
    generatedAt: string;
  };
}): SignedNodeReportPayload {
  return {
    requestId: normalizeHex32(args.requestId),
    round: args.round,
    operator: normalizeAddress(args.runtimeNode.operatorAddress),
    modelFamily: args.runtimeNode.modelFamily,
    modelNameHash: id(args.runtimeNode.modelName),
    promptTemplateHash: args.promptTemplateHash,
    canonicalPromptHash: args.canonicalPromptHash,
    paramsHash: id("temperature=0|max_tokens=256"),
    responseHash: id(
      JSON.stringify({
        verdict: args.report.verdict,
        confidence: args.report.confidence,
        reportHash: args.report.reportHash
      })
    ),
    executionReceiptHash: args.executionReceiptHash,
    verdict: args.report.verdict,
    confidenceBps: toConfidenceBps(args.report.confidence),
    reportHash: normalizeHex32(args.report.reportHash),
    timestamp: toUnixTimestampSeconds(args.report.generatedAt)
  };
}

interface VerifyRequestBody {
  requestId: string;
  input: MarketRequestInput;
  node?: {
    nodeId?: string;
    modelFamily?: CanonicalModelFamily;
    modelName?: string;
    operatorAddress?: string;
  };
}

interface SignBundleApprovalBody {
  bundleHash: string;
  requestId: string;
  round: number;
  operator?: string;
}

interface SignConsensusBundleBody {
  payload: ConsensusBundlePayload;
  leader?: string;
}

let runtimeNode: RuntimeNode;
let signerWallet: Wallet;
let donDomain: ReturnType<typeof buildDonDomainFromEnv>;
let promptTemplateHash: string;
let round: number;

try {
  runtimeNode = resolveRuntimeNodeFromEnv();
  const privateKey = (process.env.WORKER_PRIVATE_KEY ?? "").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error("WORKER_PRIVATE_KEY must be a 0x-prefixed 32-byte hex key");
  }

  signerWallet = new Wallet(privateKey);
  if (signerWallet.address.toLowerCase() !== runtimeNode.operatorAddress.toLowerCase()) {
    throw new Error("WORKER_PRIVATE_KEY does not match WORKER_OPERATOR_ADDRESS");
  }

  donDomain = buildDonDomainFromEnv();
  promptTemplateHash = resolvePromptTemplateHash();
  round = resolveRound();
} catch (error) {
  const reason = error instanceof Error ? error.message : String(error);
  console.error(`[node-worker] invalid config: ${reason}`);
  process.exit(1);
}

async function handleVerify(req: Request): Promise<Response> {
  let body: VerifyRequestBody;
  try {
    body = await parseJsonBody<VerifyRequestBody>(req);
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

  if (!/^0x[0-9a-fA-F]{64}$/.test(body.requestId ?? "")) {
    return jsonResponse({ ok: false, error: "invalid_request_id" }, 400);
  }
  if (!body.input || typeof body.input !== "object") {
    return jsonResponse({ ok: false, error: "invalid_input" }, 400);
  }
  if (body.node?.nodeId && body.node.nodeId.toLowerCase() !== runtimeNode.nodeId.toLowerCase()) {
    return jsonResponse({ ok: false, error: "node_id_mismatch" }, 409);
  }
  if (body.node?.modelFamily && body.node.modelFamily !== runtimeNode.modelFamily) {
    return jsonResponse({ ok: false, error: "node_model_family_mismatch" }, 409);
  }
  if (body.node?.operatorAddress && normalizeAddress(body.node.operatorAddress) !== normalizeAddress(runtimeNode.operatorAddress)) {
    return jsonResponse({ ok: false, error: "node_operator_mismatch" }, 409);
  }

  try {
    const report = await runRuntimeNode(body.requestId, body.input, runtimeNode);
    const canonicalPromptHash = buildCanonicalPromptHash(body.input, promptTemplateHash);
    const executionReceipt = buildExecutionReceipt({
      requestId: normalizeHex32(body.requestId),
      round,
      runtimeNode,
      promptTemplateHash,
      canonicalPromptHash,
      report
    });
    const executionReceiptHash = normalizeHex32(hashObject(executionReceipt));
    const payload = buildSignedNodeReportPayload({
      requestId: body.requestId,
      round,
      runtimeNode,
      promptTemplateHash,
      canonicalPromptHash,
      executionReceiptHash,
      report
    });
    const signature = await signerWallet.signTypedData(donDomain, DON_EIP712_TYPES.NODE_REPORT_TYPES, toNodeReportTypedDataValue(payload));

    return jsonResponse({
      ok: true,
      data: {
        report,
        signedReport: {
          payload,
          signature
        },
        executionReceipt
      }
    });
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "worker_verification_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      500
    );
  }
}

async function handleSignBundleApproval(req: Request): Promise<Response> {
  let body: SignBundleApprovalBody;
  try {
    body = await parseJsonBody<SignBundleApprovalBody>(req);
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
    if (body.operator && normalizeAddress(body.operator) !== normalizeAddress(runtimeNode.operatorAddress)) {
      return jsonResponse({ ok: false, error: "operator_mismatch" }, 409);
    }

    const typedValue = toOperatorApprovalTypedDataValue({
      bundleHash: body.bundleHash,
      requestId: body.requestId,
      round: body.round
    });
    const signature = await signerWallet.signTypedData(donDomain, DON_EIP712_TYPES.OPERATOR_APPROVAL_TYPES, typedValue);

    return jsonResponse({
      ok: true,
      data: {
        operator: signerWallet.address,
        signature
      }
    });
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "sign_bundle_approval_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

async function handleSignConsensusBundle(req: Request): Promise<Response> {
  let body: SignConsensusBundleBody;
  try {
    body = await parseJsonBody<SignConsensusBundleBody>(req);
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
    if (body.leader && normalizeAddress(body.leader) !== normalizeAddress(runtimeNode.operatorAddress)) {
      return jsonResponse({ ok: false, error: "leader_mismatch" }, 409);
    }

    const payload = toConsensusBundleTypedDataValue(body.payload);
    const leaderSignature = await signerWallet.signTypedData(
      donDomain,
      DON_EIP712_TYPES.CONSENSUS_BUNDLE_TYPES,
      payload
    );

    return jsonResponse({
      ok: true,
      data: {
        leader: signerWallet.address,
        leaderSignature,
        bundleHash: hashConsensusBundlePayload(payload)
      }
    });
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "sign_consensus_bundle_failed",
        detail: error instanceof Error ? error.message : String(error)
      },
      400
    );
  }
}

async function router(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { pathname } = url;

  if (req.method === "OPTIONS") {
    return corsPreflight();
  }

  if (req.method === "GET" && pathname === "/healthz") {
    return jsonResponse({
      ok: true,
      service: "cre-node-worker",
      timestamp: nowIso(),
      runtimeNode,
      signer: signerWallet.address,
      domain: donDomain,
      routes: ["/verify", "/sign-bundle-approval", "/sign-consensus-bundle"]
    });
  }

  if (req.method === "POST" && pathname === "/verify") {
    return handleVerify(req);
  }

  if (req.method === "POST" && pathname === "/sign-bundle-approval") {
    return handleSignBundleApproval(req);
  }

  if (req.method === "POST" && pathname === "/sign-consensus-bundle") {
    return handleSignConsensusBundle(req);
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

Bun.serve({
  port: PORT,
  fetch: router
});

console.log(
  `[node-worker] listening on http://localhost:${PORT} | nodeId=${runtimeNode.nodeId} family=${runtimeNode.modelFamily} operator=${runtimeNode.operatorAddress}`
);

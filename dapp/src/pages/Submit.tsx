import { FormEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  MiniKit,
  ResponseEvent,
  type MiniKitInstallReturnType,
  type MiniAppVerifyActionPayload,
  type VerifyCommandInput,
  type VerifyCommandPayload,
  VerificationLevel as MiniKitVerificationLevel
} from "@worldcoin/minikit-js";
import { ConnectButton, useActiveAccount, useWalletBalance } from "thirdweb/react";
import AppNav from "../components/AppNav";
import {
  createRequestForWallet,
  verifyWorldIdForWallet,
  type MarketRequestInput,
  type WorldIdSession
} from "../lib/api";
import { formatKnownMiniKitMessage } from "../lib/miniKitErrors";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";
import { clearWorldIdSession, getWorldIdConfig } from "../lib/worldId";
import { getWorldAppRuntimeMode } from "../lib/worldAppRuntime";
import {
  getWorldChainVirtualConfig,
  worldChainSepoliaChain
} from "../lib/worldChain";

const defaultForm: MarketRequestInput = {
  question: "",
  description: "",
  sourceUrls: [],
  resolutionCriteria: "",
  submitterAddress: ""
};

interface SimilarRequestTemplate {
  id: string;
  label: string;
  input: Omit<MarketRequestInput, "submitterAddress">;
}

const similarityTemplates: SimilarRequestTemplate[] = [
  {
    id: "T1",
    label: "ETH 6K by 2027",
    input: {
      question: "Will ETH close above $6,000 at least once before January 1, 2027 UTC?",
      description:
        "Track whether ETH/USD records any daily close strictly above 6000 USD before 2027-01-01 00:00:00 UTC.",
      resolutionCriteria:
        "Resolve YES if Reuters or Bloomberg market coverage confirms an ETH/USD daily close greater than 6000 USD before the deadline. Otherwise resolve NO.",
      sourceUrls: [
        "https://www.reuters.com/",
        "https://www.bloomberg.com/"
      ]
    }
  },
  {
    id: "T2",
    label: "SOL Outage Q3 2026",
    input: {
      question: "Will Solana mainnet experience any outage longer than 120 minutes during Q3 2026?",
      description:
        "Monitor incidents between 2026-07-01 and 2026-09-30 UTC and check whether cumulative unavailability in a single event exceeds 120 minutes.",
      resolutionCriteria:
        "Resolve YES if Reuters or The Block publishes incident reporting showing a Solana outage duration over 120 minutes in the period. Otherwise resolve NO.",
      sourceUrls: [
        "https://www.reuters.com/",
        "https://www.theblock.co/"
      ]
    }
  },
  {
    id: "T3",
    label: "Fed Cut by Sep 2026",
    input: {
      question: "Will the U.S. Federal Reserve cut the target rate by at least 25 bps by September 30, 2026?",
      description:
        "Track FOMC decisions through 2026-09-30 UTC and evaluate whether cumulative easing from the starting target range reaches at least 25 basis points.",
      resolutionCriteria:
        "Resolve YES if Federal Reserve statements or Reuters/WSJ reporting confirm at least one 25 bps total cut by the deadline. Otherwise resolve NO.",
      sourceUrls: [
        "https://www.federalreserve.gov/",
        "https://www.reuters.com/",
        "https://www.wsj.com/"
      ]
    }
  },
  {
    id: "T4",
    label: "XRP ETF Approval",
    input: {
      question: "Will the SEC approve a U.S. spot XRP ETF before December 31, 2026 UTC?",
      description:
        "Track official SEC filings and major financial press reports for a spot XRP ETF approval decision before the 2026 year-end cutoff.",
      resolutionCriteria:
        "Resolve YES only if an SEC order or filing confirms approval of a U.S. spot XRP ETF by the deadline. Otherwise resolve NO.",
      sourceUrls: [
        "https://www.sec.gov/",
        "https://www.reuters.com/",
        "https://www.bloomberg.com/"
      ]
    }
  },
  {
    id: "T5",
    label: "BTC Dominance < 45%",
    input: {
      question: "Will Bitcoin market dominance fall below 45% on any day before October 1, 2026 UTC?",
      description:
        "Track daily BTC dominance percentage and check if at least one published daily reading is strictly below 45.0% before the deadline.",
      resolutionCriteria:
        "Resolve YES if CoinGecko or Reuters market data coverage shows BTC dominance under 45% before 2026-10-01 00:00:00 UTC. Otherwise resolve NO.",
      sourceUrls: [
        "https://www.coingecko.com/",
        "https://www.reuters.com/"
      ]
    }
  }
];

const MINI_VERIFY_TIMEOUT_MS = 20_000;
const SUBMIT_FLOW_TIMEOUT_MS = 120_000;
const MINI_INSTALL_RETRY_COUNT = 2;
const MINI_INSTALL_RETRY_DELAY_MS = 350;

function formatShortAddress(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length < 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-4)}`;
}

function normalizeWorldIdSignal(value: string): string {
  return value.trim().toLowerCase();
}

function looksLikeWorldIdV4ProofPayload(value: Record<string, unknown>): boolean {
  if (typeof value.protocol_version === "string") {
    return true;
  }
  if (typeof value.nonce === "string") {
    return true;
  }
  if (Array.isArray(value.responses)) {
    return true;
  }
  if (
    value.result &&
    typeof value.result === "object" &&
    !Array.isArray(value.result) &&
    (
      typeof (value.result as Record<string, unknown>).proof === "string" ||
      typeof (value.result as Record<string, unknown>).nullifier_hash === "string"
    )
  ) {
    return true;
  }
  return false;
}

function hasWorldIdProofMaterial(value: Record<string, unknown>): boolean {
  const topLevelProof = typeof value.proof === "string" && value.proof.trim().length > 0;
  const topLevelNullifier = typeof value.nullifier_hash === "string" && value.nullifier_hash.trim().length > 0;
  const topLevelMerkleRoot = typeof value.merkle_root === "string" && value.merkle_root.trim().length > 0;
  if (topLevelProof || topLevelNullifier || topLevelMerkleRoot) {
    return true;
  }

  const result = value.result;
  if (result && typeof result === "object" && !Array.isArray(result)) {
    const nested = result as Record<string, unknown>;
    const nestedProof = typeof nested.proof === "string" && nested.proof.trim().length > 0;
    const nestedNullifier = typeof nested.nullifier_hash === "string" && nested.nullifier_hash.trim().length > 0;
    const nestedMerkleRoot = typeof nested.merkle_root === "string" && nested.merkle_root.trim().length > 0;
    if (nestedProof || nestedNullifier || nestedMerkleRoot) {
      return true;
    }
  }

  if (Array.isArray(value.responses)) {
    for (const entry of value.responses) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        continue;
      }
      const response = entry as Record<string, unknown>;
      const responseProof = typeof response.proof === "string" && response.proof.trim().length > 0;
      const responseNullifier = typeof response.nullifier_hash === "string" && response.nullifier_hash.trim().length > 0;
      const responseNullifierLegacy = typeof response.nullifier === "string" && response.nullifier.trim().length > 0;
      const responseMerkleRoot = typeof response.merkle_root === "string" && response.merkle_root.trim().length > 0;
      if (responseProof || responseNullifier || responseNullifierLegacy || responseMerkleRoot) {
        return true;
      }
    }
  }

  return false;
}

function readLegacyMiniKitProofPayload(
  payload: MiniAppVerifyActionPayload
): { merkleRoot: string; nullifierHash: string; proof: string; verificationLevel?: string } | null {
  if (payload.status !== "success") {
    return null;
  }

  const rawPayload = payload as unknown as Record<string, unknown>;
  const readCandidate = (
    candidate: Record<string, unknown>
  ): { merkleRoot: string; nullifierHash: string; proof: string; verificationLevel?: string } | null => {
    const proof = typeof candidate.proof === "string" ? candidate.proof.trim() : "";
    const nullifierHash = typeof candidate.nullifier_hash === "string" ? candidate.nullifier_hash.trim() : "";
    const merkleRoot = typeof candidate.merkle_root === "string" ? candidate.merkle_root.trim() : "";
    const verificationLevel =
      typeof candidate.verification_level === "string" ? candidate.verification_level.trim() : undefined;

    if (!proof || !nullifierHash || !merkleRoot) {
      return null;
    }

    return {
      merkleRoot,
      nullifierHash,
      proof,
      verificationLevel
    };
  };

  const topLevel = readCandidate(rawPayload);
  if (topLevel) {
    return topLevel;
  }

  if (Array.isArray(rawPayload.verifications)) {
    for (const entry of rawPayload.verifications) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        continue;
      }
      const nested = readCandidate(entry as Record<string, unknown>);
      if (nested) {
        return nested;
      }
    }
  }

  return null;
}

function resolveWorldIdCredentialIdentifier(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (
    normalized === "orb" ||
    normalized === "secure_document" ||
    normalized === "document" ||
    normalized === "device" ||
    normalized === "face"
  ) {
    return normalized;
  }
  return undefined;
}

function buildWorldProofFromMiniKit(
  payload: MiniAppVerifyActionPayload,
  input: { action: string; signal: string; signalHashHint?: string; nonceHint?: string }
): Record<string, unknown> | null {
  if (payload.status !== "success") {
    return null;
  }

  const rawPayload = payload as unknown as Record<string, unknown>;
  if (looksLikeWorldIdV4ProofPayload(rawPayload) && hasWorldIdProofMaterial(rawPayload)) {
    return rawPayload;
  }

  const legacyPayload = readLegacyMiniKitProofPayload(payload);
  if (!legacyPayload) {
    return null;
  }

  const nonceCandidate = input.nonceHint?.trim();
  const nonce = nonceCandidate && nonceCandidate.length > 0 ? nonceCandidate : `mini-${Date.now()}-${Math.random()}`;
  const identifier = resolveWorldIdCredentialIdentifier(legacyPayload.verificationLevel);
  const signalHashCandidate = input.signalHashHint?.trim();
  const signalHash = signalHashCandidate && signalHashCandidate.length > 0 ? signalHashCandidate : undefined;

  return {
    protocol_version: "3.0",
    nonce,
    action: input.action,
    signal: input.signal,
    responses: [
      {
        identifier,
        nullifier: legacyPayload.nullifierHash,
        nullifier_hash: legacyPayload.nullifierHash,
        merkle_root: legacyPayload.merkleRoot,
        proof: legacyPayload.proof,
        verification_level: legacyPayload.verificationLevel,
        signal_hash: signalHash
      }
    ]
  };
}

function getWorldIdErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/^network_timeout:/i.test(message)) {
    return "Network timeout while contacting backend. Please retry.";
  }
  if (message.includes("A verify request is already in flight")) {
    return "A World ID verification is already in progress. Finish or close the current World App prompt, then retry.";
  }
  const installErrorMatch = message.match(/^minikit_unavailable:\s*([a-z0-9_]+)$/i);
  if (installErrorMatch) {
    return `MiniKit is unavailable (${installErrorMatch[1]}). Open this page inside World App Mini App and retry.`;
  }
  const commandUnavailableMatch = message.match(/^minikit_command_unavailable:\s*([a-z0-9_-]+)$/i);
  if (commandUnavailableMatch) {
    return `MiniKit command '${commandUnavailableMatch[1]}' is unavailable in this World App runtime. Update World App and reopen this Mini App.`;
  }
  const verifyTimeoutMatch = message.match(/^world_id_verify_timeout:\s*(.+)$/i);
  if (verifyTimeoutMatch) {
    return `World App did not return a verify result in time. ${verifyTimeoutMatch[1]}`;
  }
  const v4PayloadRequiredMatch = message.match(/^world_id_v4_payload_required:\s*(.+)$/i);
  if (v4PayloadRequiredMatch) {
    return `World ID 4.0 payload is required. Received legacy payload (${v4PayloadRequiredMatch[1]}). Use a World ID 4.0-compatible flow.`;
  }
  if (message === "miniapp_runtime_required") {
    return "Mini App runtime is required. Open this URL from World App Mini Apps.";
  }
  const verificationRejectedMatch = message.match(/^world_id_verify_failed:\s*([a-z0-9_]+)$/i);
  if (verificationRejectedMatch) {
    return `World ID verification failed (${verificationRejectedMatch[1]}).`;
  }
  const normalized = formatKnownMiniKitMessage(message);
  if (normalized) {
    return normalized;
  }
  return message;
}

function getMiniVerifyErrorCode(payload: MiniAppVerifyActionPayload): string | null {
  if (payload.status !== "error") {
    return null;
  }
  const rawPayload = payload as unknown as Record<string, unknown>;
  const rawCode =
    (typeof rawPayload.error_code === "string" ? rawPayload.error_code : undefined) ??
    (typeof rawPayload.errorCode === "string" ? rawPayload.errorCode : undefined);
  if (!rawCode) {
    return null;
  }
  const normalized = rawCode.trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
}

function isMiniKitInstallUsable(installResult: MiniKitInstallReturnType): boolean {
  if (installResult.success) {
    return true;
  }
  return installResult.errorCode === "already_installed";
}

function isRetryableMiniKitInstallError(errorCode: string | undefined): boolean {
  return errorCode === "app_out_of_date";
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function installMiniKitWithAppId(appId: string): MiniKitInstallReturnType {
  const installResult = MiniKit.install(appId);
  if (isMiniKitInstallUsable(installResult) && appId.trim()) {
    const normalizedAppId = appId.trim();
    if (MiniKit.appId !== normalizedAppId) {
      MiniKit.appId = normalizedAppId;
    }
  }
  return installResult;
}

function readMiniKitRuntimeAppId(): string {
  return (MiniKit.appId ?? "").trim();
}

function installMiniKitRawDebugHook(onTrigger: (event: ResponseEvent, payload: unknown) => void): void {
  if (typeof window === "undefined") {
    return;
  }
  const debugWindow = window as Window & {
    __creMiniKitRawTriggerDebugInstalled?: boolean;
    __creMiniKitRawTriggerDebugHandler?: (event: ResponseEvent, payload: unknown) => void;
  };
  debugWindow.__creMiniKitRawTriggerDebugHandler = onTrigger;
  if (debugWindow.__creMiniKitRawTriggerDebugInstalled) {
    return;
  }

  const originalTrigger = MiniKit.trigger.bind(MiniKit);
  const miniKitMutable = MiniKit as unknown as {
    trigger: (event: ResponseEvent, payload: unknown) => void;
  };
  miniKitMutable.trigger = (event: ResponseEvent, payload: unknown) => {
    const currentHandler = debugWindow.__creMiniKitRawTriggerDebugHandler;
    if (currentHandler) {
      try {
        currentHandler(event, payload);
      } catch {
        // Ignore debug hook errors.
      }
    }
    originalTrigger(event, payload);
  };
  debugWindow.__creMiniKitRawTriggerDebugInstalled = true;
}

interface MiniVerifyResult {
  commandPayload: VerifyCommandPayload | null;
  finalPayload: MiniAppVerifyActionPayload;
}

function runMiniVerifyCommand(payload: VerifyCommandInput): Promise<MiniVerifyResult> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("minikit_unavailable: outside_of_worldapp"));
  }

  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      reject(new Error("world_id_verify_timeout: no verify response returned from World App."));
    }, MINI_VERIFY_TIMEOUT_MS);
    try {
      MiniKit.commandsAsync
        .verify(payload)
        .then(({ commandPayload, finalPayload }) => {
          window.clearTimeout(timeout);
          resolve({ commandPayload, finalPayload });
        })
        .catch((error) => {
          window.clearTimeout(timeout);
          reject(error);
        });
    } catch (error) {
      window.clearTimeout(timeout);
      reject(error);
    }
  });
}

function toMiniVerifyPayload(value: unknown): MiniAppVerifyActionPayload | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const status = (value as Record<string, unknown>).status;
  if (status !== "success" && status !== "error") {
    return null;
  }
  return value as MiniAppVerifyActionPayload;
}

async function ensureMiniKitInstalled(appId: string): Promise<void> {
  let lastErrorCode = "unknown";
  for (let attempt = 0; attempt <= MINI_INSTALL_RETRY_COUNT; attempt += 1) {
    const installResult = installMiniKitWithAppId(appId);
    if (isMiniKitInstallUsable(installResult)) {
      return;
    }

    lastErrorCode = installResult.success ? "unknown" : installResult.errorCode ?? "unknown";
    const canRetry = isRetryableMiniKitInstallError(installResult.success ? undefined : installResult.errorCode);
    if (!canRetry || attempt === MINI_INSTALL_RETRY_COUNT) {
      break;
    }
    await wait(MINI_INSTALL_RETRY_DELAY_MS * (attempt + 1));
  }

  throw new Error(`minikit_unavailable: ${lastErrorCode}`);
}

export default function SubmitPage() {
  const navigate = useNavigate();
  const activeAccount = useActiveAccount();
  const walletAddress = activeAccount?.address ?? "";
  const worldIdSignal = normalizeWorldIdSignal(walletAddress);
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();
  const { data: walletBalance, isLoading: walletBalanceLoading, isError: walletBalanceError } = useWalletBalance({
    chain: worldChainSepoliaChain,
    address: walletConnected ? walletAddress : undefined,
    client: thirdwebClient
  });
  const worldIdConfig = getWorldIdConfig();
  const miniWorldIdConfigured = worldIdConfig.mini.configured;
  const worldChainVirtualConfig = getWorldChainVirtualConfig();
  const worldAppMiniRuntime = getWorldAppRuntimeMode() === "miniapp";

  const [form, setForm] = useState(defaultForm);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const miniVerifyRawPayloadsRef = useRef<MiniAppVerifyActionPayload[]>([]);

  useEffect(() => {
    setForm((prev) => {
      if (prev.submitterAddress.toLowerCase() === walletAddress.toLowerCase()) {
        return prev;
      }

      return {
        ...prev,
        submitterAddress: walletAddress
      };
    });
  }, [walletAddress]);

  useEffect(() => {
    installMiniKitRawDebugHook((event, payload) => {
      if (event !== "miniapp-verify-action") {
        return;
      }
      const parsedPayload = toMiniVerifyPayload(payload);
      if (!parsedPayload) {
        return;
      }
      miniVerifyRawPayloadsRef.current = [...miniVerifyRawPayloadsRef.current.slice(-9), parsedPayload];
    });
  }, []);

  useEffect(() => {
    if (!walletConnected || !worldAppMiniRuntime || !worldIdConfig.mini.configured) {
      return;
    }
    try {
      installMiniKitWithAppId(worldIdConfig.mini.appId);
    } catch {
      // handled on submit via retry path
    }
  }, [walletConnected, worldAppMiniRuntime, worldIdConfig.mini.configured, worldIdConfig.mini.appId]);

  const nativeBalanceText =
    walletBalanceLoading
      ? "Loading..."
      : walletBalance
        ? `${walletBalance.displayValue} ${walletBalance.symbol}`
        : walletBalanceError
          ? "Failed to load"
          : "-";

  const applySimilarityTemplate = (template: SimilarRequestTemplate) => {
    setForm((prev) => ({
      ...prev,
      question: template.input.question,
      description: template.input.description,
      resolutionCriteria: template.input.resolutionCriteria,
      sourceUrls: [...template.input.sourceUrls],
      submitterAddress: walletAddress || prev.submitterAddress
    }));
    setError(null);
  };

  const verifyWorldIdForSubmitMiniApp = async (): Promise<WorldIdSession> => {
    if (!activeAccount) {
      throw new Error("wallet_account_required");
    }
    if (!worldIdConfig.mini.configured) {
      throw new Error("world_id_not_configured");
    }

    miniVerifyRawPayloadsRef.current = [];
    const requestedVerificationLevel: [MiniKitVerificationLevel, MiniKitVerificationLevel] = [
      MiniKitVerificationLevel.Orb,
      MiniKitVerificationLevel.Device
    ];

    await ensureMiniKitInstalled(worldIdConfig.mini.appId);

    const runtimeMiniAppId = readMiniKitRuntimeAppId() || worldIdConfig.mini.appId;
    const { commandPayload, finalPayload } = await runMiniVerifyCommand({
      action: worldIdConfig.mini.action,
      signal: worldIdSignal,
      verification_level: requestedVerificationLevel
    });
    if (!commandPayload) {
      throw new Error("minikit_command_unavailable: verify");
    }

    const miniVerifyErrorCode = getMiniVerifyErrorCode(finalPayload);
    if (miniVerifyErrorCode) {
      throw new Error(`world_id_verify_failed: ${miniVerifyErrorCode}`);
    }

    const proofBuildInput = {
      action: worldIdConfig.mini.action,
      signal: worldIdSignal,
      signalHashHint: typeof commandPayload.signal === "string" ? commandPayload.signal : undefined,
      nonceHint: typeof commandPayload.timestamp === "string" ? commandPayload.timestamp : undefined
    };
    const proofCandidates: Array<{ source: string; payload: MiniAppVerifyActionPayload }> = [
      ...miniVerifyRawPayloadsRef.current.slice().reverse().map((payload, index) => ({
        source: `raw_event_${index + 1}`,
        payload
      })),
      { source: "final_payload", payload: finalPayload }
    ];

    let proof: Record<string, unknown> | null = null;
    for (const candidate of proofCandidates) {
      const builtProof = buildWorldProofFromMiniKit(candidate.payload, proofBuildInput);
      if (!builtProof) {
        continue;
      }
      proof = builtProof;
      break;
    }
    if (!proof) {
      throw new Error("world_id_v4_payload_required: miniapp_returned_legacy_payload");
    }

    const result = await verifyWorldIdForWallet({
      walletAddress,
      proof,
      appId: runtimeMiniAppId,
      action: worldIdConfig.mini.action,
      clientSource: "miniapp",
      account: activeAccount
    });
    return result.session;
  };

  const verifyWorldIdForSubmit = async (): Promise<WorldIdSession> => verifyWorldIdForSubmitMiniApp();

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const submitTimeoutId = window.setTimeout(() => {
      setSubmitting(false);
      setError((prev) => prev ?? "submit_timeout: verification or submission did not complete in time. Retry.");
    }, SUBMIT_FLOW_TIMEOUT_MS);

    if (!thirdwebConfigured) {
      setError("Missing VITE_THIRDWEB_CLIENT_ID. Configure dapp/.env and restart the dev server.");
      window.clearTimeout(submitTimeoutId);
      setSubmitting(false);
      return;
    }

    if (!walletConnected || !activeAccount) {
      setError("Connect wallet before creating a request.");
      window.clearTimeout(submitTimeoutId);
      setSubmitting(false);
      return;
    }

    if (!worldAppMiniRuntime) {
      setError("Mini App runtime is required. Open this app from World App Mini Apps.");
      window.clearTimeout(submitTimeoutId);
      setSubmitting(false);
      return;
    }

    if (!miniWorldIdConfigured) {
      setError("World ID is not configured. Set VITE_WORLD_ID_MINI_APP_ID / VITE_WORLD_ID_MINI_ACTION.");
      window.clearTimeout(submitTimeoutId);
      setSubmitting(false);
      return;
    }

    try {
      clearWorldIdSession(walletAddress);

      const session = await verifyWorldIdForSubmit();

      const created = await createRequestForWallet(form, walletAddress, session.token, activeAccount);
      setRequestId(created.requestId);
      clearWorldIdSession(walletAddress);
      navigate(`/result/${encodeURIComponent(created.requestId)}`);
    } catch (err) {
      const message = getWorldIdErrorMessage(err);
      if (
        message.includes("world_id_token_") ||
        message.includes("world_id_verify_failed")
      ) {
        clearWorldIdSession(walletAddress);
      }
      setError(message);
    } finally {
      window.clearTimeout(submitTimeoutId);
      setSubmitting(false);
    }
  };

  return (
    <div className="page-shell">
      <main className="panel">
        <AppNav current="submit" />
        <header className="hero">
          <p className="eyebrow">CRE + DON Consensus</p>
          <h1>Submit Market Verification Request</h1>
          <p>
            Enter market question, evidence URLs, and resolver criteria. Submit first runs World ID verification, then
            queues the request for Verify-stage screening and execution.
          </p>
          <div className="hero-chips">
            <span className="chip">4 DON Nodes</span>
            <span className="chip">Weighted Consensus</span>
            <span className="chip">Tenderly Finalization</span>
            <span className="chip">Mini App Only</span>
          </div>
          <p className="config-warning runtime-note">
            {worldAppMiniRuntime
              ? "In World App: Submit triggers in-app World ID verification before queueing."
              : "In Web: Submit is disabled. Open this app from World App Mini Apps."}
          </p>
          <div className="wallet-row">
            {thirdwebConfigured ? (
              <ConnectButton
                client={thirdwebClient}
                chains={[worldChainSepoliaChain]}
                connectButton={{ className: "wallet-connect-btn", label: "Connect Wallet" }}
              />
            ) : (
              <p className="config-warning">
                Missing <code>VITE_THIRDWEB_CLIENT_ID</code>. Wallet login is disabled until configured.
              </p>
            )}
            {walletConnected && <p className="wallet-info mono">Connected: {walletAddress}</p>}
            {walletConnected && (
              <p className="wallet-info mono">
                Virtual Balance ({worldChainVirtualConfig.chainName}): {nativeBalanceText}
              </p>
            )}
          </div>
        </header>

        <section className="status-card">
          <h2>Quick Similarity Templates</h2>
          <p>Choose one template to auto-fill. These five templates are intentionally diverse to reduce duplicate similarity hits.</p>
          <div className="action-row">
            {similarityTemplates.map((template) => (
              <button
                key={template.id}
                type="button"
                className="secondary"
                onClick={() => applySimilarityTemplate(template)}
                disabled={submitting}
              >
                Fill {template.id}: {template.label}
              </button>
            ))}
          </div>
        </section>

        <form onSubmit={onSubmit} className="form-grid">
          <label>
            Question
            <input
              value={form.question}
              onChange={(event) => setForm((prev) => ({ ...prev, question: event.target.value }))}
              required
            />
          </label>

          <label>
            Description
            <textarea
              value={form.description}
              onChange={(event) => setForm((prev) => ({ ...prev, description: event.target.value }))}
              rows={3}
              required
            />
          </label>

          <label>
            Resolution Criteria
            <textarea
              value={form.resolutionCriteria}
              onChange={(event) => setForm((prev) => ({ ...prev, resolutionCriteria: event.target.value }))}
              rows={3}
              required
            />
          </label>

          <label>
            Source URLs (one per line)
            <textarea
              value={form.sourceUrls.join("\n")}
              onChange={(event) =>
                setForm((prev) => ({
                  ...prev,
                  sourceUrls: event.target.value
                    .split("\n")
                    .map((value) => value.trim())
                    .filter(Boolean)
                }))
              }
              rows={4}
              required
            />
          </label>

          <label>
            Submitter Address (from connected wallet)
            <input value={form.submitterAddress} placeholder="Connect wallet first" readOnly required />
          </label>

          <div className="action-row">
            <button
              type="submit"
              disabled={
                submitting ||
                !walletConnected ||
                !thirdwebConfigured ||
                !miniWorldIdConfigured ||
                !worldAppMiniRuntime
              }
            >
              {submitting ? "Verifying And Queueing..." : "Verify And Queue"}
            </button>
          </div>
        </form>

        {requestId && (
          <section className="status-card">
            <h2>Request Submitted</h2>
            <p className="mono">{requestId}</p>
            <p>Queued successfully. Open Verify page to run the verification workflow.</p>
            <div className="action-row">
              <button
                type="button"
                className="secondary"
                onClick={() => navigate(`/result/${encodeURIComponent(requestId)}`)}
              >
                Open Result
              </button>
            </div>
          </section>
        )}

        {error && <p className="error-text">{error}</p>}

      </main>
    </div>
  );
}

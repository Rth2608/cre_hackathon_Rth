import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Command,
  MiniKit,
  ResponseEvent,
  isCommandAvailable,
  type MiniKitInstallReturnType,
  type MiniAppVerifyActionPayload,
  type VerifyCommandInput,
  type VerifyCommandPayload,
  VerificationLevel as MiniKitVerificationLevel
} from "@worldcoin/minikit-js";
import { ConnectButton, useActiveAccount } from "thirdweb/react";
import AppNav from "../components/AppNav";
import {
  listRequests,
  resolveWalletAddressForAuth,
  runVerificationForWallet,
  verifyWorldIdForWallet,
  type RequestRecord,
  type WorldIdSession
} from "../lib/api";
import { formatKnownMiniKitMessage } from "../lib/miniKitErrors";
import { clearWorldIdSession, getWorldIdConfig, loadWorldIdSession, saveWorldIdSession } from "../lib/worldId";
import { getWorldAppRuntimeMode } from "../lib/worldAppRuntime";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";
import { getWorldChainVirtualConfig, worldChainSepoliaChain } from "../lib/worldChain";

const MINI_VERIFY_TIMEOUT_MS = 20_000;
const MINI_INSTALL_RETRY_COUNT = 2;
const MINI_INSTALL_RETRY_DELAY_MS = 350;

type MiniVerifyMode = "orb" | "device" | "orb_or_device";

function normalizeWorldIdSignal(value: string): string {
  return value.trim().toLowerCase();
}

function formatShortAddress(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length < 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-4)}`;
}

function shortenText(value: string, max = 96): string {
  const trimmed = value.trim();
  if (trimmed.length <= max) {
    return trimmed;
  }
  return `${trimmed.slice(0, max - 1)}...`;
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
    (typeof (value.result as Record<string, unknown>).proof === "string" ||
      typeof (value.result as Record<string, unknown>).nullifier_hash === "string")
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
      const responseLegacyNullifier = typeof response.nullifier === "string" && response.nullifier.trim().length > 0;
      const responseMerkleRoot = typeof response.merkle_root === "string" && response.merkle_root.trim().length > 0;
      if (responseProof || responseNullifier || responseLegacyNullifier || responseMerkleRoot) {
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
    return `MiniKit command '${commandUnavailableMatch[1]}' is unavailable in this runtime. Update World App and retry.`;
  }
  const verifyTimeoutMatch = message.match(/^world_id_verify_timeout:\s*(.+)$/i);
  if (verifyTimeoutMatch) {
    return `World App did not return a verify result in time. ${verifyTimeoutMatch[1]}`;
  }
  const v4PayloadRequiredMatch = message.match(/^world_id_v4_payload_required:\s*(.+)$/i);
  if (v4PayloadRequiredMatch) {
    return `World ID 4.0 payload is required. Received legacy payload (${v4PayloadRequiredMatch[1]}).`;
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
        // ignore hook errors
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

function buildMiniVerifyLevel(mode: MiniVerifyMode): [MiniKitVerificationLevel] | [MiniKitVerificationLevel, MiniKitVerificationLevel] {
  if (mode === "orb") {
    return [MiniKitVerificationLevel.Orb];
  }
  if (mode === "device") {
    return [MiniKitVerificationLevel.Device];
  }
  return [MiniKitVerificationLevel.Orb, MiniKitVerificationLevel.Device];
}

function getStatusTone(status: RequestRecord["status"]): "ok" | "warn" | "bad" {
  if (status === "FINALIZED") {
    return "ok";
  }
  if (status === "REJECTED_DUPLICATE" || status === "REJECTED_CONFLICT" || status.startsWith("FAILED_")) {
    return "bad";
  }
  return "warn";
}

export default function VerifyPage() {
  const location = useLocation();
  const activeAccount = useActiveAccount();
  const activeWalletAddress = activeAccount?.address ?? "";
  const walletAddress = resolveWalletAddressForAuth(activeWalletAddress, activeAccount);
  const walletConnected = walletAddress.length > 0;
  const worldIdSignal = normalizeWorldIdSignal(walletAddress);
  const thirdwebConfigured = isThirdwebClientConfigured();
  const worldIdConfig = getWorldIdConfig();
  const worldAppMiniRuntime = getWorldAppRuntimeMode() === "miniapp";
  const miniWorldIdConfigured = worldIdConfig.mini.configured;
  const requireWorldIdOnRun = String(import.meta.env.VITE_REQUEST_REQUIRE_WORLD_ID_ON_RUN ?? "true").trim().toLowerCase() !== "false";
  const worldChainVirtualConfig = getWorldChainVirtualConfig();

  const [requests, setRequests] = useState<RequestRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [runningRequestId, setRunningRequestId] = useState<string | null>(null);
  const [verifyingWorldId, setVerifyingWorldId] = useState(false);
  const [miniKitAvailable, setMiniKitAvailable] = useState(false);
  const [worldIdSession, setWorldIdSession] = useState<WorldIdSession | null>(null);
  const [miniVerifyMode, setMiniVerifyMode] = useState<MiniVerifyMode>("orb_or_device");

  const miniVerifyRawPayloadsRef = useRef<MiniAppVerifyActionPayload[]>([]);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await listRequests();
      setRequests(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (!walletConnected) {
      setWorldIdSession(null);
      return;
    }
    setWorldIdSession(loadWorldIdSession(walletAddress));
  }, [walletAddress, walletConnected]);

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
    if (!walletConnected || !miniWorldIdConfigured || !worldAppMiniRuntime) {
      setMiniKitAvailable(false);
      return;
    }

    try {
      const installResult = installMiniKitWithAppId(worldIdConfig.mini.appId);
      const verifyAvailable = isCommandAvailable(Command.Verify);
      setMiniKitAvailable(isMiniKitInstallUsable(installResult) && verifyAvailable);
    } catch {
      setMiniKitAvailable(false);
    }
  }, [walletConnected, miniWorldIdConfigured, worldAppMiniRuntime, worldIdConfig.mini.appId]);

  const worldIdSessionActive =
    worldIdSession && Number.isFinite(Date.parse(worldIdSession.expiresAt))
      ? Date.parse(worldIdSession.expiresAt) > Date.now()
      : Boolean(worldIdSession?.token);
  const normalizedWalletAddress = walletAddress.trim().toLowerCase();

  const sortedRequests = useMemo(() => {
    return [...requests].sort((a, b) => {
      const aPending = a.status === "PENDING";
      const bPending = b.status === "PENDING";
      if (aPending && bPending) {
        return a.createdAt.localeCompare(b.createdAt);
      }
      if (aPending) {
        return -1;
      }
      if (bPending) {
        return 1;
      }
      return b.updatedAt.localeCompare(a.updatedAt);
    });
  }, [requests]);

  const queueSummary = useMemo(() => {
    const summary = {
      total: requests.length,
      pending: 0,
      running: 0,
      finalized: 0,
      rejected: 0,
      failed: 0
    };
    for (const item of requests) {
      if (item.status === "PENDING") summary.pending += 1;
      else if (item.status === "RUNNING") summary.running += 1;
      else if (item.status === "FINALIZED") summary.finalized += 1;
      else if (item.status === "REJECTED_DUPLICATE" || item.status === "REJECTED_CONFLICT") summary.rejected += 1;
      else if (item.status.startsWith("FAILED_")) summary.failed += 1;
    }
    return summary;
  }, [requests]);

  const myRequests = useMemo(() => {
    if (!walletConnected || !normalizedWalletAddress) {
      return [];
    }
    return sortedRequests.filter(
      (item) => item.input.submitterAddress.trim().toLowerCase() === normalizedWalletAddress
    );
  }, [sortedRequests, walletConnected, normalizedWalletAddress]);

  const myRequestSummary = useMemo(() => {
    const summary = {
      total: myRequests.length,
      vectorPending: 0,
      queuedForVerify: 0,
      verifyPassed: 0,
      closed: 0,
      rejected: 0
    };

    for (const item of myRequests) {
      const vectorStatus = item.vectorSync?.vectorStatus;
      const vectorState = item.vectorSync?.state;
      const queueDecision = item.queueDecision?.decision;

      if (item.status === "FINALIZED") {
        summary.verifyPassed += 1;
      }
      if (item.status === "REJECTED_DUPLICATE" || item.status === "REJECTED_CONFLICT" || vectorStatus === "REJECTED") {
        summary.rejected += 1;
      }
      if (vectorStatus === "CLOSED") {
        summary.closed += 1;
      }

      const isVectorPending =
        vectorState === "PENDING" ||
        vectorState === "APPLYING" ||
        vectorState === "FAILED" ||
        vectorStatus === "VERIFYING";
      if (isVectorPending) {
        summary.vectorPending += 1;
      }

      const isQueuedForVerify =
        item.status === "PENDING" &&
        queueDecision === "allow" &&
        vectorState === "APPLIED" &&
        vectorStatus === "QUEUED";
      if (isQueuedForVerify) {
        summary.queuedForVerify += 1;
      }
    }

    return summary;
  }, [myRequests]);

  const returnToPath = useMemo(() => {
    const params = new URLSearchParams(location.search);
    const raw = params.get("returnTo")?.trim() ?? "";
    if (!raw || !raw.startsWith("/") || raw.startsWith("//")) {
      return null;
    }
    return raw;
  }, [location.search]);

  const onVerifyWorldIdMiniApp = async () => {
    setError(null);
    setNotice(null);

    if (!walletConnected || !activeAccount) {
      setError("Connect wallet before World ID verification.");
      return;
    }
    if (!worldAppMiniRuntime) {
      setError("Mini App runtime is required. Open this app from World App Mini Apps.");
      return;
    }
    if (!miniWorldIdConfigured) {
      setError("Missing mini app World ID config. Set VITE_WORLD_ID_MINI_APP_ID / VITE_WORLD_ID_MINI_ACTION.");
      return;
    }

    miniVerifyRawPayloadsRef.current = [];
    setVerifyingWorldId(true);
    try {
      const requestedVerificationLevel = buildMiniVerifyLevel(miniVerifyMode);

      await ensureMiniKitInstalled(worldIdConfig.mini.appId);
      const runtimeMiniAppId = readMiniKitRuntimeAppId();
      const verifyAvailable = isCommandAvailable(Command.Verify);
      if (!verifyAvailable) {
        throw new Error("minikit_command_unavailable: verify");
      }
      if (runtimeMiniAppId && worldIdConfig.mini.appId && runtimeMiniAppId !== worldIdConfig.mini.appId) {
        throw new Error(
          `world_id_config_mismatch: runtime_app_id=${runtimeMiniAppId}, env_app_id=${worldIdConfig.mini.appId}`
        );
      }

      const miniAppIdForVerify = runtimeMiniAppId || worldIdConfig.mini.appId;
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

      const proofCandidates: Array<{ payload: MiniAppVerifyActionPayload }> = [
        ...miniVerifyRawPayloadsRef.current.slice().reverse().map((payload) => ({ payload })),
        { payload: finalPayload }
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
        appId: miniAppIdForVerify,
        action: worldIdConfig.mini.action,
        clientSource: "miniapp",
        account: activeAccount
      });

      saveWorldIdSession(walletAddress, result.session);
      setWorldIdSession(result.session);
      setNotice(`World ID verified. Session valid until ${new Date(result.session.expiresAt).toLocaleString()}.`);
    } catch (err) {
      setError(getWorldIdErrorMessage(err));
    } finally {
      setVerifyingWorldId(false);
    }
  };

  const onClearWorldId = () => {
    if (!walletConnected) {
      return;
    }
    clearWorldIdSession(walletAddress);
    setWorldIdSession(null);
    setNotice("World ID session was cleared for this wallet.");
  };

  const onRunQueuedRequest = async (record: RequestRecord) => {
    setNotice(null);
    setError(null);

    if (!walletConnected || !activeAccount) {
      setError("Connect wallet before running verification.");
      return;
    }

    if (record.input.submitterAddress.trim().toLowerCase() !== walletAddress.trim().toLowerCase()) {
      setError("Connected wallet must match request submitter.");
      return;
    }

    if (requireWorldIdOnRun && (!worldIdSession?.token || !worldIdSessionActive)) {
      setError("Verify World ID first to run queued verification.");
      return;
    }

    setRunningRequestId(record.requestId);
    try {
      const runWorldIdToken = requireWorldIdOnRun ? worldIdSession?.token : undefined;
      await runVerificationForWallet(record.requestId, walletAddress, runWorldIdToken, activeAccount);
      if (requireWorldIdOnRun) {
        clearWorldIdSession(walletAddress);
        setWorldIdSession(null);
      }
      setNotice(`Verification triggered for ${record.requestId}.`);
      await load();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("world_id_token_")) {
        clearWorldIdSession(walletAddress);
        setWorldIdSession(null);
      }
      setError(message);
    } finally {
      setRunningRequestId(null);
    }
  };

  return (
    <div className="page-shell">
      <main className="panel">
        <AppNav current="verify" />

        <header className="hero compact">
          <p className="eyebrow">Mini App Verify</p>
          <h1>Verification Dashboard</h1>
          <p>
            {requireWorldIdOnRun
              ? "Verify World ID, then run queued request verification from this wallet."
              : "Run queued request verification from this wallet."}
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
                Missing <code>VITE_THIRDWEB_CLIENT_ID</code>. Wallet login is disabled.
              </p>
            )}
            {walletConnected && <p className="wallet-info mono">Connected: {walletAddress}</p>}
            {walletConnected && (
              <p className="wallet-info mono">
                Wallet: {formatShortAddress(walletAddress)} / {worldChainVirtualConfig.chainName}
              </p>
            )}
          </div>
          <div className="inline-row">
            <Link to="/" className="text-link">
              Back to Request
            </Link>
            {returnToPath && (
              <Link to={returnToPath} className="text-link">
                Back to Previous Page
              </Link>
            )}
            <button type="button" className="secondary" onClick={load}>
              Refresh
            </button>
          </div>
        </header>

        <section className="status-card">
          <h2>World ID Session</h2>
          <p className="config-warning runtime-note">
            {worldAppMiniRuntime
              ? "Runtime: World App Mini App (supported)"
              : "Runtime: Web Browser (unsupported). Open from World App Mini Apps."}
          </p>
          <p className="config-warning">
            Mini App: {worldIdConfig.mini.appId || "-"} / {worldIdConfig.mini.action || "-"}
          </p>
          <div className="action-row">
            <label>
              Verify Level
              <select
                value={miniVerifyMode}
                onChange={(event) => setMiniVerifyMode(event.target.value as MiniVerifyMode)}
                disabled={verifyingWorldId}
              >
                <option value="orb_or_device">orb_or_device (recommended)</option>
                <option value="orb">orb only</option>
                <option value="device">device only</option>
              </select>
            </label>
            <button
              type="button"
              onClick={onVerifyWorldIdMiniApp}
              disabled={!walletConnected || !worldAppMiniRuntime || !miniWorldIdConfigured || !miniKitAvailable || verifyingWorldId}
            >
              {verifyingWorldId ? "Verifying..." : "Verify in World Mini App"}
            </button>
            <button type="button" className="secondary" onClick={onClearWorldId} disabled={!walletConnected}>
              Clear Session
            </button>
          </div>
          {worldIdSession ? (
            <p>
              Session: ACTIVE / expires {new Date(worldIdSession.expiresAt).toLocaleString()}
            </p>
          ) : (
            <p>Session: NONE</p>
          )}
        </section>

        <section className="status-card">
          <h2>Queue Overview</h2>
          <div className="snapshot-grid">
            <div className="snapshot-item">
              <p className="snapshot-label">Total</p>
              <p className="wallet-info mono">{queueSummary.total}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Pending</p>
              <p className="wallet-info mono">{queueSummary.pending}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Running</p>
              <p className="wallet-info mono">{queueSummary.running}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Finalized</p>
              <p className="wallet-info mono">{queueSummary.finalized}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Rejected</p>
              <p className="wallet-info mono">{queueSummary.rejected}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Failed</p>
              <p className="wallet-info mono">{queueSummary.failed}</p>
            </div>
          </div>
        </section>

        <section className="status-card">
          <h2>My Question Dashboard</h2>
          {!walletConnected ? (
            <p>Connect wallet to view your submitted questions.</p>
          ) : myRequests.length === 0 ? (
            <p>No requests submitted by this wallet yet.</p>
          ) : (
            <>
              <div className="snapshot-grid">
                <div className="snapshot-item">
                  <p className="snapshot-label">My Total</p>
                  <p className="wallet-info mono">{myRequestSummary.total}</p>
                </div>
                <div className="snapshot-item">
                  <p className="snapshot-label">Vector Pending</p>
                  <p className="wallet-info mono">{myRequestSummary.vectorPending}</p>
                </div>
                <div className="snapshot-item">
                  <p className="snapshot-label">Queued For Verify</p>
                  <p className="wallet-info mono">{myRequestSummary.queuedForVerify}</p>
                </div>
                <div className="snapshot-item">
                  <p className="snapshot-label">Verify Passed</p>
                  <p className="wallet-info mono">{myRequestSummary.verifyPassed}</p>
                </div>
                <div className="snapshot-item">
                  <p className="snapshot-label">Closed</p>
                  <p className="wallet-info mono">{myRequestSummary.closed}</p>
                </div>
                <div className="snapshot-item">
                  <p className="snapshot-label">Rejected</p>
                  <p className="wallet-info mono">{myRequestSummary.rejected}</p>
                </div>
              </div>

              <div className="request-table">
                <div className="request-head">
                  <span>Question</span>
                  <span>Status</span>
                  <span>Queue</span>
                  <span>Vector</span>
                  <span>Updated</span>
                  <span>Action</span>
                </div>
                {myRequests.map((record) => {
                  const hasRunWorldId = !requireWorldIdOnRun || (Boolean(worldIdSession?.token) && worldIdSessionActive);
                  const canRunPending =
                    record.status === "PENDING" && hasRunWorldId && runningRequestId === null;
                  const pendingReason =
                    !hasRunWorldId
                      ? "verify world id"
                      : runningRequestId !== null
                        ? "another run in progress"
                        : "ready";
                  return (
                    <div key={record.requestId} className="request-row">
                      <span className="question-cell">{shortenText(record.input.question)}</span>
                      <span className={`status-badge ${getStatusTone(record.status)}`}>{record.status}</span>
                      <span className="small mono">{record.queueDecision?.decision ?? "-"}</span>
                      <span className="small mono">
                        {record.vectorSync ? `${record.vectorSync.state}/${record.vectorSync.vectorStatus}` : "-"}
                      </span>
                      <span>{new Date(record.updatedAt).toLocaleString()}</span>
                      <span className="inline-row">
                        <Link className="text-link" to={`/result/${encodeURIComponent(record.requestId)}`}>
                          Result
                        </Link>
                        {record.status === "PENDING" && (
                          <button
                            type="button"
                            className="secondary"
                            onClick={() => void onRunQueuedRequest(record)}
                            disabled={!canRunPending || runningRequestId === record.requestId}
                          >
                            {runningRequestId === record.requestId ? "Running..." : "Run Verify"}
                          </button>
                        )}
                        {record.status === "PENDING" && !canRunPending && (
                          <span className="small mono">({pendingReason})</span>
                        )}
                      </span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </section>

        <section className="status-card">
          <h2>Requests</h2>
          <p className="config-warning">Pending items are shown first (FIFO).</p>
          {loading ? (
            <p>Loading requests...</p>
          ) : sortedRequests.length === 0 ? (
            <p>No requests yet. Create one from Request page.</p>
          ) : (
            <div className="request-table">
              <div className="request-head">
                <span>Request</span>
                <span>Status</span>
                <span>Queue</span>
                <span>Vector</span>
                <span>Updated</span>
                <span>Action</span>
              </div>
              {sortedRequests.map((record) => {
                const ownedByConnectedWallet =
                  walletConnected &&
                  record.input.submitterAddress.trim().toLowerCase() === walletAddress.trim().toLowerCase();
                const hasRunWorldId = !requireWorldIdOnRun || (Boolean(worldIdSession?.token) && worldIdSessionActive);
                const canRunPending =
                  record.status === "PENDING" &&
                  ownedByConnectedWallet &&
                  hasRunWorldId &&
                  runningRequestId === null;
                const pendingReason =
                  !walletConnected
                    ? "connect wallet"
                    : !ownedByConnectedWallet
                      ? "submitter wallet only"
                      : !hasRunWorldId
                        ? "verify world id"
                        : runningRequestId !== null
                          ? "another run in progress"
                          : "ready";

                return (
                  <div key={record.requestId} className="request-row">
                    <span className="mono small">{record.requestId}</span>
                    <span className={`status-badge ${getStatusTone(record.status)}`}>{record.status}</span>
                    <span className="small mono">{record.queueDecision?.decision ?? "-"}</span>
                    <span className="small mono">
                      {record.vectorSync ? `${record.vectorSync.state}/${record.vectorSync.vectorStatus}` : "-"}
                    </span>
                    <span>{new Date(record.updatedAt).toLocaleString()}</span>
                    <span className="inline-row">
                      <Link className="text-link" to={`/result/${encodeURIComponent(record.requestId)}`}>
                        Result
                      </Link>
                      {record.status === "PENDING" && (
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => void onRunQueuedRequest(record)}
                          disabled={!canRunPending || runningRequestId === record.requestId}
                        >
                          {runningRequestId === record.requestId ? "Running..." : "Run Verify"}
                        </button>
                      )}
                      {record.status === "PENDING" && !canRunPending && (
                        <span className="small mono">({pendingReason})</span>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {notice && <p>{notice}</p>}
        {error && <p className="error-text">{error}</p>}
      </main>
    </div>
  );
}

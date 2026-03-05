import { FormEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  IDKitWidget,
  type IErrorState,
  type ISuccessResult,
  VerificationLevel as IDKitVerificationLevel
} from "@worldcoin/idkit";
import {
  MiniKit,
  ResponseEvent,
  type MiniKitInstallReturnType,
  type MiniAppVerifyActionPayload,
  type VerifyCommandInput,
  type VerifyCommandPayload,
  VerificationLevel as MiniKitVerificationLevel
} from "@worldcoin/minikit-js";
import { ConnectButton, useActiveAccount, useActiveWalletChain, useWalletBalance } from "thirdweb/react";
import AppNav from "../components/AppNav";
import {
  createRequestForWallet,
  verifyWorldIdForWallet,
  type MarketRequestInput,
  type WorldIdSession
} from "../lib/api";
import { formatKnownMiniKitMessage } from "../lib/miniKitErrors";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";
import { clearWorldIdSession, getWorldIdConfig, loadWorldIdSession } from "../lib/worldId";
import { getWorldAppRuntimeMode } from "../lib/worldAppRuntime";
import {
  fetchWorldChainVirtualBalances,
  getWorldChainVirtualConfig,
  worldChainSepoliaChain,
  type WorldChainVirtualBalanceSnapshot
} from "../lib/worldChain";

const defaultForm: MarketRequestInput = {
  question: "",
  description: "",
  sourceUrls: [],
  resolutionCriteria: "",
  submitterAddress: ""
};

const MINI_VERIFY_TIMEOUT_MS = 20_000;
const EXTERNAL_VERIFY_TIMEOUT_MS = 45_000;

function formatShortAddress(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length < 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-4)}`;
}

function formatRemainingDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) {
    return "expired";
  }
  const totalMinutes = Math.floor(ms / 60000);
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;
  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
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

function buildWorldProofFromIdKit(result: ISuccessResult): Record<string, unknown> {
  const rawResult = result as unknown as Record<string, unknown>;
  if (!looksLikeWorldIdV4ProofPayload(rawResult) || !hasWorldIdProofMaterial(rawResult)) {
    throw new Error("world_id_v4_payload_required: external_widget_returned_legacy_payload");
  }
  return rawResult;
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
  if (message === "world_id_widget_unavailable") {
    return "External World ID widget is not ready yet. Retry after the page fully loads.";
  }
  if (message === "world_id_widget_busy") {
    return "An external World ID verification is already in progress.";
  }
  if (message === "world_id_widget_closed") {
    return "World ID widget was closed before verification completed.";
  }
  if (message === "world_id_widget_timeout") {
    return "External World ID verification timed out. Close the widget and retry.";
  }
  if (message === "world_id_external_not_configured") {
    return "External World ID is not configured. Set VITE_WORLD_ID_EXTERNAL_APP_ID and VITE_WORLD_ID_EXTERNAL_ACTION.";
  }
  if (message === "world_id_external_not_supported_in_worldapp_browser") {
    return "This page is opened inside World App browser context. Reopen from Mini Apps entry and use in-app Mini verification.";
  }
  const normalized = formatKnownMiniKitMessage(message);
  if (normalized) {
    return normalized;
  }
  return message;
}

function shouldFallbackFromMiniToExternal(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("A verify request is already in flight")) {
    return false;
  }
  if (
    /world_id_verify_failed:\s*(verification_rejected|user_rejected|max_verifications_reached)\b/i.test(message)
  ) {
    return false;
  }
  return true;
}

function isMiniVerifyUnavailableError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    /^minikit_command_unavailable:\s*verify$/i.test(message) ||
    /^minikit_unavailable:\s*(outside_of_worldapp|not_on_client|app_out_of_date)$/i.test(message)
  );
}

function isLikelyWorldAppBrowserContext(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  const userAgent = window.navigator.userAgent.toLowerCase();
  return userAgent.includes("worldapp") || userAgent.includes("worldcoin");
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
  return installResult.errorCode === "already_installed" || installResult.errorCode === "app_out_of_date";
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

interface ExternalVerifyPending {
  resolve: (proof: Record<string, unknown>) => void;
  reject: (error: Error) => void;
  timeoutId?: number;
}

function toError(value: unknown): Error {
  if (value instanceof Error) {
    return value;
  }
  return new Error(String(value));
}

export default function SubmitPage() {
  const navigate = useNavigate();
  const activeAccount = useActiveAccount();
  const activeChain = useActiveWalletChain();
  const walletAddress = activeAccount?.address ?? "";
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();
  const { data: walletBalance, isLoading: walletBalanceLoading, isError: walletBalanceError } = useWalletBalance({
    chain: worldChainSepoliaChain,
    address: walletConnected ? walletAddress : undefined,
    client: thirdwebClient
  });
  const worldIdConfig = getWorldIdConfig();
  const worldIdConfigured = worldIdConfig.mini.configured || worldIdConfig.external.configured;
  const worldChainVirtualConfig = getWorldChainVirtualConfig();
  const worldAppMiniRuntime = getWorldAppRuntimeMode() === "miniapp";

  const [form, setForm] = useState(defaultForm);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [worldIdSession, setWorldIdSession] = useState<WorldIdSession | null>(null);
  const [worldChainBalances, setWorldChainBalances] = useState<WorldChainVirtualBalanceSnapshot | null>(null);
  const [worldChainBalancesLoading, setWorldChainBalancesLoading] = useState(false);
  const [worldChainBalancesError, setWorldChainBalancesError] = useState<string | null>(null);

  const miniVerifyRawPayloadsRef = useRef<MiniAppVerifyActionPayload[]>([]);
  const externalOpenRef = useRef<(() => void) | null>(null);
  const externalVerifyPendingRef = useRef<ExternalVerifyPending | null>(null);

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
    if (!walletConnected) {
      setWorldIdSession(null);
      return;
    }
    setWorldIdSession(loadWorldIdSession(walletAddress));
  }, [walletAddress, walletConnected]);

  useEffect(() => {
    if (!walletConnected || !thirdwebConfigured) {
      setWorldChainBalances(null);
      setWorldChainBalancesError(null);
      setWorldChainBalancesLoading(false);
      return;
    }

    let cancelled = false;
    setWorldChainBalancesLoading(true);
    setWorldChainBalancesError(null);

    void fetchWorldChainVirtualBalances(walletAddress)
      .then((snapshot) => {
        if (cancelled) {
          return;
        }
        setWorldChainBalances(snapshot);
      })
      .catch((fetchError) => {
        if (cancelled) {
          return;
        }
        setWorldChainBalancesError(fetchError instanceof Error ? fetchError.message : String(fetchError));
      })
      .finally(() => {
        if (cancelled) {
          return;
        }
        setWorldChainBalancesLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [walletAddress, walletConnected, thirdwebConfigured]);

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
    return () => {
      const pending = externalVerifyPendingRef.current;
      if (pending) {
        if (typeof pending.timeoutId === "number") {
          window.clearTimeout(pending.timeoutId);
        }
        pending.reject(new Error("world_id_widget_closed"));
      }
      externalVerifyPendingRef.current = null;
    };
  }, []);

  const nativeBalanceText =
    walletBalanceLoading
      ? "Loading..."
      : walletBalance
        ? `${walletBalance.displayValue} ${walletBalance.symbol}`
        : walletBalanceError
          ? "Failed to load"
          : "-";
  const chainText = `${worldChainVirtualConfig.chainName} (virtual, id: ${worldChainVirtualConfig.chainId})`;
  const connectedChainText = activeChain ? `${activeChain.name} (id: ${activeChain.id})` : "Not connected";
  const connectedChainMismatch = Boolean(activeChain && activeChain.id !== worldChainVirtualConfig.chainId);
  const requestCreateReady = walletConnected && thirdwebConfigured;
  const requestCreateReason = !walletConnected
    ? "Connect wallet"
    : !thirdwebConfigured
      ? "Set VITE_THIRDWEB_CLIENT_ID"
      : "Ready";
  const worldIdStatus = worldIdSession ? `Verified (${worldIdSession.verificationLevel ?? "unknown"})` : "Not verified";
  const worldIdRemaining =
    worldIdSession && Number.isFinite(Date.parse(worldIdSession.expiresAt))
      ? formatRemainingDuration(Date.parse(worldIdSession.expiresAt) - Date.now())
      : "-";
  const requestSubmitReady = requestCreateReady && worldIdConfigured;
  const requestSubmitReason = !walletConnected
    ? "Connect wallet"
    : !thirdwebConfigured
      ? "Set VITE_THIRDWEB_CLIENT_ID"
      : !worldIdConfigured
        ? "Configure World ID app/action env"
        : "Ready (verify on submit)";
  const worldChainNativeBalanceText = worldChainBalancesLoading
    ? "Loading..."
    : worldChainBalances?.native
      ? `${worldChainBalances.native.displayValue} ${worldChainBalances.native.symbol}`
      : worldChainBalancesError
        ? "Failed to load"
        : "-";

  const runExternalProofFlow = (): Promise<Record<string, unknown>> => {
    if (worldAppMiniRuntime) {
      return Promise.reject(new Error("minikit_command_unavailable: verify"));
    }
    if (isLikelyWorldAppBrowserContext()) {
      return Promise.reject(new Error("world_id_external_not_supported_in_worldapp_browser"));
    }
    if (!worldIdConfig.external.configured) {
      return Promise.reject(new Error("world_id_external_not_configured"));
    }
    const open = externalOpenRef.current;
    if (!open) {
      return Promise.reject(new Error("world_id_widget_unavailable"));
    }
    if (externalVerifyPendingRef.current) {
      return Promise.reject(new Error("world_id_widget_busy"));
    }

    return new Promise((resolve, reject) => {
      const timeoutId = window.setTimeout(() => {
        const pending = externalVerifyPendingRef.current;
        if (!pending) {
          return;
        }
        externalVerifyPendingRef.current = null;
        pending.reject(new Error("world_id_widget_timeout"));
      }, EXTERNAL_VERIFY_TIMEOUT_MS);

      externalVerifyPendingRef.current = { resolve, reject, timeoutId };
      try {
        open();
      } catch (error) {
        window.clearTimeout(timeoutId);
        externalVerifyPendingRef.current = null;
        reject(toError(error));
      }
    });
  };

  const verifyWorldIdForSubmit = async (): Promise<WorldIdSession> => {
    if (!activeAccount) {
      throw new Error("wallet_account_required");
    }

    miniVerifyRawPayloadsRef.current = [];
    const requestedVerificationLevel: [MiniKitVerificationLevel, MiniKitVerificationLevel] = [
      MiniKitVerificationLevel.Orb,
      MiniKitVerificationLevel.Device
    ];

    if (worldIdConfig.mini.configured) {
      let miniInstallUsable = false;
      let miniInstallErrorCode: string | null = null;
      try {
        const installResult = installMiniKitWithAppId(worldIdConfig.mini.appId);
        miniInstallUsable = isMiniKitInstallUsable(installResult);
        miniInstallErrorCode = installResult.success ? null : installResult.errorCode;
      } catch {
        miniInstallUsable = false;
      }

      if (miniInstallUsable) {
        try {
          const runtimeMiniAppId = readMiniKitRuntimeAppId() || worldIdConfig.mini.appId;
          const { commandPayload, finalPayload } = await runMiniVerifyCommand({
            action: worldIdConfig.mini.action,
            signal: walletAddress,
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
            signal: walletAddress,
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
        } catch (miniError) {
          const allowFallbackOnThisError = isMiniVerifyUnavailableError(miniError);
          if (
            worldAppMiniRuntime ||
            !worldIdConfig.external.configured ||
            (!allowFallbackOnThisError && !shouldFallbackFromMiniToExternal(miniError))
          ) {
            throw miniError;
          }
        }
      } else if (worldAppMiniRuntime) {
        throw new Error(`minikit_unavailable: ${miniInstallErrorCode ?? "unknown"}`);
      }
    }

    if (worldIdConfig.external.configured) {
      const proof = await runExternalProofFlow();
      const result = await verifyWorldIdForWallet({
        walletAddress,
        proof,
        appId: worldIdConfig.external.appId,
        action: worldIdConfig.external.action,
        clientSource: "external",
        account: activeAccount
      });
      return result.session;
    }

    throw new Error("world_id_not_configured");
  };

  const onExternalHandleVerify = async (result: ISuccessResult) => {
    const pending = externalVerifyPendingRef.current;
    if (!pending) {
      return;
    }

    try {
      if (typeof pending.timeoutId === "number") {
        window.clearTimeout(pending.timeoutId);
      }
      const proof = buildWorldProofFromIdKit(result);
      pending.resolve(proof);
    } catch (error) {
      pending.reject(toError(error));
      throw error;
    } finally {
      externalVerifyPendingRef.current = null;
    }
  };

  const onExternalVerifyError = (errorState: IErrorState) => {
    const pending = externalVerifyPendingRef.current;
    if (!pending) {
      return;
    }
    if (typeof pending.timeoutId === "number") {
      window.clearTimeout(pending.timeoutId);
    }
    pending.reject(new Error(`world_id_widget_error: ${errorState.code}`));
    externalVerifyPendingRef.current = null;
  };

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    if (!thirdwebConfigured) {
      setError("Missing VITE_THIRDWEB_CLIENT_ID. Configure dapp/.env and restart the dev server.");
      setSubmitting(false);
      return;
    }

    if (!walletConnected || !activeAccount) {
      setError("Connect wallet before creating a request.");
      setSubmitting(false);
      return;
    }

    if (!worldIdConfigured) {
      setError("World ID is not configured. Set VITE_WORLD_ID_* values and redeploy frontend.");
      setSubmitting(false);
      return;
    }

    try {
      clearWorldIdSession(walletAddress);
      setWorldIdSession(null);

      const session = await verifyWorldIdForSubmit();
      setWorldIdSession(session);

      const created = await createRequestForWallet(form, walletAddress, session.token, activeAccount);
      setRequestId(created.requestId);
      clearWorldIdSession(walletAddress);
      setWorldIdSession(null);
      navigate(`/result/${encodeURIComponent(created.requestId)}`);
    } catch (err) {
      const message = getWorldIdErrorMessage(err);
      if (
        message.includes("world_id_token_") ||
        message.includes("world_id_verify_failed") ||
        message.includes("world_id_widget_error")
      ) {
        clearWorldIdSession(walletAddress);
        setWorldIdSession(null);
      }
      setError(message);
    } finally {
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
            Enter market question, evidence URLs, and resolver criteria. On submit, the orchestrator immediately
            matches verifier nodes, computes consensus, and finalizes on-chain.
          </p>
          <div className="hero-chips">
            <span className="chip">4 DON Nodes</span>
            <span className="chip">Weighted Consensus</span>
            <span className="chip">Tenderly Finalization</span>
            <span className="chip">{worldAppMiniRuntime ? "Mini App Mode" : "Web / QR Mode"}</span>
          </div>
          <p className="config-warning runtime-note">
            {worldAppMiniRuntime
              ? "In World App: Submit triggers in-app Mini verification."
              : "In browser: Submit triggers external World ID QR verification."}
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
          <h2>Wallet Snapshot</h2>
          <div className="snapshot-grid">
            <div className="snapshot-item">
              <p className="snapshot-label">Wallet</p>
              <p className="wallet-info mono">{walletConnected ? walletAddress : "-"}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Short Address</p>
              <p className="wallet-info mono">{walletConnected ? formatShortAddress(walletAddress) : "-"}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Network</p>
              <p className="wallet-info">{chainText}</p>
              <p className="wallet-info small">Connected wallet chain: {connectedChainText}</p>
              {connectedChainMismatch && (
                <p className="config-warning">
                  Connected chain differs. Balance/verification display is fixed to virtual {worldChainVirtualConfig.chainName}.
                </p>
              )}
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Native Balance</p>
              <p className="wallet-info mono">{nativeBalanceText}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">World ID</p>
              <p className="wallet-info">{worldIdStatus}</p>
              <p className="wallet-info small">
                expires in {worldIdRemaining}
                {worldIdSession?.expiresAt ? ` / ${new Date(worldIdSession.expiresAt).toLocaleString()}` : ""}
              </p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">{worldChainVirtualConfig.chainName}</p>
              <p className="wallet-info">chain id: {worldChainVirtualConfig.chainId}</p>
              <p className="wallet-info small mono">
                rpc: {worldChainVirtualConfig.rpcUrl || "thirdweb default rpc"}
              </p>
              <p className="wallet-info mono">native: {worldChainNativeBalanceText}</p>
            </div>
            <div className="snapshot-item">
              <p className="snapshot-label">Virtual Token Balances</p>
              {!thirdwebConfigured ? (
                <p className="config-warning">Set VITE_THIRDWEB_CLIENT_ID first.</p>
              ) : worldChainVirtualConfig.tokenAddresses.length === 0 ? (
                <p className="wallet-info small">No ERC20 virtual tokens configured.</p>
              ) : worldChainBalancesLoading ? (
                <p className="wallet-info mono">Loading token balances...</p>
              ) : worldChainBalancesError ? (
                <p className="config-warning">Failed to load: {worldChainBalancesError}</p>
              ) : (
                <div className="token-balance-list">
                  {(worldChainBalances?.tokens ?? []).map((item) => (
                    <p key={item.tokenAddress} className="wallet-info mono small">
                      {item.tokenAddress}:{" "}
                      {item.balance ? `${item.balance.displayValue} ${item.balance.symbol}` : item.error ? "Failed" : "-"}
                    </p>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="snapshot-capabilities">
            <p className="snapshot-label">Current Availability</p>
            <div className="snapshot-capability-list">
              <p className={`snapshot-capability ${requestCreateReady ? "ok" : "warn"}`}>
                Request Create: {requestCreateReady ? "READY" : "BLOCKED"} ({requestCreateReason})
              </p>
              <p className={`snapshot-capability ${requestSubmitReady ? "ok" : "warn"}`}>
                Request Submit (World ID per request): {requestSubmitReady ? "READY" : "BLOCKED"} ({requestSubmitReason})
              </p>
            </div>
            <div className="action-row">
              <button type="button" className="secondary" onClick={() => navigate("/verify")}>
                Open Verify Page
              </button>
            </div>
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
            <button type="submit" disabled={submitting || !walletConnected || !thirdwebConfigured || !worldIdConfigured}>
              {submitting
                ? "Verifying And Submitting..."
                : worldAppMiniRuntime
                  ? "Submit And Verify (Mini App)"
                  : "Submit And Verify (QR)"}
            </button>
          </div>
        </form>

        {!worldAppMiniRuntime && worldIdConfig.external.configured && (
          <div style={{ display: "none" }}>
            <IDKitWidget
              app_id={worldIdConfig.external.appId}
              action={worldIdConfig.external.action}
              signal={walletAddress}
              verification_level={IDKitVerificationLevel.Device}
              handleVerify={onExternalHandleVerify}
              onSuccess={() => undefined}
              onError={onExternalVerifyError}
            >
              {({ open }: { open: () => void }) => {
                externalOpenRef.current = open;
                return (
                  <button type="button" aria-hidden="true" tabIndex={-1}>
                    External Verify
                  </button>
                );
              }}
            </IDKitWidget>
          </div>
        )}

        {requestId && (
          <section className="status-card">
            <h2>Request Submitted</h2>
            <p className="mono">{requestId}</p>
            <p>Verification was triggered automatically for this request.</p>
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

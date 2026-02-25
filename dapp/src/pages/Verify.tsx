import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  IDKitWidget,
  type IErrorState,
  type ISuccessResult,
  VerificationLevel as IDKitVerificationLevel
} from "@worldcoin/idkit";
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
import { signMessage } from "thirdweb/utils";
import AppNav from "../components/AppNav";
import {
  activateNodeChallenge,
  listNodes,
  listRequests,
  requestNodeChallenge,
  sendNodeHeartbeat,
  verifyWorldIdForWallet,
  type RegisteredNode,
  type RequestRecord,
  type WorldIdSession
} from "../lib/api";
import { formatKnownMiniKitMessage } from "../lib/miniKitErrors";
import { clearWorldIdSession, getWorldIdConfig, loadWorldIdSession, saveWorldIdSession } from "../lib/worldId";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";

const MODEL_FAMILIES = ["gpt", "gemini", "claude", "grok"] as const;
type ModelFamily = (typeof MODEL_FAMILIES)[number];
type MiniVerifyMode = "orb" | "device" | "orb_or_device";

interface WorldIdDebugEntry {
  at: string;
  event: string;
  detail?: string;
}

function buildNodeHeartbeatMessage(input: { walletAddress: string; endpointUrl: string; timestamp: number }): string {
  return [
    "CRE Node Heartbeat",
    `walletAddress: ${input.walletAddress}`,
    `endpointUrl: ${input.endpointUrl}`,
    `timestamp: ${input.timestamp}`
  ].join("\n");
}

function toLowerAddress(value: string): string {
  return value.trim().toLowerCase();
}

function formatEndpointHealth(node: RegisteredNode): string {
  const latency = typeof node.endpointLatencyMs === "number" ? `${node.endpointLatencyMs}ms` : "-";
  const error = node.endpointLastError ? ` / ${node.endpointLastError}` : "";
  return `${node.endpointStatus} (${latency})${error}`;
}

function buildWorldProofFromIdKit(result: ISuccessResult): Record<string, unknown> {
  return {
    merkle_root: result.merkle_root,
    nullifier_hash: result.nullifier_hash,
    proof: result.proof,
    verification_level: result.verification_level
  };
}

function buildWorldProofFromMiniKit(payload: MiniAppVerifyActionPayload): Record<string, unknown> | null {
  if (payload.status !== "success") {
    return null;
  }

  if ("proof" in payload && typeof payload.proof === "string") {
    return {
      merkle_root: payload.merkle_root,
      nullifier_hash: payload.nullifier_hash,
      proof: payload.proof,
      verification_level: payload.verification_level
    };
  }

  if ("verifications" in payload && Array.isArray(payload.verifications) && payload.verifications.length > 0) {
    const selectedVerification =
      payload.verifications.find((item) => item.verification_level === MiniKitVerificationLevel.Orb) ??
      payload.verifications[0];
    return {
      merkle_root: selectedVerification.merkle_root,
      nullifier_hash: selectedVerification.nullifier_hash,
      proof: selectedVerification.proof,
      verification_level: selectedVerification.verification_level
    };
  }

  return null;
}

function toMiniKitErrorCode(payload: MiniAppVerifyActionPayload): string {
  if (payload.status === "error") {
    return payload.error_code;
  }
  return "invalid_miniapp_payload";
}

function formatDebugDetail(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function readMiniKitRuntimeAppId(): string {
  return (MiniKit.appId ?? "").trim();
}

function readWorldAppDebugContext(): Record<string, unknown> {
  if (typeof window === "undefined") {
    return { available: false };
  }
  const worldApp = (window as Window & { WorldApp?: Record<string, unknown> }).WorldApp;
  if (!worldApp) {
    return { available: false };
  }

  const supportedCommands = Array.isArray(worldApp.supported_commands)
    ? (worldApp.supported_commands as Array<Record<string, unknown>>)
    : [];
  const verifyCommand = supportedCommands.find((entry) => entry?.name === "verify");
  const rawLocation = worldApp.location;
  let openOrigin: unknown;
  if (typeof rawLocation === "string") {
    openOrigin = rawLocation;
  } else if (typeof rawLocation === "object" && rawLocation && "open_origin" in (rawLocation as Record<string, unknown>)) {
    openOrigin = (rawLocation as Record<string, unknown>).open_origin;
  }
  return {
    available: true,
    openOrigin,
    rawLocation,
    worldAppVersion: worldApp.world_app_version,
    deviceOs: worldApp.device_os,
    verifySupportedVersions: verifyCommand?.supported_versions,
    miniKitLocation: MiniKit.location ?? null
  };
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

function summarizeMiniKitPayload(payload: MiniAppVerifyActionPayload): Record<string, unknown> {
  if (payload.status === "error") {
    return {
      status: payload.status,
      errorCode: payload.error_code
    };
  }

  if ("verification_level" in payload) {
    return {
      status: payload.status,
      verificationLevel: payload.verification_level
    };
  }

  if ("verifications" in payload) {
    return {
      status: payload.status,
      verificationLevels: payload.verifications.map((item) => item.verification_level),
      verificationCount: payload.verifications.length
    };
  }

  return { status: "unknown" };
}

function summarizeWorldProof(proof: Record<string, unknown>): Record<string, unknown> {
  const proofValue = proof.proof;
  return {
    verificationLevel: proof.verification_level,
    hasMerkleRoot: typeof proof.merkle_root === "string" && proof.merkle_root.length > 0,
    hasNullifierHash: typeof proof.nullifier_hash === "string" && proof.nullifier_hash.length > 0,
    proofType: Array.isArray(proofValue) ? "array" : typeof proofValue,
    proofLength:
      typeof proofValue === "string"
        ? proofValue.length
        : Array.isArray(proofValue)
          ? proofValue.length
          : undefined
  };
}

function getWorldIdErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
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
  const appMismatchMatch = message.match(/^world_id_config_mismatch:\s*(.+)$/i);
  if (appMismatchMatch) {
    return `World App runtime appId and deployed env appId differ. ${appMismatchMatch[1]}`;
  }

  const normalized = formatKnownMiniKitMessage(message);
  if (normalized) {
    return normalized;
  }
  return message;
}

function isMiniKitInstallUsable(installResult: MiniKitInstallReturnType): boolean {
  if (installResult.success) {
    return true;
  }
  return installResult.errorCode === "already_installed";
}

function buildMiniVerifyLevel(
  mode: MiniVerifyMode
): MiniKitVerificationLevel | [MiniKitVerificationLevel, MiniKitVerificationLevel] {
  if (mode === "orb") {
    return MiniKitVerificationLevel.Orb;
  }
  if (mode === "device") {
    return MiniKitVerificationLevel.Device;
  }
  return [MiniKitVerificationLevel.Orb, MiniKitVerificationLevel.Device];
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
        // Avoid breaking command processing due to debug hook errors.
      }
    }
    originalTrigger(event, payload);
  };
  debugWindow.__creMiniKitRawTriggerDebugInstalled = true;
}

interface MiniVerifyResult {
  commandPayload: VerifyCommandPayload;
  finalPayload: MiniAppVerifyActionPayload;
  responseChain: MiniAppVerifyActionPayload[];
}

const MINI_VERIFY_TIMEOUT_MS = 20_000;
const MINI_VERIFY_AMBIGUOUS_SETTLE_MS = 1_250;
const MINI_VERIFY_DEFAULT_SETTLE_MS = 50;

function isAmbiguousMiniVerifyError(payload: MiniAppVerifyActionPayload): boolean {
  if (payload.status !== "error") {
    return false;
  }
  return payload.error_code === "verification_rejected" || payload.error_code === "user_rejected";
}

function runMiniVerifyCommand(payload: VerifyCommandInput): Promise<MiniVerifyResult> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("minikit_unavailable: outside_of_worldapp"));
  }

  return new Promise((resolve, reject) => {
    let commandPayload: VerifyCommandPayload | null = null;
    const responseChain: MiniAppVerifyActionPayload[] = [];
    let settleTimer: number | undefined;
    let timeoutTimer: number | undefined;

    const cleanup = () => {
      MiniKit.unsubscribe(ResponseEvent.MiniAppVerifyAction);
      if (settleTimer !== undefined) {
        window.clearTimeout(settleTimer);
      }
      if (timeoutTimer !== undefined) {
        window.clearTimeout(timeoutTimer);
      }
    };

    const finalize = () => {
      const finalPayload = responseChain[responseChain.length - 1];
      cleanup();
      if (!commandPayload) {
        reject(
          new Error(
            "Failed to send verify command. Ensure MiniKit is installed and the verify command is available."
          )
        );
        return;
      }
      if (!finalPayload) {
        reject(new Error("world_id_verify_timeout: no verify response returned from World App."));
        return;
      }
      resolve({
        commandPayload,
        finalPayload,
        responseChain: [...responseChain]
      });
    };

    const scheduleFinalize = (delayMs: number) => {
      if (settleTimer !== undefined) {
        window.clearTimeout(settleTimer);
      }
      settleTimer = window.setTimeout(finalize, delayMs);
    };

    MiniKit.subscribe(ResponseEvent.MiniAppVerifyAction, (response: MiniAppVerifyActionPayload) => {
      responseChain.push(response);
      if (isAmbiguousMiniVerifyError(response)) {
        scheduleFinalize(MINI_VERIFY_AMBIGUOUS_SETTLE_MS);
        return;
      }
      scheduleFinalize(MINI_VERIFY_DEFAULT_SETTLE_MS);
    });

    commandPayload = MiniKit.commands.verify(payload);
    if (!commandPayload) {
      cleanup();
      reject(new Error("minikit_command_unavailable: verify"));
      return;
    }

    timeoutTimer = window.setTimeout(() => {
      cleanup();
      reject(new Error("world_id_verify_timeout: no verify response returned from World App."));
    }, MINI_VERIFY_TIMEOUT_MS);
  });
}

export default function VerifyPage() {
  const activeAccount = useActiveAccount();
  const walletAddress = activeAccount?.address ?? "";
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();
  const worldIdConfig = getWorldIdConfig();
  const miniWorldIdConfigured = worldIdConfig.mini.configured;
  const externalWorldIdConfigured = worldIdConfig.external.configured;

  const [requests, setRequests] = useState<RequestRecord[]>([]);
  const [nodes, setNodes] = useState<RegisteredNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [registeringNode, setRegisteringNode] = useState(false);
  const [sendingHeartbeat, setSendingHeartbeat] = useState(false);
  const [registrationMessage, setRegistrationMessage] = useState<string | null>(null);
  const [verifyingWorldId, setVerifyingWorldId] = useState(false);
  const [worldProofJson, setWorldProofJson] = useState("");
  const [miniKitAvailable, setMiniKitAvailable] = useState(false);
  const [worldIdSession, setWorldIdSession] = useState<WorldIdSession | null>(null);
  const [worldIdDebugLogs, setWorldIdDebugLogs] = useState<WorldIdDebugEntry[]>([]);
  const [miniVerifyMode, setMiniVerifyMode] = useState<MiniVerifyMode>("orb_or_device");
  const miniVerifyInFlightRef = useRef(false);
  const [nodeForm, setNodeForm] = useState<{
    selectedModelFamilies: ModelFamily[];
    stakeAmount: string;
    participationEnabled: boolean;
  }>({
    selectedModelFamilies: ["gpt"],
    stakeAmount: "1000",
    participationEnabled: true
  });

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [requestItems, nodeItems] = await Promise.all([listRequests(), listNodes()]);
      setRequests(requestItems);
      setNodes(nodeItems);
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
    if (!miniWorldIdConfigured || !walletConnected) {
      setMiniKitAvailable(false);
      return;
    }

    try {
      const installResult = installMiniKitWithAppId(worldIdConfig.mini.appId);
      setMiniKitAvailable(isMiniKitInstallUsable(installResult));
    } catch {
      setMiniKitAvailable(false);
    }
  }, [walletConnected, miniWorldIdConfigured, worldIdConfig.mini.appId]);

  const appendWorldIdDebugLog = (event: string, detail?: unknown) => {
    const entry: WorldIdDebugEntry = {
      at: new Date().toISOString(),
      event,
      detail: detail === undefined ? undefined : formatDebugDetail(detail)
    };
    console.info("[world-id-debug]", event, detail ?? "");
    setWorldIdDebugLogs((prev) => [...prev.slice(-59), entry]);
  };

  useEffect(() => {
    installMiniKitRawDebugHook((event, payload) => {
      if (event === "miniapp-verify-action") {
        appendWorldIdDebugLog("mini.verify.raw_event", payload);
      }
    });
  }, [appendWorldIdDebugLog]);

  const worldIdDebugText = useMemo(() => {
    return worldIdDebugLogs
      .map((entry) => (entry.detail ? `${entry.at} ${entry.event} ${entry.detail}` : `${entry.at} ${entry.event}`))
      .join("\n");
  }, [worldIdDebugLogs]);

  const verifyWorldIdWithProof = async (input: {
    proof: Record<string, unknown>;
    sourceLabel: string;
    appId: string;
    action: string;
    clientSource: "miniapp" | "external" | "manual";
  }) => {
    appendWorldIdDebugLog("backend.verify.request", {
      source: input.sourceLabel,
      appId: input.appId,
      action: input.action,
      clientSource: input.clientSource,
      proof: summarizeWorldProof(input.proof)
    });
    try {
      const result = await verifyWorldIdForWallet({
        walletAddress,
        proof: input.proof,
        appId: input.appId,
        action: input.action,
        clientSource: input.clientSource
      });
      appendWorldIdDebugLog("backend.verify.success", {
        profileId: result.session.profileId,
        verificationLevel: result.session.verificationLevel,
        source: result.session.source,
        expiresAt: result.session.expiresAt
      });
      saveWorldIdSession(walletAddress, result.session);
      setWorldIdSession(result.session);
      setRegistrationMessage(
        `${input.sourceLabel} verification succeeded. Session valid until ${new Date(result.session.expiresAt).toLocaleString()}.`
      );
    } catch (error) {
      appendWorldIdDebugLog("backend.verify.error", {
        message: getWorldIdErrorMessage(error),
        raw: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  };

  const onVerifyWorldIdManual = async () => {
    setRegistrationMessage(null);
    setError(null);
    setWorldIdDebugLogs([]);
    appendWorldIdDebugLog("manual.verify.start", {
      appId: worldIdConfig.external.appId,
      action: worldIdConfig.external.action
    });

    if (!walletConnected) {
      setError("Connect wallet before World ID verification.");
      return;
    }
    if (!externalWorldIdConfigured) {
      setError("Missing external World ID config. Set VITE_WORLD_ID_EXTERNAL_APP_ID / VITE_WORLD_ID_EXTERNAL_ACTION.");
      return;
    }

    let parsedProof: Record<string, unknown>;
    try {
      parsedProof = JSON.parse(worldProofJson) as Record<string, unknown>;
      appendWorldIdDebugLog("manual.verify.parsed_proof", summarizeWorldProof(parsedProof));
    } catch {
      setError("World ID proof JSON is invalid.");
      return;
    }

    setVerifyingWorldId(true);
    try {
      await verifyWorldIdWithProof({
        proof: parsedProof,
        sourceLabel: "Manual",
        appId: worldIdConfig.external.appId,
        action: worldIdConfig.external.action,
        clientSource: "manual"
      });
    } catch (err) {
      appendWorldIdDebugLog("manual.verify.error", err instanceof Error ? err.message : String(err));
      setError(getWorldIdErrorMessage(err));
    } finally {
      setVerifyingWorldId(false);
    }
  };

  const onVerifyWorldIdMiniApp = async () => {
    if (miniVerifyInFlightRef.current) {
      appendWorldIdDebugLog("mini.verify.skipped_duplicate_dispatch", { reason: "in_flight" });
      return;
    }
    miniVerifyInFlightRef.current = true;

    const requestedVerificationLevel = buildMiniVerifyLevel(miniVerifyMode);
    setRegistrationMessage(null);
    setError(null);
    setWorldIdDebugLogs([]);
    appendWorldIdDebugLog("mini.verify.start", {
      envMiniAppId: worldIdConfig.mini.appId,
      envMiniAction: worldIdConfig.mini.action,
      selectedVerificationMode: miniVerifyMode,
      requestedVerificationLevel,
      worldApp: readWorldAppDebugContext()
    });

    if (!walletConnected) {
      setError("Connect wallet before World ID verification.");
      return;
    }
    if (!miniWorldIdConfigured) {
      setError("Missing mini app World ID config. Set VITE_WORLD_ID_MINI_APP_ID / VITE_WORLD_ID_MINI_ACTION.");
      return;
    }

    setVerifyingWorldId(true);
    try {
      appendWorldIdDebugLog("mini.install.before", { appId: readMiniKitRuntimeAppId() || null });
      const installResult = installMiniKitWithAppId(worldIdConfig.mini.appId);
      appendWorldIdDebugLog("mini.install.result", {
        ...installResult,
        appIdAfterInstall: readMiniKitRuntimeAppId() || null
      });
      if (!isMiniKitInstallUsable(installResult)) {
        const errorCode = installResult.success ? "unknown" : installResult.errorCode;
        throw new Error(`minikit_unavailable: ${errorCode}`);
      }
      setMiniKitAvailable(true);
      const runtimeMiniAppId = readMiniKitRuntimeAppId();
      const verifyAvailable = isCommandAvailable(Command.Verify);
      appendWorldIdDebugLog("mini.command.availability", {
        verifyAvailable,
        worldAppVersion: MiniKit.deviceProperties.worldAppVersion,
        deviceOS: MiniKit.deviceProperties.deviceOS
      });
      appendWorldIdDebugLog("mini.runtime.state", {
        runtimeMiniAppId,
        miniKitLocation: MiniKit.location ?? null
      });
      if (!verifyAvailable) {
        throw new Error("minikit_command_unavailable: verify");
      }
      if (runtimeMiniAppId && worldIdConfig.mini.appId && runtimeMiniAppId !== worldIdConfig.mini.appId) {
        throw new Error(`world_id_config_mismatch: runtime_app_id=${runtimeMiniAppId}, env_app_id=${worldIdConfig.mini.appId}`);
      }
      const miniAppIdForVerify = runtimeMiniAppId || worldIdConfig.mini.appId;

      const { commandPayload, finalPayload, responseChain } = await runMiniVerifyCommand({
        action: worldIdConfig.mini.action,
        signal: walletAddress,
        verification_level: requestedVerificationLevel
      });
      appendWorldIdDebugLog("mini.verify.command_payload", commandPayload ?? null);
      appendWorldIdDebugLog("mini.verify.response_chain", responseChain);
      appendWorldIdDebugLog(
        "mini.verify.final_payload",
        finalPayload.status === "error" ? finalPayload : summarizeMiniKitPayload(finalPayload)
      );

      const proof = buildWorldProofFromMiniKit(finalPayload);
      if (!proof) {
        throw new Error(`world_id_verify_failed: ${toMiniKitErrorCode(finalPayload)}`);
      }

      await verifyWorldIdWithProof({
        proof,
        sourceLabel: "Mini App",
        appId: miniAppIdForVerify,
        action: worldIdConfig.mini.action,
        clientSource: "miniapp"
      });
    } catch (err) {
      appendWorldIdDebugLog("mini.verify.error", {
        message: getWorldIdErrorMessage(err),
        raw: err instanceof Error ? err.message : String(err)
      });
      setError(getWorldIdErrorMessage(err));
    } finally {
      miniVerifyInFlightRef.current = false;
      setVerifyingWorldId(false);
    }
  };

  const onVerifyWorldIdExternal = async (result: ISuccessResult) => {
    if (!walletConnected) {
      setError("Connect wallet before World ID verification.");
      return;
    }
    setRegistrationMessage(null);
    setError(null);
    setWorldIdDebugLogs([]);
    appendWorldIdDebugLog("external.verify.start", {
      appId: worldIdConfig.external.appId,
      action: worldIdConfig.external.action
    });
    setVerifyingWorldId(true);
    try {
      const proof = buildWorldProofFromIdKit(result);
      appendWorldIdDebugLog("external.verify.proof", summarizeWorldProof(proof));
      await verifyWorldIdWithProof({
        proof,
        sourceLabel: "External Widget",
        appId: worldIdConfig.external.appId,
        action: worldIdConfig.external.action,
        clientSource: "external"
      });
    } catch (err) {
      appendWorldIdDebugLog("external.verify.error", err instanceof Error ? err.message : String(err));
      setError(getWorldIdErrorMessage(err));
      throw err;
    } finally {
      setVerifyingWorldId(false);
    }
  };

  const onWorldIdExternalError = (errorState: IErrorState) => {
    setError(`world_id_widget_error: ${errorState.code}`);
  };

  const onClearWorldId = () => {
    if (!walletConnected) {
      return;
    }
    clearWorldIdSession(walletAddress);
    setWorldIdSession(null);
    setRegistrationMessage("World ID session was cleared for this wallet.");
  };

  const onRegisterNode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setRegistrationMessage(null);

    if (!thirdwebConfigured) {
      setError("Missing VITE_THIRDWEB_CLIENT_ID. Configure dapp/.env and restart.");
      return;
    }
    if (!walletConnected || !activeAccount) {
      setError("Connect wallet before registering a node.");
      return;
    }
    if (nodeForm.selectedModelFamilies.length === 0) {
      setError("Select at least one model family.");
      return;
    }
    if (!worldIdSession?.token) {
      setError("Verify World ID first and obtain a session token.");
      return;
    }

    setRegisteringNode(true);
    setError(null);
    try {
      const challengeResult = await requestNodeChallenge({
        walletAddress,
        selectedModelFamilies: nodeForm.selectedModelFamilies,
        stakeAmount: nodeForm.stakeAmount,
        participationEnabled: nodeForm.participationEnabled,
        worldIdToken: worldIdSession.token
      });
      const challenge = challengeResult.challenge;
      const signature = await signMessage({
        account: activeAccount,
        message: challenge.challengeMessage
      });

      const activated = await activateNodeChallenge({
        challengeId: challenge.challengeId,
        walletAddress,
        signature
      });

      const health = activated.endpointProbe.ok ? "HEALTHY" : `UNHEALTHY (${activated.endpointProbe.error ?? "unknown"})`;
      const lifecycleTx = activated.lifecycleOnchainReceipt?.txHash
        ? `, tx=${activated.lifecycleOnchainReceipt.txHash}`
        : "";
      setRegistrationMessage(
        `Node ${activated.node.nodeId} activated. endpoint=${health}, x402=${challengeResult.paymentReceipt.paymentRef.slice(0, 14)}...${lifecycleTx}`
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRegisteringNode(false);
    }
  };

  const myActiveNode = useMemo(
    () => nodes.find((node) => node.walletAddress.toLowerCase() === walletAddress.toLowerCase() && node.status === "ACTIVE"),
    [nodes, walletAddress]
  );

  const onSendHeartbeat = async () => {
    setRegistrationMessage(null);

    if (!walletConnected || !activeAccount || !myActiveNode) {
      setError("Connect wallet and activate node first.");
      return;
    }
    if (!myActiveNode.endpointUrl) {
      setError("Current node has no endpoint URL.");
      return;
    }

    setSendingHeartbeat(true);
    setError(null);
    try {
      const timestamp = Date.now();
      const heartbeatMessage = buildNodeHeartbeatMessage({
        walletAddress: toLowerAddress(walletAddress),
        endpointUrl: myActiveNode.endpointUrl,
        timestamp
      });
      const signature = await signMessage({
        account: activeAccount,
        message: heartbeatMessage
      });

      const result = await sendNodeHeartbeat({
        walletAddress,
        endpointUrl: myActiveNode.endpointUrl,
        timestamp,
        signature
      });

      const lifecycleTx = result.lifecycleOnchainReceipt?.txHash ? `, tx=${result.lifecycleOnchainReceipt.txHash}` : "";
      setRegistrationMessage(
        `Heartbeat accepted. endpoint=${result.node.endpointStatus}, checkedAt=${result.node.endpointLastCheckedAt ?? "-"}${lifecycleTx}`
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSendingHeartbeat(false);
    }
  };

  const toggleModelFamily = (family: ModelFamily) => {
    setNodeForm((prev) => {
      const exists = prev.selectedModelFamilies.includes(family);
      const selectedModelFamilies = exists
        ? prev.selectedModelFamilies.filter((item) => item !== family)
        : [...prev.selectedModelFamilies, family];

      return {
        ...prev,
        selectedModelFamilies
      };
    });
  };

  return (
    <div className="page-shell">
      <main className="panel">
        <AppNav current="verify" />
        <header className="hero compact">
          <p className="eyebrow">Verifier Participation</p>
          <h1>Operator Verify Settings</h1>
          <p>
            DON-like flow: create registration challenge, sign with wallet, then activate node. Node ID is fixed to your
            wallet address.
          </p>
          <div className="wallet-row">
            {thirdwebConfigured ? (
              <ConnectButton
                client={thirdwebClient}
                connectButton={{ className: "wallet-connect-btn", label: "Connect Wallet" }}
              />
            ) : (
              <p className="config-warning">
                Missing <code>VITE_THIRDWEB_CLIENT_ID</code>. Wallet login is disabled.
              </p>
            )}
            {walletConnected && <p className="wallet-info mono">Connected: {walletAddress}</p>}
          </div>
          <div className="inline-row">
            <Link to="/" className="text-link">
              Back to Request
            </Link>
            <button type="button" className="secondary" onClick={load}>
              Refresh List
            </button>
          </div>
        </header>

        <section className="status-card">
          <h2>World ID Verification</h2>
          <p>
            Verify with Mini App (World App) or External Widget. A wallet-bound World ID session token is required before node
            activation.
          </p>
          <p className="config-warning">
            Mini App: {worldIdConfig.mini.appId || "-"} / {worldIdConfig.mini.action || "-"}
          </p>
          <p className="config-warning">
            External: {worldIdConfig.external.appId || "-"} / {worldIdConfig.external.action || "-"}
          </p>
          <div className="action-row">
            <label>
              Mini Level
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
              disabled={!walletConnected || verifyingWorldId || !miniWorldIdConfigured}
            >
              {verifyingWorldId ? "Verifying..." : "Verify in World Mini App"}
            </button>
            {externalWorldIdConfigured ? (
              <IDKitWidget
                app_id={worldIdConfig.external.appId}
                action={worldIdConfig.external.action}
                signal={walletAddress}
                verification_level={IDKitVerificationLevel.Device}
                handleVerify={onVerifyWorldIdExternal}
                onSuccess={() => undefined}
                onError={onWorldIdExternalError}
              >
                {({ open }: { open: () => void }) => (
                  <button type="button" className="secondary" onClick={open} disabled={!walletConnected || verifyingWorldId}>
                    Verify with External Widget
                  </button>
                )}
              </IDKitWidget>
            ) : (
              <button type="button" className="secondary" disabled>
                Verify with External Widget
              </button>
            )}
            <button type="button" className="secondary" onClick={onClearWorldId} disabled={!walletConnected}>
              Clear Session
            </button>
          </div>
          {!miniKitAvailable && (
            <p className="config-warning">
              Mini App verification is available only inside World App. For desktop browser testing, use External Widget.
            </p>
          )}
          <details className="manual-world-proof">
            <summary>Manual proof JSON (simulator fallback)</summary>
            <label>
              World ID Proof JSON
              <textarea
                value={worldProofJson}
                onChange={(event) => setWorldProofJson(event.target.value)}
                rows={7}
                placeholder='{"merkle_root":"0x...","nullifier_hash":"0x...","proof":"0x...","verification_level":"device"}'
              />
            </label>
            <div className="action-row">
              <button
                type="button"
                className="secondary"
                onClick={onVerifyWorldIdManual}
                disabled={!walletConnected || verifyingWorldId || !externalWorldIdConfigured}
              >
                {verifyingWorldId ? "Verifying..." : "Verify Manual Proof"}
              </button>
            </div>
          </details>
          {worldIdSession ? (
            <p>
              Session token active until {new Date(worldIdSession.expiresAt).toLocaleString()} ({worldIdSession.source}).
            </p>
          ) : (
            <p>No active World ID session for this wallet.</p>
          )}
          <details className="manual-world-proof">
            <summary>World ID debug logs ({worldIdDebugLogs.length})</summary>
            <div className="action-row">
              <button
                type="button"
                className="secondary"
                onClick={() => setWorldIdDebugLogs([])}
                disabled={worldIdDebugLogs.length === 0}
              >
                Clear Debug Logs
              </button>
            </div>
            <textarea readOnly rows={10} value={worldIdDebugText || "No logs yet."} />
          </details>
        </section>

        <section className="status-card">
          <h2>Register / Update Node</h2>
          <form onSubmit={onRegisterNode} className="form-grid compact-form">
            <p className="config-warning">Node ID is auto-assigned as your wallet address.</p>
            <label>
              Stake Amount (token unit)
              <input
                value={nodeForm.stakeAmount}
                onChange={(event) => setNodeForm((prev) => ({ ...prev, stakeAmount: event.target.value }))}
                inputMode="numeric"
                pattern="[0-9]+"
                required
              />
            </label>
            <fieldset className="family-picker">
              <legend>LLM Family Participation (select 1~4)</legend>
              <div className="family-grid">
                {MODEL_FAMILIES.map((family) => (
                  <label key={family} className="family-option">
                    <input
                      type="checkbox"
                      checked={nodeForm.selectedModelFamilies.includes(family)}
                      onChange={() => toggleModelFamily(family)}
                    />
                    <span>{family}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <label className="inline-check">
              <input
                type="checkbox"
                checked={nodeForm.participationEnabled}
                onChange={(event) => setNodeForm((prev) => ({ ...prev, participationEnabled: event.target.checked }))}
              />
              <span>Participate in auto-matching for new requests</span>
            </label>
            <p className="config-warning">
              Model Name / Endpoint URL are auto-assigned by server mapping for this wallet.
            </p>
            <div className="action-row">
              <button type="submit" disabled={!walletConnected || registeringNode || !thirdwebConfigured}>
                {registeringNode ? "Signing / Activating..." : "Sign And Activate Node"}
              </button>
            </div>
          </form>
          {myActiveNode ? (
            <div>
              <p>
                <strong>My Active Node:</strong> {myActiveNode.nodeId} ({myActiveNode.selectedModelFamilies.join(", ")}
                {" / "}
                {myActiveNode.modelName}) | stake={myActiveNode.stakeAmount} |{" "}
                {myActiveNode.participationEnabled ? "participating" : "paused"}
              </p>
              <p>
                endpoint={myActiveNode.endpointUrl ?? "-"} | health={formatEndpointHealth(myActiveNode)}
              </p>
              <div className="action-row">
                <button
                  type="button"
                  className="secondary"
                  onClick={onSendHeartbeat}
                  disabled={sendingHeartbeat || !walletConnected || !myActiveNode.endpointUrl}
                >
                  {sendingHeartbeat ? "Sending Heartbeat..." : "Send Signed Heartbeat"}
                </button>
              </div>
            </div>
          ) : (
            <p>No active node for this wallet yet.</p>
          )}
          {registrationMessage && <p>{registrationMessage}</p>}
        </section>

        <section className="status-card">
          <h2>Auto Verification Flow</h2>
          <p>Manual verification is disabled in this page. Verification runs automatically on request submission.</p>
          <p>
            Flow: <code>request submit - x402 check - node match - consensus - on-chain finalize</code>
          </p>
        </section>

        <section className="status-card">
          <h2>Recent Requests</h2>
          <p className="config-warning">This list is loaded from on-chain finalization events for the active registry.</p>
          {loading ? (
            <p>Loading requests...</p>
          ) : requests.length === 0 ? (
            <p>No requests yet. Create one in the Request page.</p>
          ) : (
            <div className="request-table">
              <div className="request-head">
                <span>Request</span>
                <span>Status</span>
                <span>Attempts</span>
                <span>Updated</span>
                <span>Action</span>
              </div>
              {requests.map((record) => {
                return (
                  <div key={record.requestId} className="request-row">
                    <span className="mono small">{record.requestId}</span>
                    <span className={`status-badge ${record.status === "FINALIZED" ? "ok" : "warn"}`}>
                      {record.status}
                    </span>
                    <span>{record.runAttempts}/2</span>
                    <span>{new Date(record.updatedAt).toLocaleString()}</span>
                    <span className="inline-row">
                      <Link className="text-link" to={`/result/${encodeURIComponent(record.requestId)}`}>
                        Result
                      </Link>
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="status-card">
          <h2>Active Nodes</h2>
          <p className="config-warning">
            This list is reconstructed from on-chain node lifecycle events (activation/heartbeat).
          </p>
          {nodes.length === 0 ? (
            <p>No registered nodes. Default mock 4 nodes will be used unless server requires registered nodes.</p>
          ) : (
            <div className="request-table">
              <div className="request-head">
                <span>Node ID</span>
                <span>Models / Stake</span>
                <span>Endpoint</span>
                <span>Health</span>
                <span>Wallet</span>
                <span>Updated</span>
              </div>
              {nodes.map((node) => (
                <div key={node.registrationId} className="request-row">
                  <span className="mono small">{node.nodeId}</span>
                  <span>
                    {node.selectedModelFamilies.join(", ")} / stake={node.stakeAmount}
                  </span>
                  <span className="mono small">{node.endpointUrl ?? "-"}</span>
                  <span className={`status-badge ${node.endpointStatus === "HEALTHY" ? "ok" : "warn"}`}>
                    {node.endpointStatus}
                  </span>
                  <span className="mono small">{node.walletAddress}</span>
                  <span>{new Date(node.updatedAt).toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        {error && <p className="error-text">{error}</p>}
      </main>
    </div>
  );
}

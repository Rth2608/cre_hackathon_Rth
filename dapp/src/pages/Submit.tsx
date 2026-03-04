import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ConnectButton, useActiveAccount, useActiveWalletChain, useWalletBalance } from "thirdweb/react";
import AppNav from "../components/AppNav";
import { createRequestForWallet, type MarketRequestInput, type WorldIdSession } from "../lib/api";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";
import { clearWorldIdSession, getWorldIdConfig, loadWorldIdSession } from "../lib/worldId";
import {
  fetchWorldChainVirtualBalances,
  getWorldChainVirtualConfig,
  type WorldChainVirtualBalanceSnapshot
} from "../lib/worldChain";

const defaultForm: MarketRequestInput = {
  question: "Will BTC close above $100,000 on 2026-12-31 UTC?",
  description: "Prediction market validation demo request",
  sourceUrls: [
    "https://www.reuters.com/world/us/example-story",
    "https://www.bloomberg.com/news/articles/example-story"
  ],
  resolutionCriteria: "Use Reuters or Bloomberg market close report as canonical source.",
  submitterAddress: ""
};

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

export default function SubmitPage() {
  const navigate = useNavigate();
  const activeAccount = useActiveAccount();
  const activeChain = useActiveWalletChain();
  const walletAddress = activeAccount?.address ?? "";
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();
  const { data: walletBalance, isLoading: walletBalanceLoading, isError: walletBalanceError } = useWalletBalance({
    chain: activeChain ?? undefined,
    address: walletConnected ? walletAddress : undefined,
    client: thirdwebClient
  });
  const worldIdConfig = getWorldIdConfig();
  const worldIdConfigured = worldIdConfig.mini.configured || worldIdConfig.external.configured;
  const worldChainVirtualConfig = getWorldChainVirtualConfig();

  const [form, setForm] = useState(defaultForm);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [worldIdSession, setWorldIdSession] = useState<WorldIdSession | null>(null);
  const [worldChainBalances, setWorldChainBalances] = useState<WorldChainVirtualBalanceSnapshot | null>(null);
  const [worldChainBalancesLoading, setWorldChainBalancesLoading] = useState(false);
  const [worldChainBalancesError, setWorldChainBalancesError] = useState<string | null>(null);

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

  const nativeBalanceText =
    walletBalanceLoading
      ? "Loading..."
      : walletBalance
        ? `${walletBalance.displayValue} ${walletBalance.symbol}`
        : walletBalanceError
          ? "Failed to load"
          : "-";
  const chainText = activeChain ? `${activeChain.name} (id: ${activeChain.id})` : "Not connected";
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
  const requestSubmitReady = requestCreateReady && Boolean(worldIdSession?.token);
  const requestSubmitReason = !walletConnected
    ? "Connect wallet"
    : !thirdwebConfigured
      ? "Set VITE_THIRDWEB_CLIENT_ID"
      : !worldIdConfigured
        ? "Configure World ID app/action env"
          : !worldIdSession?.token
            ? "Verify World ID in Verify page"
            : "Ready";
  const worldChainNativeBalanceText = worldChainBalancesLoading
    ? "Loading..."
    : worldChainBalances?.native
      ? `${worldChainBalances.native.displayValue} ${worldChainBalances.native.symbol}`
      : worldChainBalancesError
        ? "Failed to load"
        : "-";

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    if (!thirdwebConfigured) {
      setError("Missing VITE_THIRDWEB_CLIENT_ID. Configure dapp/.env and restart the dev server.");
      setSubmitting(false);
      return;
    }

    if (!walletConnected) {
      setError("Connect wallet before creating a request.");
      setSubmitting(false);
      return;
    }
    if (!worldIdConfigured) {
      setError("World ID is not configured. Set VITE_WORLD_ID_* values and redeploy frontend.");
      setSubmitting(false);
      return;
    }
    if (!worldIdSession?.token) {
      setError("Verify World ID in the Verify page before creating a request.");
      setSubmitting(false);
      return;
    }

    try {
      const created = await createRequestForWallet(form, walletAddress, worldIdSession.token);
      // Request creation consumes World ID token on server. Force re-verify for next request.
      clearWorldIdSession(walletAddress);
      setWorldIdSession(null);
      setRequestId(created.requestId);
      navigate(`/result/${encodeURIComponent(created.requestId)}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("world_id_token_")) {
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
          <p className="eyebrow">CRE + DON Consensus Demo</p>
          <h1>Submit Market Verification Request</h1>
          <p>
            Enter market question, evidence URLs, and resolver criteria. On submit, the orchestrator immediately
            matches verifier nodes, computes consensus, and finalizes on-chain.
          </p>
          <div className="hero-chips">
            <span className="chip">4 DON Nodes</span>
            <span className="chip">Weighted Consensus</span>
            <span className="chip">Tenderly Finalization</span>
          </div>
          <div className="wallet-row">
            {thirdwebConfigured ? (
              <ConnectButton
                client={thirdwebClient}
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
                Balance: {nativeBalanceText}
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
              <p className="snapshot-label">World Chain Sepolia</p>
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
                <p className="config-warning">
                  Set <code>VITE_WORLDCHAIN_VIRTUAL_TOKEN_ADDRESSES</code> to show ERC20 test token balances.
                </p>
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
            <button type="submit" disabled={submitting || !walletConnected || !thirdwebConfigured || !worldIdSession?.token}>
              {submitting ? "Submitting..." : "Submit And Verify"}
            </button>
          </div>
        </form>

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

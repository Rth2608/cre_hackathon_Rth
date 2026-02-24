import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ConnectButton, useActiveAccount } from "thirdweb/react";
import AppNav from "../components/AppNav";
import { createRequestForWallet, type MarketRequestInput } from "../lib/api";
import { isThirdwebClientConfigured, thirdwebClient } from "../lib/thirdweb";

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

export default function SubmitPage() {
  const navigate = useNavigate();
  const activeAccount = useActiveAccount();
  const walletAddress = activeAccount?.address ?? "";
  const walletConnected = walletAddress.length > 0;
  const thirdwebConfigured = isThirdwebClientConfigured();

  const [form, setForm] = useState(defaultForm);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

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

    try {
      const created = await createRequestForWallet(form, walletAddress);
      setRequestId(created.requestId);
      navigate(`/result/${encodeURIComponent(created.requestId)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
          </div>
        </header>

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
            <button type="submit" disabled={submitting || !walletConnected || !thirdwebConfigured}>
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

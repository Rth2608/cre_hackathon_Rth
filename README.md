# CRE Prediction Market Demo

End-to-end demo for multi-DON style verification:

1. User submits a prediction market request from dApp.
2. Orchestrator validates sources, applies x402 payment guard, and auto-matches verifier nodes.
3. Consensus engine computes weighted result.
4. Coordinator submits final result to on-chain registry (Tenderly Virtual Network target).
5. dApp shows verdict, score, report hash, tx hash.

## Monorepo layout

- `contracts/`: Solidity registry + Foundry deploy/test files
- `orchestrator/`: API server + CRE workflow runner + consensus engine
- `dapp/`: React UI for submit/result pages

## Prerequisites

- Bun 1.0+
- Node.js 20+ (recommended for broader tool compatibility)
- Foundry (`forge`, `cast`) for contract compile/deploy/test

## Quick start

### 1) Orchestrator

```bash
cd orchestrator
cp .env.example .env
bun install
bun run dev
```

Server default: `http://localhost:8787`

### 2) dApp

```bash
cd dapp
cp .env.example .env
# set VITE_THIRDWEB_CLIENT_ID, VITE_WORLD_ID_APP_ID, VITE_WORLD_ID_ACTION in .env
bun install
bun run dev
```

dApp default: `http://localhost:5173`

Pages:

- `/` request submission (auto verification trigger)
- `/verify` verifier node registration/stake/participation settings
- `/result/:requestId` verification result view
- `/por` PoR dashboard

Notes:

- In local/SSH-tunnel dev, keep `VITE_API_BASE_URL` unset.
- Vite dev server proxies `/api` and `/healthz` to `VITE_API_PROXY_TARGET` (default `http://127.0.0.1:8787`).
- This avoids browser-side `127.0.0.1:8787` connection errors when frontend is accessed remotely.
- `VITE_THIRDWEB_CLIENT_ID` is required for wallet login (`ConnectButton`).

### dApp-only cloud deploy (Vercel)

Use this when you want a stable HTTPS URL for World Mini App while keeping orchestrator separate.

1. Prepare frontend env for production:
   - `VITE_API_BASE_URL=https://<public-orchestrator-url>`
   - `VITE_THIRDWEB_CLIENT_ID=<thirdweb client id>`
   - `VITE_WORLD_ID_APP_ID=<world app id>`
   - `VITE_WORLD_ID_ACTION=<world action>`
2. Import repo into Vercel and set **Root Directory** to `dapp`.
3. Keep framework as Vite default. Build command remains `vite build`.
4. SPA routes are handled via `dapp/vercel.json` rewrite to `index.html`.
5. After deployment, use the production URL `https://<project>.vercel.app` as:
   - World Mini App `App URL`
   - thirdweb allowed domain entry

Custom fixed domain (optional):

1. Vercel Dashboard -> Project -> `Settings` -> `Domains`.
2. Add your domain (e.g. `app.example.com`).
3. Configure DNS records Vercel shows (typically `CNAME` or `A`).
4. Set domain as Primary and use that URL for World/thirdweb allowlists.

Important:

- Vercel hosts only the frontend in this setup.
- Orchestrator must be publicly reachable over HTTPS from the browser.
- Local worker endpoints like `http://127.0.0.1:19001` are not reachable from cloud runtime.

### Orchestrator cloud deploy (Railway, Docker)

Use this to get the `VITE_API_BASE_URL` value for Vercel.

1. Push this repository to GitHub (includes `orchestrator/Dockerfile`).
2. Railway -> `New Project` -> `Deploy from GitHub repo`.
3. Set **Root Directory** to `orchestrator`.
4. Railway will build/run Docker automatically.
5. In Railway `Variables`, set at least:
   - `PORT=8787`
   - `RPC_URL`
   - `CHAIN_ID`
   - `CONTRACT_ADDRESS`
   - `COORDINATOR_PRIVATE_KEY`
   - `USE_MOCK_ONCHAIN` (`false` for real finalize, `true` for mock demo)
   - `WORLD_ID_APP_ID`
   - `WORLD_ID_ACTION`
   - `ASSUME_WORLD_ID_VERIFIED=false`
   - `WORLD_ID_VERIFY_API_V4_BASE_URL=https://developer.world.org/api/v4/verify`
   - `WORLD_ID_RP_ID=<rp_xxx (required for v4 payload verify)>`
6. For cloud demo stability (no local worker dependency), also set:
   - `DON_DISTRIBUTED_MODE=false`
   - `NODE_ENDPOINT_VERIFY_ENABLED=false`
   - `ALLOW_DEFAULT_NODES=true`
   - `REQUIRE_REGISTERED_NODES=false`
7. Confirm health endpoint:
   - `https://<railway-service-url>/healthz`

Then set Vercel env:

- `VITE_API_BASE_URL=https://<railway-service-url>`

### 3) Contracts (Foundry)

```bash
cd contracts
cp .env.example .env
forge build
forge test
forge script script/Deploy.s.sol:Deploy --rpc-url $RPC_URL --broadcast
# DON bundle registry deploy (optional)
forge script script/DeployDonConsensus.s.sol:DeployDonConsensus --rpc-url $RPC_URL --broadcast
```

### 4) Automated Redeploy (disable old + deploy new + env sync)

On EVM networks, you cannot truly "delete" a deployed contract.  
This project provides an automation script that:

1. Disables the old registry by setting coordinator to `0x...dEaD` (optional)
2. Deploys a new contract (`MarketVerificationRegistry` or `DonConsensusRegistrySkeleton`)
3. Updates `orchestrator/.env` (`RPC_URL`, `CHAIN_ID`, `CONTRACT_ADDRESS`, and DON flags when applicable)
4. (DON profile) optionally auto-whitelists default operator addresses onchain

```bash
# required: contracts/.env with RPC_URL, PRIVATE_KEY, COORDINATOR_ADDRESS
bash scripts/redeploy_registry.sh
```

Deploy DON profile:

```bash
DEPLOY_PROFILE=don bash scripts/redeploy_registry.sh
```

`DEPLOY_PROFILE=don` deploy path uses `forge ... --via-ir` automatically to avoid Solidity "stack too deep" errors in bundle finalize logic.

Optional runtime variables:

- `DEPLOY_PROFILE=legacy|don` (default: `legacy`)
- `OLD_CONTRACT_ADDRESS=0x...` (if omitted, reads `orchestrator/.env` `CONTRACT_ADDRESS`)
- `DISABLE_OLD_CONTRACT=false` (skip old contract disable step)
- `OLD_OWNER_PRIVATE_KEY=0x...` (if old contract owner key is different)
- `CONTRACTS_ENV_FILE=contracts/.env`
- `ORCHESTRATOR_ENV_FILE=orchestrator/.env`
- `AUTO_ALLOW_DON_OPERATORS=true|false` (default: `true` for `DEPLOY_PROFILE=don`)
- `DON_ALLOWLIST_OPERATORS=0x...,0x...` (comma/newline separated, optional override)

Behavior notes:

- `DEPLOY_PROFILE=don`: sets `USE_DON_SIGNED_REPORTS=true`, `USE_DON_BUNDLE_FINALIZE=true`
- `DEPLOY_PROFILE=legacy`: sets those DON flags back to `false`

## Orchestrator REST API

- `POST /api/requests` (create + auto-run verification)
- `GET /api/requests/:requestId`
- `POST /api/requests/:requestId/run-verification` (optional manual rerun/admin fallback)
- `GET /api/requests/:requestId/report`
- `GET /api/nodes`
- `POST /api/world-id/verify`
- `POST /api/nodes/register`
- `POST /api/nodes/challenge`
- `POST /api/nodes/activate`
- `POST /api/nodes/heartbeat`
- `GET /api/por/status`

## Mock behavior and consensus

- Node weights: equal among active responders
- Score per node: `PASS => +confidence`, `FAIL => -confidence`
- Quorum:
  - `>= 3` responders: consensus computed (weights re-normalized)
  - `< 3` responders: `FAILED_NO_QUORUM`
- Final verdict: `aggregateScore >= 0.6` => `PASS`, otherwise `FAIL`

### Node registration + x402 (current stage)

- Node registration is wallet-bound (`x-wallet-address` header + payload wallet must match).
- `nodeId` is auto-assigned to the normalized wallet address (user input not required).
- World ID gate:
  - `ASSUME_WORLD_ID_VERIFIED=false` (recommended): `/api/world-id/verify` must succeed first.
  - server returns a session token, and node registration/challenge must include `x-world-id-token`.
  - `ASSUME_WORLD_ID_VERIFIED=true` keeps a demo bypass path.
  - Verify page supports both:
    - `Verify in World Mini App` (MiniKit, inside World App)
    - `Verify with External Widget` (IDKit, regular browser)
    - manual proof JSON input as simulator fallback
- x402 gate is enabled with `X402_ENABLED=true`.
  - `POST /api/requests` requires payment header and auto-runs verification.
  - `POST /api/nodes/register` requires payment header
  - `POST /api/requests/:requestId/run-verification` also requires payment header (if used)
- Node matching filters by:
  - `participationEnabled=true`
  - `stakeAmount >= MIN_NODE_STAKE`
  - selected model family coverage (`gpt/gemini/claude/grok`)
- `REQUIRE_REGISTERED_NODES=true` enforces minimum 3 eligible registered nodes.
- `ALLOW_DEFAULT_NODES=true` lets server fall back to default mock 4 nodes when no eligible operator nodes are available.
- Current implementation uses mock settlement references for x402 and is designed to be swapped with real facilitator verification later.

### DON worker endpoints

Each verifier worker node exposes:

- `GET /healthz`
- `POST /verify` (returns `report` + `signedReport` + `executionReceipt`)
- `POST /sign-bundle-approval`
- `POST /sign-consensus-bundle`

Worker launcher script:

- `scripts/start_don_workers.sh`
- optional `DON_WORKER_BASE_PORT` (default `19001`)
  - example: `DON_WORKER_BASE_PORT=19101 bash scripts/start_don_workers.sh`

For distributed DON-like operation, use:

- `USE_DON_SIGNED_REPORTS=true`
- `NODE_ENDPOINT_VERIFY_ENABLED=true`
- `NODE_ENDPOINT_REQUIRE_SIGNED_REPORTS=true`
- `DON_ENDPOINT_BUNDLE_SIGNING_ENABLED=true`
- `NODE_ENDPOINT_VERIFY_FALLBACK_MOCK=false`
- `ALLOW_DEFAULT_NODES=false`

## Runtime artifacts

For each request:

- `orchestrator/reports/artifacts/<requestId>/request.json`
- `orchestrator/reports/artifacts/<requestId>/node-reports.json`
- `orchestrator/reports/artifacts/<requestId>/consensus.json`
- `orchestrator/reports/artifacts/<requestId>/final-report.json`
- `orchestrator/reports/<requestId>.json`

## Tenderly integration

The orchestrator reads chain settings from `orchestrator/.env`:

- `RPC_URL`
- `CONTRACT_ADDRESS`
- `COORDINATOR_PRIVATE_KEY`
- `CHAIN_ID` (optional)
- `TENDERLY_TX_BASE_URL` (optional, used for clickable tx links)
- `USE_DON_BUNDLE_FINALIZE` (optional, submit `finalizeWithBundle` instead of legacy finalize)
- `USE_DON_SIGNED_REPORTS` (optional, require EIP-712 signed operator reports before consensus)
- `DON_DISTRIBUTED_MODE` (default auto, when true: endpoint/registered-node requirements become strict by default)
- `NODE_ENDPOINT_VERIFY_ENABLED` (default `false`, call registered worker endpoints)
- `NODE_ENDPOINT_REQUIRE_SIGNED_REPORTS` (default `true`, require signed report + execution receipt)
- `NODE_ENDPOINT_VERIFY_PATH` (default `/verify`)
- `NODE_ENDPOINT_VERIFY_TIMEOUT_MS` (default `8000`)
- `NODE_ENDPOINT_VERIFY_FALLBACK_MOCK` (default `false`)
- `NODE_ENDPOINT_BUNDLE_APPROVAL_PATH` (default `/sign-bundle-approval`)
- `NODE_ENDPOINT_LEADER_SIGN_PATH` (default `/sign-consensus-bundle`)
- `DON_ENDPOINT_BUNDLE_SIGNING_ENABLED` (default `true`, collect bundle signatures from workers)
- `WORLD_ID_APP_ID` (required when `ASSUME_WORLD_ID_VERIFIED=false`)
- `WORLD_ID_ACTION` (required when `ASSUME_WORLD_ID_VERIFIED=false`)
- `WORLD_ID_VERIFY_API_V4_BASE_URL` (default `https://developer.world.org/api/v4/verify`)
- `WORLD_ID_RP_ID` (v4 route id, e.g. `rp_xxx`; required for strict World ID 4.0 verify path)
- `WORLD_ID_VERIFY_TIMEOUT_MS` (default `8000`)
- `WORLD_ID_SESSION_TTL_SECONDS` (default `86400`)
- `ONCHAIN_READ_ENABLED` (default `true`, read requests/nodes from contract events)
- `ONCHAIN_READ_STRICT` (default `true`, fail API read if chain query fails instead of fallback local DB)
- `ONCHAIN_LOG_FROM_BLOCK` (optional, default `0`, set start block for event scans)
- `ONCHAIN_MAX_REQUESTS` (optional, default `100`, max request rows returned from on-chain events)
- `POR_ONCHAIN_READ_ENABLED` (default `true`, read PoR dashboard from `PorProofRecorded` on-chain events)
- `POR_ONCHAIN_READ_STRICT` (default `false`, fail `/api/por/status` if on-chain query fails)
- `POR_ONCHAIN_AUTO_RECORD_ENABLED` (default `true`, auto-record PoR snapshot after finalized verification)
- `POR_ONCHAIN_AUTO_RECORD_STRICT` (default `false`, fail request flow if PoR auto-record tx fails)
- `POR_AUTO_DELTA_ASSETS_MICROUSDC` / `POR_AUTO_DELTA_LIABILITIES_MICROUSDC` (auto increment per epoch)

If `USE_MOCK_ONCHAIN=true`, orchestrator returns a deterministic mock receipt instead of sending a transaction.

## Contract roles

- `owner` (deployer): can update coordinator via `setCoordinator` and transfer ownership.
- `coordinator`: can call `finalizeVerification`/`finalizeWithBundle`, `recordNodeLifecycle`, and `recordPorProof`.

## PoR on-chain flow (updated)

- The dashboard (`/por`) now reads PoR snapshots from on-chain `PorProofRecorded` events when enabled.
- If no on-chain PoR event exists yet, API falls back to file/env mock values.
- After each successful verification finalization, orchestrator auto-submits one PoR proof epoch:
  - first epoch uses `POR_*` base values,
  - next epochs increment by `POR_AUTO_DELTA_*`.

## CRE CLI integration

By default, workflow is executed in-process and still follows CRE step structure.

Optional external command mode:

- `CRE_CLI_ENABLED=true`
- `CRE_COMMAND=cre`
- `CRE_ARGS=workflow run`

The external command runs before local deterministic node execution and is logged in run summary.

## DON Signature Flow (updated)

This repo includes a DON-style EIP-712 path:

- EIP-712 types + signature verification helpers: `orchestrator/src/donSignatures.ts`
- Worker-side signed report generation: `orchestrator/src/nodeWorker.ts`
- Quorum validation + bundle preparation: `orchestrator/src/donConsensus.ts`
- Endpoint dispatch + distributed bundle signature collection: `orchestrator/src/endpointNodes.ts`
- ABI exports for both finalization modes: `orchestrator/src/contractAbi.ts`
- Optional on-chain bundle submission path: `orchestrator/src/onchainWriter.ts`
- Solidity bundle registry with on-chain signature checks: `contracts/src/DonConsensusRegistrySkeleton.sol`

Enable the DON path with:

```bash
USE_DON_SIGNED_REPORTS=true
USE_DON_BUNDLE_FINALIZE=true
```

Relevant optional env:

- `NODE_ENDPOINT_REQUIRE_SIGNED_REPORTS` (default `true`)
- `DON_ENDPOINT_BUNDLE_SIGNING_ENABLED` (default `true`)
- `NODE_ENDPOINT_BUNDLE_APPROVAL_PATH`, `NODE_ENDPOINT_LEADER_SIGN_PATH`
- `DON_LEADER_OPERATOR`
- `DON_PROMPT_TEMPLATE_HASH`
- `DON_DOMAIN_NAME`, `DON_DOMAIN_VERSION`, `DON_VERIFIER_CONTRACT`, `DON_CONSENSUS_ROUND`
- fallback-only (non-distributed signing): `DON_OPERATOR_PRIVATE_KEYS_JSON`, `DON_LEADER_PRIVATE_KEY`
- worker-only: `WORKER_PRIVATE_KEY` (must match `WORKER_OPERATOR_ADDRESS`)

On-chain bundle verification enforces:

- leader EIP-712 signature over `ConsensusBundle`
- operator EIP-712 approval signatures over `OperatorApproval(bundleHash, requestId, round)`
- owner-managed operator allowlist

Before using `USE_DON_BUNDLE_FINALIZE=true` on a real network:

1. Deploy `DonConsensusRegistrySkeleton` (`contracts/script/DeployDonConsensus.s.sol`).
2. Set `CONTRACT_ADDRESS` to that deployment.
3. Allow operators via `setOperatorPermission` (or `setOperatorPermissions`) from owner account.

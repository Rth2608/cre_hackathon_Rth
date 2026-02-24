# CRE Prediction Market Demo - Architecture

This document maps the current architecture in this repository (`contracts`, `orchestrator`, `dapp`) with multiple diagrams.

## 1) System Context

```mermaid
flowchart LR
    U["End User / Operator<br/>Wallet + Browser"]
    TW["Thirdweb SDK / Wallet Infra"]
    D["DApp<br/>React + Vite<br/>routes: /, /verify, /result/:id, /por"]
    O["Orchestrator API<br/>Bun server :8787"]
    W["DON Worker Nodes<br/>nodeWorker.ts<br/>/verify /sign-*"]
    C["On-chain Registry Contract<br/>MarketVerificationRegistry or<br/>DonConsensusRegistrySkeleton"]
    RPC["JSON-RPC / Tenderly"]
    FS["Local JSON Storage + Artifacts<br/>orchestrator/data + reports"]

    U -->|"submit request / verify node / view result"| D
    D -->|"wallet connect + sign challenge/heartbeat"| TW
    D -->|"/api/*"| O
    O -->|"dispatch verification + bundle signatures"| W
    O -->|"finalize + lifecycle + PoR tx"| RPC
    RPC --> C
    O -->|"read/write requests,nodes,reports"| FS
    O -->|"event scan (finalization,lifecycle,PoR)"| RPC
    C -->|"logs"| RPC
```

## 2) Orchestrator Component View

```mermaid
flowchart TB
    subgraph API["API Layer (server.ts)"]
      R1["POST /api/requests"]
      R2["POST /api/requests/:id/run-verification"]
      R3["GET /api/requests /:id /:id/report"]
      R4["POST /api/nodes/challenge activate heartbeat"]
      R5["GET /api/nodes"]
      R6["GET /api/por/status"]
    end

    subgraph Guard["Guards + Validation"]
      X["x402.ts<br/>enforceX402Payment"]
      V["validator.ts<br/>allowlist + schema checks"]
    end

    subgraph NodeMgmt["Node Registry + Matching"]
      NR["nodeRegistry.ts<br/>nodes.json + challenge flow"]
      M["matcher.ts<br/>stake/model/health filters"]
    end

    subgraph Workflow["Verification Workflow (creRunner.ts)"]
      WF1["validate_input"]
      WF2["dispatch_nodes"]
      WF3["collect_reports"]
      WF4["compute_consensus"]
      WF5["persist_offchain_report"]
      WF6["submit_onchain"]
      WF7["emit_run_summary"]
      EP["endpointNodes.ts<br/>/verify dispatch + bundle signature collection"]
      MK["mockNodes.ts<br/>deterministic mock execution"]
      DR["donRuntime.ts<br/>signed reports + execution receipts"]
      DC["donConsensus.ts<br/>quorum + bundle skeleton"]
      CS["consensus.ts<br/>weighted scoring"]
    end

    subgraph Chain["On-chain Adapters"]
      OW["onchainWriter.ts"]
      OR["onchainReader.ts"]
      POR["por.ts"]
    end

    subgraph Persist["Persistence"]
      ST["storage.ts<br/>requests.json"]
      ART["reports/artifacts/:requestId/*.json"]
    end

    API --> X
    API --> V
    API --> NR
    API --> OR
    API --> POR

    API --> M
    M --> WF1
    WF1 --> WF2 --> WF3 --> WF4 --> WF5 --> WF6 --> WF7

    WF2 --> EP
    WF2 --> MK
    WF2 --> DR
    WF4 --> DC
    WF4 --> CS
    WF6 --> OW

    API --> ST
    WF5 --> ART
    API --> ART
```

## 3) Request Lifecycle (Auto Verification)

```mermaid
sequenceDiagram
    participant User as User (Submit Page)
    participant DApp as dApp
    participant API as Orchestrator /api/requests
    participant X402 as x402 Guard
    participant Val as Validator
    participant Match as Node Registry + Matcher
    participant Workflow as runCreWorkflow
    participant Nodes as Runtime Nodes (endpoint or mock)
    participant Cons as Consensus Engine
    participant Chain as onchainWriter
    participant C as Registry Contract
    participant Por as PoR Auto Recorder

    User->>DApp: Submit form (wallet connected)
    DApp->>API: POST /api/requests + x-wallet-address + payment-signature
    API->>Val: validateMarketRequest()
    API->>X402: enforceX402Payment(resource=/api/requests)
    X402-->>API: payment receipt (or 402)
    API->>Match: list active nodes + select runtime nodes
    Match-->>API: selected nodes/runtime config
    API->>Workflow: runCreWorkflow(requestId,input,nodes)

    Workflow->>Nodes: dispatch verification (/verify or mock run)
    Nodes-->>Workflow: nodeReports (+ optional signedReports/executionReceipts)
    Workflow->>Cons: compute consensus (legacy or DON path)
    Cons-->>Workflow: consensus + optional consensusBundle
    Workflow->>Chain: submitConsensusOnchain()
    Chain->>C: finalizeVerification() or finalizeWithBundle()
    C-->>Chain: tx receipt
    Chain-->>Workflow: onchainReceipt
    Workflow-->>API: FINALIZED/FAILED_* + artifacts paths

    alt final status is FINALIZED and POR_ONCHAIN_AUTO_RECORD_ENABLED=true
      API->>Por: buildNextPorProofInput()
      API->>Chain: submitPorProofOnchain()
      Chain->>C: recordPorProof()
      C-->>Chain: tx receipt
    end

    API-->>DApp: request record with consensus + onchain receipt
```

## 4) Node Operator Registration + Heartbeat

```mermaid
sequenceDiagram
    participant Op as Operator Wallet
    participant Verify as Verify Page
    participant API as Orchestrator Node APIs
    participant X402 as x402 Guard
    participant NR as nodeRegistry
    participant Worker as Node Endpoint (/healthz)
    participant Chain as onchainWriter
    participant C as Registry Contract

    Op->>Verify: Connect wallet
    Verify->>API: POST /api/nodes/challenge
    API->>X402: enforceX402Payment(resource=/api/nodes/challenge)
    API->>NR: createNodeRegistrationChallenge()
    NR-->>API: challengeMessage + challengeId
    API-->>Verify: challenge payload

    Verify->>Op: signMessage(challengeMessage)
    Op-->>Verify: signature
    Verify->>API: POST /api/nodes/activate (challengeId, signature)
    API->>NR: activateNodeRegistrationChallenge()
    NR->>Worker: probe endpoint /healthz
    Worker-->>NR: health result
    NR-->>API: ACTIVE node + endpoint probe

    opt NODE_LIFECYCLE_ONCHAIN_ENABLED=true
      API->>Chain: submitNodeLifecycleOnchain(action=ACTIVATED)
      Chain->>C: recordNodeLifecycle()
      C-->>Chain: tx receipt
    end

    Verify->>Op: signMessage(heartbeat message)
    Verify->>API: POST /api/nodes/heartbeat
    API->>NR: touchNodeHeartbeat() + optional probe
    opt NODE_LIFECYCLE_ONCHAIN_ENABLED=true
      API->>Chain: submitNodeLifecycleOnchain(action=HEARTBEAT)
      Chain->>C: recordNodeLifecycle()
    end
```

## 5) DON Distributed Consensus + Bundle Signing Path

```mermaid
sequenceDiagram
    participant Orch as Orchestrator
    participant WV as Worker Endpoints (/verify)
    participant WA as Included Operator Endpoint
    participant WL as Leader Endpoint
    participant Don as donConsensus + donSignatures
    participant Chain as onchainWriter
    participant C as DonConsensusRegistrySkeleton

    Note over Orch: USE_DON_SIGNED_REPORTS=true<br/>NODE_ENDPOINT_VERIFY_ENABLED=true

    Orch->>WV: POST /verify (parallel to matched workers)
    WV-->>Orch: report + signedReport + executionReceipt (N responses)

    Orch->>Don: validateSignedReportsForQuorum()
    Orch->>Don: computeReportsMerkleRoot()
    Orch->>Don: prepareConsensusBundleFromSignedReports()
    Don-->>Orch: quorum + consensus + bundle skeleton

    loop each included operator
      Orch->>WA: POST /sign-bundle-approval
      WA-->>Orch: operator approval signature
    end

    Orch->>WL: POST /sign-consensus-bundle (leader sign)
    WL-->>Orch: leaderSignature
    Orch->>Don: verify approval + leader signatures

    Orch->>Chain: finalizeWithBundle(encodedInput)
    Chain->>C: on-chain EIP-712 checks + allowlist checks
    C-->>Chain: VerificationBundleFinalized event
```

## 6) Read Path for Result / Verify / PoR Pages

```mermaid
flowchart LR
    D["DApp"]
    API["Orchestrator GET APIs"]
    OR["onchainReader.ts"]
    ST["Local requests.json + nodes.json"]
    C["Contract Events"]
    POR["por.ts"]

    D -->|"GET /api/requests, /api/requests/:id"| API
    D -->|"GET /api/nodes"| API
    D -->|"GET /api/por/status"| API

    API -->|"ONCHAIN_READ_ENABLED"| OR
    OR --> C
    API -->|"fallback when strict=false"| ST

    API --> POR
    POR -->|"POR_ONCHAIN_READ_ENABLED"| OR
    POR -->|"fallback"| ST
```

## 7) Local Dev Deployment Topology

```mermaid
flowchart TB
    subgraph Browser["Browser"]
      UI["dApp http://localhost:5173"]
    end

    subgraph Frontend["dapp (Vite)"]
      VITE["Vite dev server<br/>proxy /api,/healthz -> :8787"]
    end

    subgraph Backend["orchestrator (Bun)"]
      API["server.ts :8787"]
      DATA["data/*.json"]
      REPORTS["reports/*.json + artifacts"]
    end

    subgraph Workers["Optional DON Workers"]
      W1[":19001"]
      W2[":19002"]
      W3[":19003"]
      W4[":19004"]
    end

    subgraph Chain["EVM/Tenderly"]
      RPC["RPC_URL"]
      REG["Registry Contract"]
    end

    UI --> VITE --> API
    API --> DATA
    API --> REPORTS
    API --> W1
    API --> W2
    API --> W3
    API --> W4
    API --> RPC --> REG
    REG --> RPC --> API
```

## Runtime Mode Switches (Key Flags)

```mermaid
flowchart TB
    A["DON signed flow"]
    A1["USE_DON_SIGNED_REPORTS"]
    A2["NODE_ENDPOINT_VERIFY_ENABLED"]
    A3["NODE_ENDPOINT_REQUIRE_SIGNED_REPORTS"]
    A --> A1
    A --> A2
    A --> A3

    B["DON bundle finalize"]
    B1["USE_DON_BUNDLE_FINALIZE"]
    B2["DON_ENDPOINT_BUNDLE_SIGNING_ENABLED"]
    B --> B1
    B --> B2

    C["x402 gate"]
    C1["X402_ENABLED"]
    C2["X402_PRICE_*"]
    C --> C1
    C --> C2

    D["Node selection strictness"]
    D1["REQUIRE_REGISTERED_NODES"]
    D2["ALLOW_DEFAULT_NODES"]
    D3["MIN_NODE_STAKE"]
    D4["REQUIRE_HEALTHY_NODE_ENDPOINTS"]
    D --> D1
    D --> D2
    D --> D3
    D --> D4

    E["On-chain read behavior"]
    E1["ONCHAIN_READ_ENABLED"]
    E2["ONCHAIN_READ_STRICT"]
    E --> E1
    E --> E2

    F["PoR source + auto record"]
    F1["POR_ONCHAIN_READ_ENABLED"]
    F2["POR_ONCHAIN_AUTO_RECORD_ENABLED"]
    F --> F1
    F --> F2

    G["Mock vs real tx"]
    G1["USE_MOCK_ONCHAIN"]
    G --> G1
```

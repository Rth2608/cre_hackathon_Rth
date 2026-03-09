# Operator Verifier (CRE + Confidential HTTP)

This folder contains a minimal verifier workflow where:

- Node workers **do not** hold raw provider API keys.
- The operator stores key material in CRE secrets (`llmApiKey`).
- Workflow uses `ConfidentialHTTPClient` for secret-backed outbound model calls.

## Where this fits in the architecture

This service is the verifier side of the LLM consensus layer:

1. Orchestrator dispatches requests to worker endpoints.
2. Worker runs with `RUNTIME_NODE_EXECUTION_MODE=cre_confidential_http`.
3. Worker calls this verifier endpoint (`/verify`) with bearer auth.
4. Verifier returns a synchronous report payload.
5. Worker signs the report + execution receipt and returns to orchestrator.
6. Orchestrator aggregates quorum and writes final records onchain.

In short: this folder implements the confidential verifier that workers call in step 7 of the pipeline diagram.

## Folder layout

- `project.yaml`: CRE project-level network/target settings.
- `secrets.yaml`: maps `llmApiKey` to env var `EMBEDDING_LLM_API_KEY`.
- `operator-verifier-workflow/main.ts`: HTTP trigger workflow logic.
- `operator-verifier-workflow/config.*.json`: runtime config.
- `operator-verifier-workflow/http_trigger_payload.json`: simulation payload sample.

`config.*.json` defaults to OpenAI embeddings URL (`https://api.openai.com/v1/embeddings`).
Set `embeddingModel` to your actual OpenAI embedding model ID before simulation/deploy.

## Request contract

Expected input payload:

```json
{
  "requestId": "0x...",
  "input": {
    "question": "...",
    "description": "...",
    "sourceUrls": ["https://..."],
    "resolutionCriteria": "...",
    "submitterAddress": "0x..."
  },
  "node": {
    "nodeId": "node-gpt",
    "modelFamily": "gpt",
    "modelName": "operator-gpt",
    "operatorAddress": "0x..."
  }
}
```

Workflow output:

```json
{
  "report": {
    "verdict": "PASS|FAIL",
    "confidence": 0.0,
    "rationale": "...",
    "evidenceSummary": "...",
    "generatedAt": "2026-03-06T00:00:00.000Z"
  },
  "providerRequestId": "...",
  "policyVersion": "operator-verifier-v1"
}
```

## Secrets and local simulation

1. Set env variables.

```bash
cd cre-operator-verifier
cp .env.example .env
# fill CRE_ETH_PRIVATE_KEY, EMBEDDING_LLM_API_KEY
```

Required values:

- `EMBEDDING_LLM_API_KEY` must be your OpenAI key (`sk-...`), not xAI key (`xai-...`).
- `operator-verifier-workflow/config.*.json` should keep:
  - `embeddingUrl=https://api.openai.com/v1/embeddings`
  - `embeddingModel=text-embedding-3-small` (or another OpenAI embedding model you can access)

2. Install workflow dependencies.

```bash
cd operator-verifier-workflow
bun install
bun run setup:cre
```

`bun run setup:cre` is required once per machine/workspace to build the CRE Javy plugin (`javy-chainlink-sdk.plugin.wasm`).

3. Simulate HTTP trigger.

```bash
cd ..
cre workflow simulate ./operator-verifier-workflow \
  --target staging-settings \
  --non-interactive \
  --trigger-index 0 \
  --http-payload @./operator-verifier-workflow/http_trigger_payload.json
```

Troubleshooting (`Incorrect API key provided: xai-...`):

1. Check current shell value:
   - `echo "$EMBEDDING_LLM_API_KEY"`
2. If it still starts with `xai-`, reload env and retry simulation.
3. For deployed targets, re-upload secret so CRE target no longer uses stale key:

```bash
cd cre-operator-verifier
cre secrets create ./secrets.yaml --target production-settings
```

Secret hygiene:

- Never commit `.env` with real key values.
- Commit only `.env.example` placeholders.

## Deploy notes

- Deployment requires CRE account access and linked wallet.
- Before deploy, set real owner address in:
  - `project.yaml` -> `production-settings.account.workflow-owner-address`
- Upload secrets before activate:

```bash
cd cre-operator-verifier
cre secrets create ./secrets.yaml --target production-settings
```

- Deploy workflow:

```bash
cd cre-operator-verifier
cre workflow deploy ./operator-verifier-workflow --target production-settings
```

## Integration note for current orchestrator workers

Current worker implementation expects a synchronous endpoint returning `{ report: ... }`.
CRE gateway HTTP trigger for deployed workflows may return `ACCEPTED` first.

If your gateway is async, add a thin adapter endpoint that:

1. triggers CRE workflow,
2. waits/polls execution result,
3. returns the final `{ report: ... }` object to the worker.

Minimum worker-side env (per node):

```bash
RUNTIME_NODE_EXECUTION_MODE=cre_confidential_http
RUNTIME_NODE_CRE_VERIFY_URL=https://<this-verifier>/verify
RUNTIME_NODE_CRE_VERIFY_AUTH_TOKEN=<bearer-token>
RUNTIME_NODE_CRE_VERIFY_TIMEOUT_MS=12000
```

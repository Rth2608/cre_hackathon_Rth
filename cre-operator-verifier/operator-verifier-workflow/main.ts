import {
  type HTTPPayload,
  type Runtime,
  ConfidentialHTTPClient,
  HTTPCapability,
  Runner,
  cre,
  decodeJson,
  json,
  ok,
  text
} from "@chainlink/cre-sdk";
import { z } from "zod";

const configSchema = z.object({
  authorizedKey: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  embeddingUrl: z.string().regex(/^https?:\/\/\S+$/),
  embeddingModel: z.string().min(1),
  policyVersion: z.string().min(1),
  passMinEmbeddingDims: z.number().int().min(1).max(32768)
});

type WorkflowConfig = z.infer<typeof configSchema>;

const inputSchema = z.object({
  question: z.string().min(1),
  description: z.string().min(1),
  sourceUrls: z.array(z.string().regex(/^https?:\/\/\S+$/)).default([]),
  resolutionCriteria: z.string().min(1),
  submitterAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/)
});

const requestSchema = z.object({
  requestId: z.string().min(1),
  input: inputSchema,
  node: z
    .object({
      nodeId: z.string().min(1),
      modelFamily: z.string().min(1),
      modelName: z.string().min(1),
      operatorAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/)
    })
    .optional()
});

type VerifierRequest = z.infer<typeof requestSchema>;

interface EmbeddingApiResponse {
  id?: string;
  model?: string;
  usage?: {
    total_tokens?: number;
  };
  data?: Array<{
    embedding?: number[];
  }>;
}

function normalizeUrls(urls: string[]): string[] {
  return [...urls].map((value) => value.trim()).filter(Boolean).sort((a, b) => a.localeCompare(b));
}

function buildCanonicalText(payload: VerifierRequest): string {
  const input = payload.input;
  const sections = [
    `question=${input.question.trim()}`,
    `description=${input.description.trim()}`,
    `resolutionCriteria=${input.resolutionCriteria.trim()}`,
    `sourceUrls=${normalizeUrls(input.sourceUrls).join("|")}`,
    `submitterAddress=${input.submitterAddress.toLowerCase()}`
  ];
  return sections.join("\n");
}

function computeConfidence(embeddingDims: number): number {
  if (embeddingDims <= 0) {
    return 0;
  }
  const normalized = Math.min(embeddingDims, 4096) / 4096;
  const confidence = 0.5 + normalized * 0.49;
  return Number(confidence.toFixed(2));
}

function buildVerdict(args: {
  embeddingDims: number;
  minDims: number;
}): "PASS" | "FAIL" {
  return args.embeddingDims >= args.minDims ? "PASS" : "FAIL";
}

async function onHttpTrigger(runtime: Runtime<unknown>, payload: HTTPPayload) {
  const config = configSchema.parse(runtime.config);
  if (config.embeddingModel === "openai-embedding-model-id") {
    throw new Error(
      "embedding_model_not_configured: set config.embeddingModel to a real OpenAI embedding model your team can access"
    );
  }
  const request = requestSchema.parse(decodeJson(payload.input) as unknown);
  const canonicalText = buildCanonicalText(request);

  const confidentialClient = new ConfidentialHTTPClient();
  const response = confidentialClient
    .sendRequest(runtime, {
      vaultDonSecrets: [
        {
          key: "llmApiKey"
        }
      ],
      request: {
        method: "POST",
        url: config.embeddingUrl,
        multiHeaders: {
          "Content-Type": {
            values: ["application/json"]
          },
          Authorization: {
            values: ["Bearer {{.llmApiKey}}"]
          }
        },
        bodyString: JSON.stringify({
          model: config.embeddingModel,
          input: canonicalText
        })
      }
    })
    .result();

  if (!ok(response)) {
    throw new Error(`embedding_request_failed status=${response.statusCode} detail=${text(response)}`);
  }

  const decoded = json(response) as EmbeddingApiResponse;
  const embedding = decoded.data?.[0]?.embedding;
  const embeddingDims = Array.isArray(embedding) ? embedding.length : 0;
  const verdict = buildVerdict({
    embeddingDims,
    minDims: config.passMinEmbeddingDims
  });
  const confidence = computeConfidence(embeddingDims);
  const generatedAt = runtime.now().toISOString();

  return {
    report: {
      verdict,
      confidence,
      rationale:
        verdict === "PASS"
          ? "Confidential embedding generation succeeded and minimum embedding-dimension policy passed."
          : "Confidential embedding generation succeeded but minimum embedding-dimension policy failed.",
      evidenceSummary: `embeddingModel=${decoded.model ?? config.embeddingModel} dims=${embeddingDims} totalTokens=${decoded.usage?.total_tokens ?? "n/a"}`,
      generatedAt
    },
    providerRequestId: decoded.id ?? "",
    policyVersion: config.policyVersion
  };
}

function initWorkflow(config: unknown) {
  const typedConfig = configSchema.parse(config);
  const http = new HTTPCapability();
  const trigger = http.trigger({
    authorizedKeys: [
      {
        type: "KEY_TYPE_ECDSA_EVM",
        publicKey: typedConfig.authorizedKey
      }
    ]
  });

  return [cre.handler(trigger, (runtime, payload) => onHttpTrigger(runtime, payload))];
}

export async function main() {
  const runner = await Runner.newRunner<unknown>({
    configParser: (configBytes) => decodeJson(configBytes) as unknown
  });
  await runner.run(initWorkflow);
}

await main();

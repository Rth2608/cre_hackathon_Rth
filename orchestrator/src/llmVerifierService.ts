import { createHash } from "node:crypto";
import { hashObject, nowIso } from "./utils";

const PORT = Number.parseInt(process.env.PORT ?? "9897", 10);

type VerifierProvider = "openai" | "xai" | "anthropic" | "gemini";
type VerifierVerdict = "PASS" | "FAIL";

interface VerifyRequestBody {
  requestId: string;
  input: {
    question: string;
    description: string;
    sourceUrls: string[];
    resolutionCriteria: string;
    submitterAddress: string;
  };
  node?: {
    nodeId?: string;
    modelFamily?: string;
    modelName?: string;
    operatorAddress?: string;
  };
}

interface CanonicalRequestInput {
  question: string;
  description: string;
  sourceUrls: string[];
  resolutionCriteria: string;
  submitterAddress: string;
}

interface VerifierConfig {
  provider: VerifierProvider;
  model: string;
  timeoutMs: number;
  temperature: number;
  maxOutputTokens: number;
  strictOutput: boolean;
  requireJsonResponse: boolean;
  templateId: string;
  templateVersion: string;
  template: string;
}

const DEFAULT_PROMPT_TEMPLATE = [
  "You are a deterministic verifier node for a prediction-market request.",
  "Evaluate whether this request is suitable to move forward to market verification.",
  "",
  "Decision policy:",
  "1. PASS only if the question is clear, binary/decidable, and time-bounded enough for resolution.",
  "2. FAIL if resolution criteria are vague, subjective, or not independently verifiable.",
  "3. FAIL if source evidence list is weak, obviously untrusted, or insufficient for reliable resolution.",
  "4. Confidence must be a number between 0 and 1.",
  "",
  "Return strict JSON only with this schema:",
  '{"verdict":"PASS|FAIL","confidence":0.0,"rationale":"string","evidenceSummary":"string"}',
  "",
  "Request payload (canonical JSON):",
  "{{INPUT_JSON}}"
].join("\n");

const SYSTEM_PROMPT = [
  "Output JSON only.",
  "Do not include markdown fences.",
  "Use PASS or FAIL for verdict."
].join(" ");

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function parseIntEnv(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isInteger(parsed)) return fallback;
  if (parsed < min || parsed > max) return fallback;
  return parsed;
}

function parseFloatEnv(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseFloat(value ?? "");
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < min || parsed > max) return fallback;
  return parsed;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Cre-Request-Id"
    }
  });
}

function corsPreflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Cre-Request-Id"
    }
  });
}

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function truncateText(value: string, maxLength = 400): string {
  if (value.length <= maxLength) return value;
  return `${value.slice(0, maxLength)}...`;
}

function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function normalizeAddress(value: string): string {
  const trimmed = value.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return trimmed;
}

function normalizeSourceUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed);
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return trimmed;
  }
}

function canonicalizeInput(input: VerifyRequestBody["input"]): CanonicalRequestInput {
  const sourceUrls = Array.from(
    new Set(
      input.sourceUrls
        .map((url) => normalizeSourceUrl(String(url)))
        .map((url) => url.trim())
        .filter(Boolean)
    )
  ).sort((a, b) => a.localeCompare(b));

  return {
    question: normalizeWhitespace(String(input.question ?? "")),
    description: normalizeWhitespace(String(input.description ?? "")),
    sourceUrls,
    resolutionCriteria: normalizeWhitespace(String(input.resolutionCriteria ?? "")),
    submitterAddress: normalizeAddress(String(input.submitterAddress ?? ""))
  };
}

function sha256Hex(value: string): string {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function resolveProvider(): VerifierProvider {
  const raw = (process.env.VERIFIER_PROVIDER ?? "").trim().toLowerCase();
  switch (raw) {
    case "gpt":
    case "openai":
      return "openai";
    case "grok":
    case "xai":
      return "xai";
    case "claude":
    case "anthropic":
      return "anthropic";
    case "gemini":
    case "google":
      return "gemini";
    default:
      return "openai";
  }
}

function resolveModel(provider: VerifierProvider): string {
  const configured = process.env.VERIFIER_MODEL?.trim();
  if (configured) return configured;

  if (provider === "xai") return "grok-3-mini-beta";
  if (provider === "anthropic") return "claude-3-5-haiku-latest";
  if (provider === "gemini") return "gemini-2.0-flash";
  return "gpt-4.1-mini";
}

function resolveApiKey(provider: VerifierProvider): string {
  if (provider === "xai") {
    return (process.env.VERIFIER_XAI_API_KEY ?? process.env.XAI_API_KEY ?? "").trim();
  }
  if (provider === "anthropic") {
    return (process.env.VERIFIER_ANTHROPIC_API_KEY ?? process.env.ANTHROPIC_API_KEY ?? "").trim();
  }
  if (provider === "gemini") {
    return (process.env.VERIFIER_GEMINI_API_KEY ?? process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY ?? "").trim();
  }
  return (process.env.VERIFIER_OPENAI_API_KEY ?? process.env.OPENAI_API_KEY ?? "").trim();
}

function resolveOpenAiBaseUrl(provider: VerifierProvider): string {
  if (provider === "xai") {
    return (process.env.VERIFIER_XAI_BASE_URL ?? "https://api.x.ai/v1").trim().replace(/\/$/, "");
  }
  return (process.env.VERIFIER_OPENAI_BASE_URL ?? "https://api.openai.com/v1").trim().replace(/\/$/, "");
}

function resolveAnthropicMessagesUrl(): string {
  return (process.env.VERIFIER_ANTHROPIC_MESSAGES_URL ?? "https://api.anthropic.com/v1/messages").trim();
}

function resolveGeminiBaseUrl(): string {
  return (process.env.VERIFIER_GEMINI_BASE_URL ?? "https://generativelanguage.googleapis.com/v1beta/models")
    .trim()
    .replace(/\/$/, "");
}

function resolveConfig(): VerifierConfig {
  const provider = resolveProvider();
  return {
    provider,
    model: resolveModel(provider),
    timeoutMs: parseIntEnv(process.env.VERIFIER_TIMEOUT_MS, 20_000, 1_000, 120_000),
    temperature: parseFloatEnv(process.env.VERIFIER_TEMPERATURE, 0, 0, 2),
    maxOutputTokens: parseIntEnv(process.env.VERIFIER_MAX_OUTPUT_TOKENS, 700, 64, 8_192),
    strictOutput: parseBooleanEnv(process.env.VERIFIER_STRICT_OUTPUT, true),
    requireJsonResponse: parseBooleanEnv(process.env.VERIFIER_REQUIRE_JSON_RESPONSE, true),
    templateId: (process.env.VERIFIER_PROMPT_TEMPLATE_ID ?? "cre-market-verify-template").trim(),
    templateVersion: (process.env.VERIFIER_PROMPT_TEMPLATE_VERSION ?? "v1").trim(),
    template: process.env.VERIFIER_PROMPT_TEMPLATE?.trim() || DEFAULT_PROMPT_TEMPLATE
  };
}

async function parseJsonBody<T>(req: Request): Promise<T> {
  const raw = await req.text();
  if (!raw) {
    throw new Error("request_body_empty");
  }
  return JSON.parse(raw) as T;
}

function validateVerifyBody(body: VerifyRequestBody): string | null {
  if (!/^0x[0-9a-fA-F]{64}$/.test(body.requestId ?? "")) {
    return "invalid_request_id";
  }
  if (!body.input || typeof body.input !== "object") {
    return "invalid_input";
  }
  if (!Array.isArray(body.input.sourceUrls)) {
    return "invalid_input_source_urls";
  }
  return null;
}

function requireAuth(req: Request): Response | null {
  const requiredToken = (process.env.VERIFIER_AUTH_TOKEN ?? process.env.CRE_ADAPTER_AUTH_TOKEN ?? "").trim();
  if (!requiredToken) {
    return null;
  }
  const authorization = req.headers.get("authorization")?.trim() ?? "";
  if (authorization !== `Bearer ${requiredToken}`) {
    return jsonResponse(
      {
        ok: false,
        error: "verifier_unauthorized"
      },
      401
    );
  }
  return null;
}

function renderPromptTemplate(template: string, canonicalInputJson: string): string {
  return template
    .replaceAll("{{INPUT_JSON}}", canonicalInputJson)
    .replaceAll("{{input_json}}", canonicalInputJson);
}

async function fetchJson(args: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs: number;
}): Promise<{ ok: boolean; status: number; data: unknown; text: string }> {
  const response = await fetch(args.url, {
    method: args.method ?? "POST",
    headers: args.headers,
    body: args.body === undefined ? undefined : JSON.stringify(args.body),
    signal: AbortSignal.timeout(args.timeoutMs)
  });

  const text = await response.text();
  let data: unknown = {};
  try {
    data = text ? (JSON.parse(text) as unknown) : {};
  } catch {
    data = {};
  }
  return {
    ok: response.ok,
    status: response.status,
    data,
    text
  };
}

function extractOpenAiText(data: unknown): string {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("openai_invalid_payload");
  }
  const choices = (data as Record<string, unknown>).choices;
  if (!Array.isArray(choices) || choices.length === 0) {
    throw new Error("openai_missing_choices");
  }
  const first = choices[0];
  if (!first || typeof first !== "object") {
    throw new Error("openai_invalid_choice");
  }
  const message = (first as Record<string, unknown>).message;
  if (!message || typeof message !== "object") {
    throw new Error("openai_missing_message");
  }
  const content = (message as Record<string, unknown>).content;
  if (typeof content === "string" && content.trim()) {
    return content.trim();
  }
  if (Array.isArray(content)) {
    const texts = content
      .map((item) => {
        if (!item || typeof item !== "object") return "";
        const text = (item as Record<string, unknown>).text;
        return typeof text === "string" ? text : "";
      })
      .filter(Boolean);
    if (texts.length > 0) {
      return texts.join("\n").trim();
    }
  }
  throw new Error("openai_empty_content");
}

function shouldRetryWithoutJsonMode(status: number, text: string): boolean {
  if (status !== 400) return false;
  const lower = text.toLowerCase();
  return lower.includes("response_format") || lower.includes("json_schema") || lower.includes("json mode");
}

async function callOpenAiCompatible(args: {
  provider: "openai" | "xai";
  model: string;
  apiKey: string;
  systemPrompt: string;
  userPrompt: string;
  temperature: number;
  maxOutputTokens: number;
  timeoutMs: number;
  requireJsonResponse: boolean;
}): Promise<string> {
  const url = `${resolveOpenAiBaseUrl(args.provider)}/chat/completions`;
  const headers = {
    Authorization: `Bearer ${args.apiKey}`,
    "Content-Type": "application/json"
  };

  const baseBody = {
    model: args.model,
    temperature: args.temperature,
    max_tokens: args.maxOutputTokens,
    messages: [
      { role: "system", content: args.systemPrompt },
      { role: "user", content: args.userPrompt }
    ]
  };

  const withJsonMode = {
    ...baseBody,
    response_format: { type: "json_object" }
  };

  const attempts = args.requireJsonResponse ? [withJsonMode, baseBody] : [baseBody];
  for (let i = 0; i < attempts.length; i += 1) {
    const response = await fetchJson({
      url,
      headers,
      body: attempts[i],
      timeoutMs: args.timeoutMs
    });
    if (response.ok) {
      return extractOpenAiText(response.data);
    }
    if (i === 0 && args.requireJsonResponse && shouldRetryWithoutJsonMode(response.status, response.text)) {
      continue;
    }
    throw new Error(`openai_http_${response.status}:${truncateText(response.text || "unknown_error")}`);
  }

  throw new Error("openai_request_failed");
}

function extractAnthropicText(data: unknown): string {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("anthropic_invalid_payload");
  }
  const content = (data as Record<string, unknown>).content;
  if (!Array.isArray(content) || content.length === 0) {
    throw new Error("anthropic_missing_content");
  }
  const texts = content
    .map((item) => {
      if (!item || typeof item !== "object") return "";
      const text = (item as Record<string, unknown>).text;
      return typeof text === "string" ? text : "";
    })
    .filter(Boolean);
  if (texts.length === 0) {
    throw new Error("anthropic_empty_content");
  }
  return texts.join("\n").trim();
}

async function callAnthropic(args: {
  model: string;
  apiKey: string;
  systemPrompt: string;
  userPrompt: string;
  temperature: number;
  maxOutputTokens: number;
  timeoutMs: number;
}): Promise<string> {
  const url = resolveAnthropicMessagesUrl();
  const response = await fetchJson({
    url,
    headers: {
      "x-api-key": args.apiKey,
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json"
    },
    body: {
      model: args.model,
      max_tokens: args.maxOutputTokens,
      temperature: args.temperature,
      system: args.systemPrompt,
      messages: [{ role: "user", content: args.userPrompt }]
    },
    timeoutMs: args.timeoutMs
  });

  if (!response.ok) {
    throw new Error(`anthropic_http_${response.status}:${truncateText(response.text || "unknown_error")}`);
  }
  return extractAnthropicText(response.data);
}

function extractGeminiText(data: unknown): string {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("gemini_invalid_payload");
  }
  const candidates = (data as Record<string, unknown>).candidates;
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new Error("gemini_missing_candidates");
  }

  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object") continue;
    const content = (candidate as Record<string, unknown>).content;
    if (!content || typeof content !== "object") continue;
    const parts = (content as Record<string, unknown>).parts;
    if (!Array.isArray(parts)) continue;
    const text = parts
      .map((part) => {
        if (!part || typeof part !== "object") return "";
        const value = (part as Record<string, unknown>).text;
        return typeof value === "string" ? value : "";
      })
      .filter(Boolean)
      .join("\n")
      .trim();
    if (text) {
      return text;
    }
  }

  throw new Error("gemini_empty_content");
}

async function callGemini(args: {
  model: string;
  apiKey: string;
  systemPrompt: string;
  userPrompt: string;
  temperature: number;
  maxOutputTokens: number;
  timeoutMs: number;
  requireJsonResponse: boolean;
}): Promise<string> {
  const url = `${resolveGeminiBaseUrl()}/${encodeURIComponent(args.model)}:generateContent?key=${encodeURIComponent(args.apiKey)}`;
  const response = await fetchJson({
    url,
    headers: {
      "Content-Type": "application/json"
    },
    body: {
      systemInstruction: {
        parts: [{ text: args.systemPrompt }]
      },
      contents: [
        {
          role: "user",
          parts: [{ text: args.userPrompt }]
        }
      ],
      generationConfig: {
        temperature: args.temperature,
        maxOutputTokens: args.maxOutputTokens,
        responseMimeType: args.requireJsonResponse ? "application/json" : "text/plain"
      }
    },
    timeoutMs: args.timeoutMs
  });

  if (!response.ok) {
    throw new Error(`gemini_http_${response.status}:${truncateText(response.text || "unknown_error")}`);
  }
  return extractGeminiText(response.data);
}

function parseJsonObjectFromText(raw: string): Record<string, unknown> {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("model_output_empty");
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }

  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    const jsonSlice = trimmed.slice(firstBrace, lastBrace + 1);
    try {
      const parsed = JSON.parse(jsonSlice) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // fall through
    }
  }

  throw new Error("model_output_not_json_object");
}

function toVerdict(value: unknown): VerifierVerdict | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toUpperCase();
  if (normalized === "PASS" || normalized === "ALLOW" || normalized === "APPROVE") return "PASS";
  if (normalized === "FAIL" || normalized === "REJECT" || normalized === "DENY") return "FAIL";
  return null;
}

function toConfidence(value: unknown): number | null {
  const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
  if (!Number.isFinite(numeric)) return null;
  if (numeric >= 0 && numeric <= 1) return numeric;
  if (numeric > 1 && numeric <= 100) return numeric / 100;
  return null;
}

function inferFallbackVerdict(raw: string): VerifierVerdict {
  const normalized = raw.toLowerCase();
  if (normalized.includes("pass") || normalized.includes("allow") || normalized.includes("approve")) {
    return "PASS";
  }
  return "FAIL";
}

function parseVerifierOutput(rawOutput: string, strictOutput: boolean): {
  verdict: VerifierVerdict;
  confidence: number;
  rationale: string;
  evidenceSummary: string;
} {
  try {
    const parsed = parseJsonObjectFromText(rawOutput);
    const verdict = toVerdict(parsed.verdict);
    const confidence = toConfidence(parsed.confidence);
    if (!verdict || confidence === null) {
      throw new Error("json_missing_verdict_or_confidence");
    }
    const rationale =
      typeof parsed.rationale === "string" && parsed.rationale.trim()
        ? normalizeWhitespace(parsed.rationale)
        : "No detailed rationale was provided.";
    const evidenceSummary =
      typeof parsed.evidenceSummary === "string" && parsed.evidenceSummary.trim()
        ? normalizeWhitespace(parsed.evidenceSummary)
        : "No evidence summary was provided.";
    return {
      verdict,
      confidence: Number(Math.max(0, Math.min(1, confidence)).toFixed(4)),
      rationale,
      evidenceSummary
    };
  } catch (error) {
    if (strictOutput) {
      throw error;
    }
    const fallbackVerdict = inferFallbackVerdict(rawOutput);
    return {
      verdict: fallbackVerdict,
      confidence: fallbackVerdict === "PASS" ? 0.65 : 0.35,
      rationale: truncateText(normalizeWhitespace(rawOutput), 600) || "Fallback parser used due to non-JSON model output.",
      evidenceSummary: "Fallback parser used."
    };
  }
}

async function runProviderInference(args: {
  config: VerifierConfig;
  systemPrompt: string;
  userPrompt: string;
}): Promise<string> {
  const apiKey = resolveApiKey(args.config.provider);
  if (!apiKey) {
    throw new Error(`missing_api_key_for_provider:${args.config.provider}`);
  }

  if (args.config.provider === "anthropic") {
    return callAnthropic({
      model: args.config.model,
      apiKey,
      systemPrompt: args.systemPrompt,
      userPrompt: args.userPrompt,
      temperature: args.config.temperature,
      maxOutputTokens: args.config.maxOutputTokens,
      timeoutMs: args.config.timeoutMs
    });
  }

  if (args.config.provider === "gemini") {
    return callGemini({
      model: args.config.model,
      apiKey,
      systemPrompt: args.systemPrompt,
      userPrompt: args.userPrompt,
      temperature: args.config.temperature,
      maxOutputTokens: args.config.maxOutputTokens,
      timeoutMs: args.config.timeoutMs,
      requireJsonResponse: args.config.requireJsonResponse
    });
  }

  return callOpenAiCompatible({
    provider: args.config.provider,
    model: args.config.model,
    apiKey,
    systemPrompt: args.systemPrompt,
    userPrompt: args.userPrompt,
    temperature: args.config.temperature,
    maxOutputTokens: args.config.maxOutputTokens,
    timeoutMs: args.config.timeoutMs,
    requireJsonResponse: args.config.requireJsonResponse
  });
}

async function handleVerify(req: Request): Promise<Response> {
  const authError = requireAuth(req);
  if (authError) {
    return authError;
  }

  let body: VerifyRequestBody;
  try {
    body = await parseJsonBody<VerifyRequestBody>(req);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "invalid_json",
        detail: stringifyError(error)
      },
      400
    );
  }

  const validationError = validateVerifyBody(body);
  if (validationError) {
    return jsonResponse(
      {
        ok: false,
        error: validationError
      },
      400
    );
  }

  const config = resolveConfig();
  const canonicalInput = canonicalizeInput(body.input);
  const canonicalInputJson = JSON.stringify(canonicalInput);
  const renderedPrompt = renderPromptTemplate(config.template, canonicalInputJson);
  const templateHash = sha256Hex(`${SYSTEM_PROMPT}\n${config.template}`);
  const canonicalPromptHash = sha256Hex(`${SYSTEM_PROMPT}\n${renderedPrompt}`);

  try {
    const rawModelOutput = await runProviderInference({
      config,
      systemPrompt: SYSTEM_PROMPT,
      userPrompt: renderedPrompt
    });

    const parsed = parseVerifierOutput(rawModelOutput, config.strictOutput);
    const generatedAt = nowIso();
    const reportCore = {
      requestId: body.requestId,
      verdict: parsed.verdict,
      confidence: parsed.confidence,
      rationale: parsed.rationale,
      evidenceSummary: `${parsed.evidenceSummary} | provider=${config.provider} model=${config.model}`,
      generatedAt
    };
    const reportHash = hashObject(reportCore);

    return jsonResponse({
      ok: true,
      data: {
        provider: config.provider,
        model: config.model,
        promptTemplateId: config.templateId,
        promptTemplateVersion: config.templateVersion,
        promptTemplateHash: templateHash,
        canonicalPromptHash,
        report: {
          ...reportCore,
          reportHash,
          promptTemplateHash: templateHash,
          canonicalPromptHash
        }
      }
    });
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "llm_verification_failed",
        detail: stringifyError(error)
      },
      502
    );
  }
}

async function router(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (req.method === "OPTIONS") {
    return corsPreflight();
  }

  if (req.method === "GET" && url.pathname === "/healthz") {
    const config = resolveConfig();
    return jsonResponse({
      ok: true,
      service: "llm-verifier-service",
      timestamp: nowIso(),
      provider: config.provider,
      model: config.model,
      timeoutMs: config.timeoutMs,
      strictOutput: config.strictOutput,
      requireJsonResponse: config.requireJsonResponse,
      promptTemplateId: config.templateId,
      promptTemplateVersion: config.templateVersion,
      promptTemplateHash: sha256Hex(`${SYSTEM_PROMPT}\n${config.template}`),
      authRequired: Boolean((process.env.VERIFIER_AUTH_TOKEN ?? process.env.CRE_ADAPTER_AUTH_TOKEN ?? "").trim())
    });
  }

  if (req.method === "POST" && url.pathname === "/verify") {
    return handleVerify(req);
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

Bun.serve({
  port: PORT,
  fetch: router
});

const startupConfig = resolveConfig();
console.log(
  `[llm-verifier-service] listening on http://localhost:${PORT} provider=${startupConfig.provider} model=${startupConfig.model}`
);

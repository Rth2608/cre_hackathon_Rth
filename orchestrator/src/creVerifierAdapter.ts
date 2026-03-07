import { nowIso } from "./utils";

const PORT = Number.parseInt(process.env.PORT ?? "9898", 10);

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function resolveTimeoutMs(): number {
  const parsed = Number.parseInt(process.env.CRE_ADAPTER_TIMEOUT_MS ?? "15000", 10);
  if (!Number.isInteger(parsed) || parsed < 500 || parsed > 120_000) {
    return 15_000;
  }
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

async function parseJsonBody<T>(req: Request): Promise<T> {
  const raw = await req.text();
  if (!raw) {
    throw new Error("request_body_empty");
  }
  return JSON.parse(raw) as T;
}

function requireAuth(req: Request): Response | null {
  const requiredToken = process.env.CRE_ADAPTER_AUTH_TOKEN?.trim();
  if (!requiredToken) {
    return null;
  }
  const authorization = req.headers.get("authorization")?.trim() ?? "";
  const expected = `Bearer ${requiredToken}`;
  if (authorization !== expected) {
    return jsonResponse(
      {
        ok: false,
        error: "adapter_unauthorized"
      },
      401
    );
  }
  return null;
}

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

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

async function forwardToUpstream(req: Request, body: VerifyRequestBody): Promise<Response> {
  const upstream = process.env.CRE_ADAPTER_UPSTREAM_URL?.trim();
  if (!upstream) {
    return jsonResponse(
      {
        ok: false,
        error: "adapter_upstream_missing",
        detail: "Set CRE_ADAPTER_UPSTREAM_URL to a synchronous verifier endpoint that returns { report: ... }."
      },
      500
    );
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Cre-Request-Id": body.requestId
  };
  const upstreamAuth = process.env.CRE_ADAPTER_UPSTREAM_AUTH_TOKEN?.trim();
  if (upstreamAuth) {
    headers.Authorization = `Bearer ${upstreamAuth}`;
  }

  try {
    const timeoutMs = resolveTimeoutMs();
    const response = await fetch(upstream, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs)
    });

    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text ? (JSON.parse(text) as unknown) : {};
    } catch {
      parsed = {
        ok: false,
        error: "adapter_upstream_non_json",
        detail: text.slice(0, 500)
      };
    }

    if (!response.ok) {
      return jsonResponse(
        {
          ok: false,
          error: "adapter_upstream_http_error",
          statusCode: response.status,
          upstream: parsed
        },
        502
      );
    }

    const strictSync = parseBooleanEnv(process.env.CRE_ADAPTER_REQUIRE_SYNC_REPORT, true);
    if (strictSync) {
      const root = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
      const data =
        root.data && typeof root.data === "object" && !Array.isArray(root.data)
          ? (root.data as Record<string, unknown>)
          : root;
      const report =
        data.report && typeof data.report === "object" && !Array.isArray(data.report)
          ? (data.report as Record<string, unknown>)
          : undefined;
      if (!report || typeof report.verdict !== "string" || typeof report.confidence !== "number") {
        return jsonResponse(
          {
            ok: false,
            error: "adapter_upstream_invalid_report",
            detail: "upstream response must include report.verdict and report.confidence"
          },
          502
        );
      }
    }

    return jsonResponse(parsed, 200);
  } catch (error) {
    return jsonResponse(
      {
        ok: false,
        error: "adapter_upstream_request_failed",
        detail: stringifyError(error)
      },
      502
    );
  }
}

async function router(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") {
    return corsPreflight();
  }

  const url = new URL(req.url);
  if (req.method === "GET" && url.pathname === "/healthz") {
    return jsonResponse({
      ok: true,
      service: "cre-verifier-adapter",
      timestamp: nowIso(),
      upstreamConfigured: Boolean(process.env.CRE_ADAPTER_UPSTREAM_URL?.trim()),
      timeoutMs: resolveTimeoutMs()
    });
  }

  if (req.method === "POST" && url.pathname === "/verify") {
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

    const bodyError = validateVerifyBody(body);
    if (bodyError) {
      return jsonResponse(
        {
          ok: false,
          error: bodyError
        },
        400
      );
    }

    return forwardToUpstream(req, body);
  }

  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

Bun.serve({
  port: PORT,
  fetch: router
});

console.log(
  `[cre-verifier-adapter] listening on http://localhost:${PORT} | upstream=${process.env.CRE_ADAPTER_UPSTREAM_URL?.trim() || "(unset)"}`
);

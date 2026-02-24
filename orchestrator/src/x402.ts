import type { VerificationPaymentReceipt } from "./types";
import { hashObject, nowIso } from "./utils";

const PAYMENT_HEADER_V2 = "payment-signature";
const PAYMENT_HEADER_V1 = "x-payment";
const WALLET_HEADER = "x-wallet-address";

export interface X402GuardOptions {
  resource: string;
  price: string;
  walletAddress?: string;
}

export interface X402GuardResult {
  ok: boolean;
  response?: Response;
  receipt: VerificationPaymentReceipt;
}

function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function normalizeAddress(value: string): string {
  return value.toLowerCase();
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Wallet-Address, X-Payment, Payment-Signature",
      ...headers
    }
  });
}

function buildPaymentRequiredHeader(resource: string, price: string): string {
  return `x402; resource="${resource}"; price="${price}"`;
}

function getPaymentToken(req: Request): string {
  return req.headers.get(PAYMENT_HEADER_V2)?.trim() || req.headers.get(PAYMENT_HEADER_V1)?.trim() || "";
}

function getPayerAddress(req: Request): string {
  return req.headers.get(WALLET_HEADER)?.trim() || "";
}

export function getWalletAddressFromHeaders(req: Request): string | null {
  const payerAddress = getPayerAddress(req);
  if (!payerAddress) return null;
  if (!isAddress(payerAddress)) return null;
  return normalizeAddress(payerAddress);
}

export async function enforceX402Payment(req: Request, options: X402GuardOptions): Promise<X402GuardResult> {
  const x402Enabled = process.env.X402_ENABLED === "true";
  const required = x402Enabled;
  const payerFromHeader = getPayerAddress(req);
  const paymentToken = getPaymentToken(req);
  const settledAt = nowIso();

  if (!payerFromHeader || !isAddress(payerFromHeader)) {
    return {
      ok: false,
      response: jsonResponse(
        {
          ok: false,
          error: "payer_wallet_required",
          detail: "set x-wallet-address header with connected wallet"
        },
        400
      ),
      receipt: {
        x402Enabled,
        required,
        paid: false,
        payerAddress: payerFromHeader || "",
        resource: options.resource,
        price: options.price,
        paymentRef: "",
        settledAt
      }
    };
  }

  const normalizedPayer = normalizeAddress(payerFromHeader);
  if (options.walletAddress && normalizeAddress(options.walletAddress) !== normalizedPayer) {
    return {
      ok: false,
      response: jsonResponse(
        {
          ok: false,
          error: "payer_wallet_mismatch",
          detail: "wallet in payload and x-wallet-address header must match"
        },
        400
      ),
      receipt: {
        x402Enabled,
        required,
        paid: false,
        payerAddress: normalizedPayer,
        resource: options.resource,
        price: options.price,
        paymentRef: "",
        settledAt
      }
    };
  }

  if (!required) {
    const receipt: VerificationPaymentReceipt = {
      x402Enabled,
      required,
      paid: true,
      payerAddress: normalizedPayer,
      resource: options.resource,
      price: options.price,
      paymentRef: `x402-disabled-${hashObject({ payer: normalizedPayer, resource: options.resource, settledAt })}`,
      settledAt
    };
    return { ok: true, receipt };
  }

  if (!paymentToken) {
    const headers = {
      "PAYMENT-REQUIRED": buildPaymentRequiredHeader(options.resource, options.price)
    };
    return {
      ok: false,
      response: jsonResponse(
        {
          ok: false,
          error: "payment_required",
          x402: {
            resource: options.resource,
            price: options.price,
            acceptedHeaders: [PAYMENT_HEADER_V2, PAYMENT_HEADER_V1]
          }
        },
        402,
        headers
      ),
      receipt: {
        x402Enabled,
        required,
        paid: false,
        payerAddress: normalizedPayer,
        resource: options.resource,
        price: options.price,
        paymentRef: "",
        settledAt
      }
    };
  }

  const receipt: VerificationPaymentReceipt = {
    x402Enabled,
    required,
    paid: true,
    payerAddress: normalizedPayer,
    resource: options.resource,
    price: options.price,
    paymentRef: hashObject({
      payerAddress: normalizedPayer,
      resource: options.resource,
      price: options.price,
      paymentToken,
      settledAt
    }),
    settledAt
  };

  return { ok: true, receipt };
}

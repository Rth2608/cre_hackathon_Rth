import { describe, expect, test } from "bun:test";
import { enforceX402Payment } from "./x402";

function req(headers: Record<string, string>): Request {
  return new Request("http://localhost:8787/api/requests/0xabc/run-verification", {
    method: "POST",
    headers
  });
}

describe("x402 guard", () => {
  test("returns 402 when enabled and no payment header", async () => {
    process.env.X402_ENABLED = "true";
    const result = await enforceX402Payment(
      req({
        "x-wallet-address": "0x1111111111111111111111111111111111111111"
      }),
      {
        resource: "/api/requests/0xabc/run-verification",
        price: "$0.05"
      }
    );

    expect(result.ok).toBe(false);
    expect(result.response?.status).toBe(402);
  });

  test("accepts payment-signature when enabled", async () => {
    process.env.X402_ENABLED = "true";
    const result = await enforceX402Payment(
      req({
        "x-wallet-address": "0x1111111111111111111111111111111111111111",
        "payment-signature": "mock-signature"
      }),
      {
        resource: "/api/nodes/register",
        price: "$0.01"
      }
    );

    expect(result.ok).toBe(true);
    expect(result.receipt.paid).toBe(true);
    expect(result.receipt.required).toBe(true);
  });
});

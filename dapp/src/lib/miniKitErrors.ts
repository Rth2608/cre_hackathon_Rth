export type MiniKitCommand = "verify" | "pay" | "walletAuth" | "transaction";

interface MiniKitErrorInfo {
  description: string;
  fix: string;
}

type MiniKitErrorCatalog = Record<MiniKitCommand, Record<string, MiniKitErrorInfo>>;

// Based on https://docs.world.org/mini-apps/reference/errors
export const MINI_KIT_ERROR_CATALOG: MiniKitErrorCatalog = {
  verify: {
    verification_rejected: {
      description: "World App returned a verification rejection for this request.",
      fix: "Retry verification and make sure the World App approval prompt is completed."
    },
    max_verifications_reached: {
      description: "The user already hit the maximum verification count for this action.",
      fix: "This action cannot be verified again for this user."
    },
    credential_unavailable: {
      description: "The required credential is not available for this user.",
      fix: "The user needs the required credential (Orb or device path) before retrying."
    },
    malformed_request: {
      description: "The request payload is invalid or could not be decrypted.",
      fix: "Check MiniKit setup and verify request parameters."
    },
    invalid_network: {
      description: "App environment does not match the user client environment.",
      fix: "Use Simulator for staging apps and World App for production apps."
    },
    inclusion_proof_failed: {
      description: "Credential inclusion proof retrieval failed unexpectedly.",
      fix: "Retry after a short delay. If it keeps failing, wait and try later or use an alternative verification path."
    },
    inclusion_proof_pending: {
      description: "Credential may exist but is not finalized on-chain yet.",
      fix: "Retry later (around one hour)."
    },
    unexpected_response: {
      description: "World App returned an unexpected response shape.",
      fix: "Retry first. If it repeats, report it."
    },
    generic_error: {
      description: "An unexpected internal error occurred.",
      fix: "Retry first. If it repeats, report it."
    }
  },
  pay: {
    input_error: {
      description: "The payment request payload is invalid.",
      fix: "Validate request shape and try again."
    },
    payment_rejected: {
      description: "The user canceled the payment in World App.",
      fix: "Restart payment if the user still wants to proceed."
    },
    invalid_receiver: {
      description: "Receiver address is invalid or not allowed.",
      fix: "Whitelist/check the receiver address in Developer Portal."
    },
    insufficient_balance: {
      description: "Wallet balance is not enough for this payment.",
      fix: "Fund the wallet and retry."
    },
    transaction_failed: {
      description: "On-chain payment transaction failed.",
      fix: "Retry and inspect chain-level failure details."
    },
    generic_error: {
      description: "Unexpected payment error.",
      fix: "Retry first; escalate if persistent."
    }
  },
  walletAuth: {
    malformed_request: {
      description: "Wallet auth request parameters are invalid.",
      fix: "Validate walletAuth payload and retry."
    },
    user_rejected: {
      description: "The user declined the wallet auth request.",
      fix: "Ask the user to retry and confirm."
    },
    generic_error: {
      description: "Unexpected wallet auth error.",
      fix: "Retry first; escalate if persistent."
    }
  },
  transaction: {
    invalid_operation: {
      description: "Request contains an invalid operation.",
      fix: "Remove disallowed operations (e.g., approvals/admin calls)."
    },
    invalid_contract: {
      description: "Target contract is not whitelisted for the app.",
      fix: "Whitelist the contract in Developer Portal."
    },
    user_rejected: {
      description: "The user declined the transaction modal.",
      fix: "Ask the user to retry and confirm."
    },
    input_error: {
      description: "Transaction payload format is invalid.",
      fix: "Ensure args are strings and payload size/ABI constraints are met."
    },
    simulation_failed: {
      description: "Transaction simulation failed before submission.",
      fix: "Inspect simulation debug data and fix root cause."
    },
    transaction_failed: {
      description: "Transaction submission/execution failed.",
      fix: "Retry later or inspect network/congestion conditions."
    },
    generic_error: {
      description: "Unexpected transaction error.",
      fix: "Retry first; escalate if persistent."
    },
    daily_tx_limit_reached: {
      description: "Daily transaction limit was reached.",
      fix: "Wait until the next day and retry."
    },
    disallowed_operation: {
      description: "Request includes a blocked operation.",
      fix: "Avoid user safe admin/approval-like operations."
    },
    permitted_amount_exceeds_slippage: {
      description: "Spending amount is outside permitted slippage bounds.",
      fix: "Spend at least 90% of permitted amount."
    },
    permitted_amount_not_found: {
      description: "Permit2 payload is missing permitted amount.",
      fix: "Provide permitted amount correctly in permit payload."
    }
  }
};

export const MINI_KIT_VERIFY_DEVICE_FALLBACK_CODES = new Set([
  "credential_unavailable",
  "inclusion_proof_failed",
  "verification_rejected"
]);

function normalizeCode(code: string): string {
  return code.trim().toLowerCase();
}

export function formatMiniKitError(command: MiniKitCommand, code: string): string | null {
  const normalizedCode = normalizeCode(code);
  const info = MINI_KIT_ERROR_CATALOG[command][normalizedCode];
  if (!info) {
    return null;
  }
  return `${command} error (${normalizedCode}): ${info.description} ${info.fix}`;
}

export function formatKnownMiniKitMessage(rawMessage: string): string | null {
  const message = rawMessage.trim();
  const verifyFailedMatch = message.match(/^world_id_verify_failed:\s*([a-z0-9_]+)$/i);
  if (verifyFailedMatch) {
    return formatMiniKitError("verify", verifyFailedMatch[1]);
  }
  if (message.includes("GS026")) {
    return "Signature validation failed (GS026). Verify Permit args order and ensure nonce/timestamp match the signed payload.";
  }
  return null;
}

import { defineChain } from "thirdweb";
import { getWalletBalance } from "thirdweb/wallets";
import { thirdwebClient } from "./thirdweb";

const DEFAULT_WORLDCHAIN_SEPOLIA_CHAIN_ID = 4801;
const rawWorldChainSepoliaChainId = Number.parseInt((import.meta.env.VITE_WORLDCHAIN_SEPOLIA_CHAIN_ID || "4801").trim(), 10);
const worldChainSepoliaChainId = Number.isInteger(rawWorldChainSepoliaChainId) && rawWorldChainSepoliaChainId > 0
  ? rawWorldChainSepoliaChainId
  : DEFAULT_WORLDCHAIN_SEPOLIA_CHAIN_ID;
const worldChainSepoliaRpcUrl = (import.meta.env.VITE_WORLDCHAIN_SEPOLIA_RPC_URL || "").trim();

const virtualTokenEnvList = (import.meta.env.VITE_WORLDCHAIN_VIRTUAL_TOKEN_ADDRESSES || "").trim();
const fallbackStakeTokenAddress = (import.meta.env.VITE_STAKE_TOKEN_ADDRESS || "").trim();

function isLikelyEvmAddress(value: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(value.trim());
}

function parseVirtualTokenAddresses(): string[] {
  const envTokens = String(virtualTokenEnvList || "")
    .split(",")
    .map((value: string) => value.trim());
  const combined = [
    ...envTokens,
    fallbackStakeTokenAddress
  ]
    .map((value: string) => value.trim())
    .filter(Boolean)
    .filter((value: string) => isLikelyEvmAddress(value));

  return Array.from(new Set(combined));
}

const worldChainVirtualTokenAddresses = parseVirtualTokenAddresses();

export const worldChainSepoliaChain = defineChain(
  worldChainSepoliaRpcUrl
    ? {
        id: worldChainSepoliaChainId,
        name: "World Chain Sepolia",
        rpc: worldChainSepoliaRpcUrl,
        testnet: true
      }
    : {
        id: worldChainSepoliaChainId,
        name: "World Chain Sepolia",
        testnet: true
      }
);

type WalletBalanceResult = Awaited<ReturnType<typeof getWalletBalance>>;

export interface WorldChainVirtualBalanceItem {
  tokenAddress: string;
  balance: WalletBalanceResult | null;
  error?: string;
}

export interface WorldChainVirtualBalanceSnapshot {
  native: WalletBalanceResult | null;
  tokens: WorldChainVirtualBalanceItem[];
}

export function getWorldChainVirtualConfig(): {
  chainId: number;
  rpcUrl: string;
  tokenAddresses: string[];
} {
  return {
    chainId: worldChainSepoliaChainId,
    rpcUrl: worldChainSepoliaRpcUrl,
    tokenAddresses: worldChainVirtualTokenAddresses
  };
}

export async function fetchWorldChainVirtualBalances(walletAddress: string): Promise<WorldChainVirtualBalanceSnapshot> {
  const native = await getWalletBalance({
    chain: worldChainSepoliaChain,
    address: walletAddress,
    client: thirdwebClient
  });

  const tokenBalances = await Promise.all(
    worldChainVirtualTokenAddresses.map(async (tokenAddress) => {
      try {
        const balance = await getWalletBalance({
          chain: worldChainSepoliaChain,
          address: walletAddress,
          client: thirdwebClient,
          tokenAddress
        });
        return {
          tokenAddress,
          balance
        };
      } catch (error) {
        return {
          tokenAddress,
          balance: null,
          error: error instanceof Error ? error.message : String(error)
        };
      }
    })
  );

  return {
    native,
    tokens: tokenBalances
  };
}

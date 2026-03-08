import { defineChain } from "thirdweb";

const DEFAULT_WORLDCHAIN_SEPOLIA_CHAIN_ID = 4801;
const rawWorldChainSepoliaChainId = Number.parseInt((import.meta.env.VITE_WORLDCHAIN_SEPOLIA_CHAIN_ID || "4801").trim(), 10);
const worldChainSepoliaChainId = Number.isInteger(rawWorldChainSepoliaChainId) && rawWorldChainSepoliaChainId > 0
  ? rawWorldChainSepoliaChainId
  : DEFAULT_WORLDCHAIN_SEPOLIA_CHAIN_ID;
const worldChainSepoliaRpcUrl = (import.meta.env.VITE_WORLDCHAIN_SEPOLIA_RPC_URL || "").trim();
const virtualChainName = (import.meta.env.VITE_WORLDCHAIN_NETWORK_NAME || "World Chain Sepolia").trim();

export const worldChainSepoliaChain = defineChain(
  worldChainSepoliaRpcUrl
    ? {
        id: worldChainSepoliaChainId,
        name: virtualChainName,
        rpc: worldChainSepoliaRpcUrl,
        testnet: true
      }
    : {
        id: worldChainSepoliaChainId,
        name: virtualChainName,
        testnet: true
      }
);

export function getWorldChainVirtualConfig(): {
  chainId: number;
  chainName: string;
  rpcUrl: string;
} {
  return {
    chainId: worldChainSepoliaChainId,
    chainName: virtualChainName,
    rpcUrl: worldChainSepoliaRpcUrl
  };
}

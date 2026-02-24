import { createThirdwebClient } from "thirdweb";

const clientId = (import.meta.env.VITE_THIRDWEB_CLIENT_ID || "").trim();

export const thirdwebClient = createThirdwebClient({
  clientId: clientId || "thirdweb-client-id-not-set"
});

export function isThirdwebClientConfigured(): boolean {
  return clientId.length > 0;
}

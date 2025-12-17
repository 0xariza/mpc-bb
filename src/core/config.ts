import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "../..");

export const config = {
  server: { name: "blockchain-security-mcp", version: "1.0.0" },
  paths: {
    root: ROOT_DIR,
    data: path.join(ROOT_DIR, "data"),
    logs: path.join(ROOT_DIR, "logs"),
    chroma: path.join(ROOT_DIR, "data/chroma"),
    sqlite: path.join(ROOT_DIR, "data/sqlite"),
  },
  vectorDb: {
    // ChromaDB HTTP API endpoint
    url: process.env.CHROMA_URL || "http://localhost:8000",
  },
  timeouts: { default: 60000, analysis: 300000 },
  limits: { maxFileSize: 10485760 },
  rpc: {
    ethereum: process.env.ETH_RPC_URL || "https://eth.llamarpc.com",
    polygon: process.env.POLYGON_RPC_URL || "https://polygon.llamarpc.com",
    arbitrum: process.env.ARBITRUM_RPC_URL || "https://arbitrum.llamarpc.com",
  },
  features: { 
    verboseLogging: process.env.NODE_ENV !== "production",
    enableVectorDb: process.env.ENABLE_VECTOR_DB !== "false",
    enableSqlite: process.env.ENABLE_SQLITE !== "false",
  },
  isDev: process.env.NODE_ENV !== "production",
} as const;

export function getRpcUrl(chain: string): string {
  return (config.rpc as Record<string, string>)[chain] || config.rpc.ethereum;
}

export function validateConfig(): void {}

/**
 * Ingest Attack Vectors Tool
 * ==========================
 * 
 * Ingest Solidity Attack Vectors into the knowledge base.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger, config } from "../../core/index.js";
import { ingestSwcRegistry } from "../../services/knowledge.service.js";
import { 
  parseAllAttackVectors,
  convertToSwcEntries,
  getAttackVectorStatistics 
} from "../../services/solidity-attack-vectors.service.js";
import * as path from "path";

/**
 * Register the ingest_attack_vectors tool
 */
export function registerIngestAttackVectors(server: McpServer): void {
  server.tool(
    "ingest_attack_vectors",
    "Ingest Solidity Attack Vectors into the knowledge base as SWC-like entries",
    {},
    async () => {
      try {
        logger.info("Ingesting Solidity Attack Vectors");
        
        const basePath = path.join(config.paths.root, "resource", "Solidity-Attack-Vectors");
        const vectors = parseAllAttackVectors(basePath);
        
        if (vectors.length === 0) {
          return errorResponse("No attack vectors found", { path: basePath });
        }
        
        // Convert to SWC entries
        const swcEntries = convertToSwcEntries(vectors);
        
        // Ingest into knowledge base
        const count = await ingestSwcRegistry(swcEntries);
        
        const stats = getAttackVectorStatistics(vectors);
        
        return jsonResponse({
          success: true,
          message: `Ingested ${count} attack vector entries`,
          summary: {
            total: count,
            byCategory: stats.byCategory,
            bySeverity: stats.bySeverity,
            withCodeExamples: stats.withCodeExamples,
            withReferences: stats.withReferences,
          },
        });
        
      } catch (e) {
        logger.error("Failed to ingest attack vectors", { error: e });
        return errorResponse("Ingestion failed", { error: String(e) });
      }
    }
  );
}

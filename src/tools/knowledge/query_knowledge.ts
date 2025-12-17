/**
 * Query Knowledge Tool
 * ====================
 * 
 * Search the knowledge base for relevant information.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger } from "../../core/index.js";
import { 
  querySWC, 
  findSimilarExploits, 
  findSimilarAuditFindings,
  searchAll 
} from "../../services/knowledge.service.js";

/**
 * Register the query_knowledge tool
 */
export function registerQueryKnowledge(server: McpServer): void {
  server.tool(
    "query_knowledge",
    "Search the security knowledge base for vulnerabilities, exploits, and audit findings",
    {
      query: z.string().describe("Search query (vulnerability type, code pattern, protocol name, etc.)"),
      collection: z.enum(["all", "swc", "exploits", "audit_findings"])
        .optional()
        .default("all")
        .describe("Which collection to search"),
      limit: z.number()
        .optional()
        .default(5)
        .describe("Maximum number of results per collection"),
      filters: z.object({
        severity: z.string().optional(),
        category: z.string().optional(),
      }).optional().describe("Optional filters"),
    },
    async ({ query, collection, limit, filters }) => {
      try {
        logger.info("Querying knowledge base", { query, collection, limit });
        
        let results: Record<string, unknown>;
        
        if (collection === "all") {
          const allResults = await searchAll(query, limit);
          results = {
            swc: allResults.swc.map(formatResult),
            exploits: allResults.exploits.map(formatResult),
            auditFindings: allResults.auditFindings.map(formatResult),
          };
        } else if (collection === "swc") {
          const swcResults = await querySWC(query, limit);
          results = { swc: swcResults.map(formatResult) };
        } else if (collection === "exploits") {
          const exploitResults = await findSimilarExploits(query, { 
            limit, 
            category: filters?.category 
          });
          results = { exploits: exploitResults.map(formatResult) };
        } else {
          const auditResults = await findSimilarAuditFindings(query, { 
            limit, 
            severity: filters?.severity 
          });
          results = { auditFindings: auditResults.map(formatResult) };
        }
        
        return jsonResponse({
          query,
          collection,
          results,
        });
        
      } catch (e) {
        logger.error("Failed to query knowledge base", { query, error: e });
        return errorResponse("Query failed", { error: String(e) });
      }
    }
  );
}

/**
 * Format a query result for display
 */
function formatResult(result: { id: string; document: string; metadata: Record<string, unknown>; distance: number }) {
  return {
    id: result.id,
    relevance: Math.round((1 - result.distance) * 100) + "%",
    metadata: result.metadata,
    excerpt: result.document.substring(0, 300) + (result.document.length > 300 ? "..." : ""),
  };
}

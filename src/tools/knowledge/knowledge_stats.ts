/**
 * Knowledge Stats Tool
 * ====================
 * 
 * Get statistics about the knowledge base.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger } from "../../core/index.js";
import { getKnowledgeStats } from "../../services/knowledge.service.js";
import { getRuleStats } from "../../database/repositories/rule.repo.js";
import { getToolRunStats } from "../../database/repositories/tool-run.repo.js";

/**
 * Register the knowledge_stats tool
 */
export function registerKnowledgeStats(server: McpServer): void {
  server.tool(
    "knowledge_stats",
    "Get statistics about the security knowledge base",
    {
      includeToolStats: z.boolean()
        .optional()
        .default(false)
        .describe("Include tool run statistics"),
    },
    async ({ includeToolStats }) => {
      try {
        const stats = await getKnowledgeStats();
        const ruleStats = getRuleStats();
        
        const result: Record<string, unknown> = {
          vectorDatabase: {
            collections: stats.vectorDb,
            totalDocuments: Object.values(stats.vectorDb).reduce((a, b) => a + b, 0),
          },
          findings: stats.findings,
          detectionRules: ruleStats,
        };
        
        if (includeToolStats) {
          result.toolRuns = getToolRunStats();
        }
        
        // Calculate accuracy if we have validated findings
        const { validated, falsePositives } = stats.findings;
        if (validated + falsePositives > 0) {
          result.accuracy = {
            rate: Math.round((validated / (validated + falsePositives)) * 100) + "%",
            validated,
            falsePositives,
            pending: stats.findings.pending,
          };
        }
        
        logger.info("Knowledge stats retrieved");
        
        return jsonResponse(result);
        
      } catch (e) {
        logger.error("Failed to get knowledge stats", { error: e });
        return errorResponse("Failed to get statistics", { error: String(e) });
      }
    }
  );
}

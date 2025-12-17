/**
 * Find Similar Tool
 * =================
 * 
 * Find similar exploits or vulnerabilities based on code or description.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger } from "../../core/index.js";
import { findSimilarExploits, findSimilarAuditFindings } from "../../services/knowledge.service.js";
import { exists, readFile } from "../../utils/file.utils.js";

/**
 * Register the find_similar tool
 */
export function registerFindSimilar(server: McpServer): void {
  server.tool(
    "find_similar",
    "Find similar historical exploits or audit findings based on code snippet or vulnerability description",
    {
      input: z.string().describe("Code snippet, vulnerability description, or file path"),
      inputType: z.enum(["code", "description", "file"])
        .optional()
        .default("description")
        .describe("Type of input"),
      searchIn: z.enum(["exploits", "audits", "both"])
        .optional()
        .default("both")
        .describe("Where to search"),
      limit: z.number()
        .optional()
        .default(5)
        .describe("Maximum number of results"),
    },
    async ({ input, inputType, searchIn, limit }) => {
      try {
        let searchText = input;
        
        // If file path, read the file
        if (inputType === "file") {
          if (!exists(input)) {
            return errorResponse("File not found", { path: input });
          }
          searchText = readFile(input);
        }
        
        logger.info("Finding similar", { inputType, searchIn, limit });
        
        const results: Record<string, unknown[]> = {};
        
        if (searchIn === "exploits" || searchIn === "both") {
          const exploitResults = await findSimilarExploits(searchText, { limit });
          results.exploits = exploitResults.map(r => ({
            id: r.id,
            similarity: Math.round((1 - r.distance) * 100) + "%",
            name: r.metadata.name,
            protocol: r.metadata.protocol,
            category: r.metadata.category,
            loss: r.metadata.loss,
            description: r.document.substring(0, 500),
          }));
        }
        
        if (searchIn === "audits" || searchIn === "both") {
          const auditResults = await findSimilarAuditFindings(searchText, { limit });
          results.auditFindings = auditResults.map(r => ({
            id: r.id,
            similarity: Math.round((1 - r.distance) * 100) + "%",
            title: r.metadata.title,
            severity: r.metadata.severity,
            protocol: r.metadata.protocol,
            auditor: r.metadata.auditor,
            description: r.document.substring(0, 500),
          }));
        }
        
        // Provide recommendations based on results
        const recommendations = generateRecommendations(results);
        
        return jsonResponse({
          inputType,
          searchIn,
          results,
          recommendations,
        });
        
      } catch (e) {
        logger.error("Failed to find similar", { error: e });
        return errorResponse("Search failed", { error: String(e) });
      }
    }
  );
}

/**
 * Generate recommendations based on similar findings
 */
function generateRecommendations(results: Record<string, unknown[]>): string[] {
  const recommendations: string[] = [];
  
  // Check exploit categories
  const exploits = (results.exploits || []) as any[];
  const categories = new Set(exploits.map(e => e.category));
  
  if (categories.has("reentrancy")) {
    recommendations.push("Consider adding reentrancy guards (ReentrancyGuard or nonReentrant modifier)");
    recommendations.push("Follow checks-effects-interactions pattern");
  }
  
  if (categories.has("flash-loan")) {
    recommendations.push("Implement flash loan protections if using external price feeds");
    recommendations.push("Consider using TWAP oracles instead of spot prices");
  }
  
  if (categories.has("oracle-manipulation")) {
    recommendations.push("Use multiple oracle sources for price feeds");
    recommendations.push("Implement price deviation checks");
  }
  
  if (categories.has("access-control")) {
    recommendations.push("Review all privileged functions for proper access control");
    recommendations.push("Consider using role-based access control (OpenZeppelin AccessControl)");
  }
  
  // Check audit severity
  const audits = (results.auditFindings || []) as any[];
  const criticalAudits = audits.filter(a => a.severity === "critical");
  
  if (criticalAudits.length > 0) {
    recommendations.push("Similar code patterns have had CRITICAL findings in past audits - review carefully");
  }
  
  if (recommendations.length === 0) {
    recommendations.push("No specific patterns matched known exploits - still recommend thorough review");
  }
  
  return recommendations;
}

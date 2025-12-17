/**
 * Analyze DeFiHackLabs Tool
 * ========================
 * 
 * Analyze the DeFiHackLabs repository and provide statistics.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger, config } from "../../core/index.js";
import { 
  scanDeFiHackLabs, 
  getExploitStatistics 
} from "../../services/defihacklabs.service.js";
import * as path from "path";
import * as fs from "fs";

/**
 * Register the analyze_defihacklabs tool
 */
export function registerAnalyzeDeFiHackLabs(server: McpServer): void {
  server.tool(
    "analyze_defihacklabs",
    "Analyze DeFiHackLabs repository and provide statistics about exploits",
    {
      scan: z.boolean()
        .optional()
        .default(false)
        .describe("Scan the repository (may take time for large repos)"),
    },
    async ({ scan }) => {
      try {
        const defihacklabsPath = path.join(config.paths.root, "resource", "DeFiHackLabs");
        
        if (scan) {
          logger.info("Scanning DeFiHackLabs repository", { path: defihacklabsPath });
          const exploits = scanDeFiHackLabs(defihacklabsPath);
          const stats = getExploitStatistics(exploits);
          
          // Get top protocols
          const topProtocols = Object.entries(stats.byProtocol)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([protocol, count]) => ({ protocol, count }));
          
          // Get top vulnerability types
          const topVulnerabilities = Object.entries(stats.vulnerabilityTypes)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15)
            .map(([vuln, count]) => ({ vulnerability: vuln, count }));
          
          return jsonResponse({
            success: true,
            scanned: true,
            statistics: {
              total: stats.total,
              byCategory: stats.byCategory,
              byYear: stats.byYear,
              topProtocols,
              topVulnerabilities,
            },
            summary: {
              totalExploits: stats.total,
              categories: Object.keys(stats.byCategory).length,
              years: Object.keys(stats.byYear).length,
              protocols: Object.keys(stats.byProtocol).length,
              vulnerabilityTypes: Object.keys(stats.vulnerabilityTypes).length,
            },
          });
        } else {
          // Just check if directory exists
          const testDir = path.join(defihacklabsPath, "src", "test");
          const exists = fs.existsSync(testDir);
          
          return jsonResponse({
            success: true,
            scanned: false,
            repository: {
              path: defihacklabsPath,
              exists,
              testDirectory: testDir,
            },
            message: exists 
              ? "Repository found. Use scan=true to analyze exploits."
              : "Repository not found. Please ensure DeFiHackLabs is cloned in resource/DeFiHackLabs",
          });
        }
      } catch (e) {
        logger.error("Failed to analyze DeFiHackLabs", { error: e });
        return errorResponse("Analysis failed", { error: String(e) });
      }
    }
  );
}

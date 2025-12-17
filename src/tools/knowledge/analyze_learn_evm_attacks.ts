/**
 * Analyze Learn EVM Attacks Tool
 * ==============================
 * 
 * Analyze the learn-evm-attacks repository and provide statistics.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger, config } from "../../core/index.js";
import { 
  scanLearnEVMAttacks, 
  getExploitStatistics 
} from "../../services/learn-evm-attacks.service.js";
import * as path from "path";
import * as fs from "fs";

/**
 * Register the analyze_learn_evm_attacks tool
 */
export function registerAnalyzeLearnEVMAttacks(server: McpServer): void {
  server.tool(
    "analyze_learn_evm_attacks",
    "Analyze learn-evm-attacks repository and provide statistics about exploits",
    {
      scan: z.boolean()
        .optional()
        .default(false)
        .describe("Scan the repository (may take time for large repos)"),
    },
    async ({ scan }) => {
      try {
        const learnEvmAttacksPath = path.join(config.paths.root, "resource", "learn-evm-attacks");
        
        if (scan) {
          logger.info("Scanning learn-evm-attacks repository", { path: learnEvmAttacksPath });
          const exploits = scanLearnEVMAttacks(learnEvmAttacksPath);
          const stats = getExploitStatistics(exploits);
          
          // Get top categories
          const topCategories = Object.entries(stats.byCategory)
            .sort((a, b) => b[1] - a[1])
            .map(([category, count]) => ({ category, count }));
          
          // Get top vulnerability types
          const topVulnerabilities = Object.entries(stats.vulnerabilityTypes)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15)
            .map(([vuln, count]) => ({ vulnerability: vuln, count }));
          
          // Get top networks
          const topNetworks = Object.entries(stats.byNetwork)
            .sort((a, b) => b[1] - a[1])
            .map(([network, count]) => ({ network, count }));
          
          return jsonResponse({
            success: true,
            scanned: true,
            statistics: {
              total: stats.total,
              byCategory: stats.byCategory,
              byYear: stats.byYear,
              byNetwork: stats.byNetwork,
              topCategories,
              topVulnerabilities,
              topNetworks,
              totalLossUsd: stats.totalLoss,
              totalLossFormatted: `$${stats.totalLoss.toLocaleString()}`,
            },
            summary: {
              totalExploits: stats.total,
              categories: Object.keys(stats.byCategory).length,
              years: Object.keys(stats.byYear).length,
              networks: Object.keys(stats.byNetwork).length,
              vulnerabilityTypes: Object.keys(stats.vulnerabilityTypes).length,
              totalLossUsd: stats.totalLoss,
            },
          });
        } else {
          // Just check if directory exists
          const testDir = path.join(learnEvmAttacksPath, "test");
          const exists = fs.existsSync(testDir);
          
          return jsonResponse({
            success: true,
            scanned: false,
            repository: {
              path: learnEvmAttacksPath,
              exists,
              testDirectory: testDir,
            },
            message: exists 
              ? "Repository found. Use scan=true to analyze exploits."
              : "Repository not found. Please ensure learn-evm-attacks is cloned in resource/learn-evm-attacks",
          });
        }
      } catch (e) {
        logger.error("Failed to analyze learn-evm-attacks", { error: e });
        return errorResponse("Analysis failed", { error: String(e) });
      }
    }
  );
}

/**
 * Analyze Solidity Attack Vectors Tool
 * ====================================
 *
 * Parses the Solidity-Attack-Vectors repository index and summarizes
 * known attack vectors and their high-level categories.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger, config } from "../../core/index.js";
import { 
  parseAllAttackVectors,
  getAttackVectorStatistics,
  convertToSwcEntries 
} from "../../services/solidity-attack-vectors.service.js";
import * as fs from "fs";
import * as path from "path";

interface AttackVector {
  id: number;
  name: string;
  category: string;
  sourcePath: string | null;
}

/**
 * Heuristically categorize an attack vector name
 */
function categorizeVector(name: string): string {
  const lower = name.toLowerCase();

  if (lower.includes("re-entrancy") || lower.includes("reentrancy")) return "reentrancy";
  if (lower.includes("access control") || lower.includes("ownership") || lower.includes("authorization")) return "access-control";
  if (lower.includes("arithmetic") || lower.includes("over/under") || lower.includes("overflow") || lower.includes("underflow")) return "integer-overflow";
  if (lower.includes("randomness") || lower.includes("entropy")) return "weak-randomness";
  if (lower.includes("timestamp") || lower.includes("block")) return "time-manipulation";
  if (lower.includes("delegatecall")) return "delegatecall";
  if (lower.includes("dos") || lower.includes("denial")) return "dos";
  if (lower.includes("price") || lower.includes("manipulation")) return "oracle-manipulation";
  if (lower.includes("short address") || lower.includes("parameter")) return "input-validation";
  if (lower.includes("validation") || lower.includes("check")) return "improper-validation";
  if (lower.includes("logic") || lower.includes("logical")) return "logic-error";
  if (lower.includes("signature")) return "signature";
  if (lower.includes("storage") || lower.includes("state variable")) return "storage";
  if (lower.includes("visibility")) return "visibility";
  if (lower.includes("selfdestruct")) return "selfdestruct";

  return "other";
}

/**
 * Determine severity (helper function)
 */
function determineSeverity(category: string, name: string): string {
  const criticalCategories = ["reentrancy", "access-control", "delegatecall", "selfdestruct"];
  const highCategories = ["integer-overflow", "oracle-manipulation", "signature", "upgrade"];
  
  if (criticalCategories.includes(category)) return "critical";
  if (highCategories.includes(category)) return "high";
  if (name.toLowerCase().includes("critical") || name.toLowerCase().includes("unprotected")) return "high";
  
  return "medium";
}

/**
 * Parse attack vectors table from README
 */
function parseAttackVectors(readmePath: string): AttackVector[] {
  const content = fs.readFileSync(readmePath, "utf-8");
  const lines = content.split(/\r?\n/);

  const vectors: AttackVector[] = [];
  let inTable = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (!inTable) {
      // Detect start of table (header row)
      if (trimmed.startsWith("Serial No. |")) {
        inTable = true;
      }
      continue;
    }

    // Stop if we reach a non-table section
    if (!trimmed || trimmed.startsWith("---")) continue;
    if (!trimmed.includes("|")) break;

    // Expected format: **1** | [Name](data/1.md)
    const parts = trimmed.split("|").map(p => p.trim());
    if (parts.length < 2) continue;

    const idMatch = parts[0].match(/\*\*(\d+)\*\*/);
    const linkMatch = parts[1].match(/\[(.+?)\]\((.+?)\)/);

    if (!idMatch || !linkMatch) continue;

    const id = parseInt(idMatch[1], 10);
    const name = linkMatch[1].trim();
    const relPath = linkMatch[2].trim();
    const sourcePath = relPath ? relPath : null;
    const category = categorizeVector(name);

    vectors.push({ id, name, category, sourcePath });
  }

  return vectors;
}

/**
 * Register the analyze_attack_vectors tool
 */
export function registerAnalyzeAttackVectors(server: McpServer): void {
  server.tool(
    "analyze_attack_vectors",
    "Analyze Solidity-Attack-Vectors index and summarize known attack vectors",
    {
      includeList: z.boolean()
        .optional()
        .default(false)
        .describe("Include full list of attack vectors in the response"),
      deepAnalysis: z.boolean()
        .optional()
        .default(false)
        .describe("Parse detailed information from individual attack vector files"),
    },
    async ({ includeList, deepAnalysis }) => {
      try {
        const basePath = path.join(config.paths.root, "resource", "Solidity-Attack-Vectors");
        const readmePath = path.join(basePath, "README.md");

        if (!fs.existsSync(readmePath)) {
          return errorResponse("Solidity-Attack-Vectors README not found", { path: readmePath });
        }

        if (deepAnalysis) {
          // Deep analysis: parse all individual files
          logger.info("Performing deep analysis of Solidity-Attack-Vectors", { path: basePath });
          const vectors = parseAllAttackVectors(basePath);
          const stats = getAttackVectorStatistics(vectors);
          
          // Get top categories
          const topCategories = Object.entries(stats.byCategory)
            .sort((a, b) => b[1] - a[1])
            .map(([category, count]) => ({ category, count }));
          
          // Get severity breakdown
          const severityBreakdown = Object.entries(stats.bySeverity)
            .sort((a, b) => {
              const order = { critical: 0, high: 1, medium: 2, low: 3 };
              return (order[a[0] as keyof typeof order] ?? 99) - (order[b[0] as keyof typeof order] ?? 99);
            })
            .map(([severity, count]) => ({ severity, count }));
          
          return jsonResponse({
            success: true,
            deepAnalysis: true,
            repository: basePath,
            statistics: {
              total: stats.total,
              byCategory: stats.byCategory,
              bySeverity: stats.bySeverity,
              topCategories,
              severityBreakdown,
              withCodeExamples: stats.withCodeExamples,
              withReferences: stats.withReferences,
              totalReferences: stats.totalReferences,
            },
            summary: {
              totalVectors: stats.total,
              categories: Object.keys(stats.byCategory).length,
              critical: stats.bySeverity.critical || 0,
              high: stats.bySeverity.high || 0,
              medium: stats.bySeverity.medium || 0,
              vectorsWithCode: stats.withCodeExamples,
              vectorsWithReferences: stats.withReferences,
            },
            vectors: includeList
              ? vectors.map(v => ({
                  id: v.id,
                  name: v.name,
                  category: v.category,
                  severity: determineSeverity(v.category, v.name),
                  description: v.description.substring(0, 200) + (v.description.length > 200 ? "..." : ""),
                  hasCodeExamples: v.codeExamples.length > 0,
                  referenceCount: v.references.length,
                  sourcePath: v.sourcePath,
                }))
              : undefined,
            references: {
              swcRegistry: "https://swcregistry.io/",
              defiThreat: "https://github.com/manifoldfinance/defi-threat",
              daspTop10: "https://www.dasp.co/",
            },
          });
        } else {
          // Quick analysis: just parse index
          logger.info("Analyzing Solidity-Attack-Vectors index", { path: readmePath });
          const vectors = parseAttackVectors(readmePath);

          const byCategory: Record<string, number> = {};
          for (const v of vectors) {
            byCategory[v.category] = (byCategory[v.category] || 0) + 1;
          }

          const total = vectors.length;
          const sortedCategories = Object.entries(byCategory)
            .sort((a, b) => b[1] - a[1])
            .map(([category, count]) => ({ category, count }));

          return jsonResponse({
            success: true,
            deepAnalysis: false,
            repository: basePath,
            totalVectors: total,
            categories: sortedCategories,
            message: "Use deepAnalysis=true to parse detailed information from individual files",
            references: {
              swcRegistry: "https://swcregistry.io/",
              defiThreat: "https://github.com/manifoldfinance/defi-threat",
              daspTop10: "https://www.dasp.co/",
            },
            vectors: includeList
              ? vectors.map(v => ({
                  id: v.id,
                  name: v.name,
                  category: v.category,
                  sourcePath: v.sourcePath,
                }))
              : undefined,
          });
        }
      } catch (e) {
        logger.error("Failed to analyze Solidity-Attack-Vectors", { error: e });
        return errorResponse("Analysis failed", { error: String(e) });
      }
    }
  );
}

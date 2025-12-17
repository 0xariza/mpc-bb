/**
 * Comprehensive Analysis Tool
 * ============================
 * 
 * Performs complete security analysis combining:
 * - Contract static analysis
 * - Knowledge base queries
 * - Similar exploit detection
 * - SWC Registry matching
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger, config } from "../../core/index.js";
import { exists, readFile, getFileInfo } from "../../utils/file.utils.js";
import { 
  extractFunctions, 
  extractMetadata,
  checkVulnerabilityIndicators, 
  detectProtocolType 
} from "../../utils/solidity.utils.js";
import { 
  searchAll,
  findSimilarExploits,
  findSimilarAuditFindings,
  querySWC
} from "../../services/knowledge.service.js";
import { isToolInstalled, executeCommand } from "../../utils/command.utils.js";
import * as path from "path";

/**
 * Register the comprehensive_analysis tool
 */
export function registerComprehensiveAnalysis(server: McpServer): void {
  server.registerTool(
    "comprehensive_analysis",
    {
      title: "Comprehensive Security Analysis",
      description: "Perform comprehensive security analysis combining contract analysis with knowledge base queries",
      inputSchema: z.object({
        path: z.string().describe("Path to the .sol file to analyze"),
        includeKnowledgeBase: z.boolean()
          .optional()
          .default(true)
          .describe("Include knowledge base queries from all sources"),
        knowledgeLimit: z.number()
          .optional()
          .default(10)
          .describe("Number of knowledge base results per collection (increased for comprehensive analysis)"),
        includeSimilarExploits: z.boolean()
          .optional()
          .default(true)
          .describe("Find similar historical exploits from all sources"),
        useExternalTools: z.boolean()
          .optional()
          .default(true)
          .describe("Use external security tools (slither, solhint, mythril) if available"),
        comprehensiveMode: z.boolean()
          .optional()
          .default(true)
          .describe("Enable comprehensive mode - uses all available analysis methods"),
      }),
    },
    async ({ path: p, includeKnowledgeBase, knowledgeLimit, includeSimilarExploits, useExternalTools, comprehensiveMode }) => {
      try {
        if (!exists(p)) {
          return errorResponse("File not found", { path: p });
        }

        logger.info("Starting comprehensive analysis", { path: p });

        // Step 1: Enhanced contract analysis
        const content = readFile(p);
        const metadata = extractMetadata(content);
        const fns = extractFunctions(content);
        const externalFns = fns.filter(f => f.visibility === "external");
        const publicFns = fns.filter(f => f.visibility === "public");
        const payableFns = fns.filter(f => f.mutability === "payable");
        const viewFns = fns.filter(f => f.mutability === "view" || f.mutability === "pure");
        
        // Enhanced vulnerability detection
        const indicators = checkVulnerabilityIndicators(content);
        const criticalIssues = indicators.filter(i => i.includes("CRITICAL"));
        const highIssues = indicators.filter(i => i.includes("HIGH"));
        const mediumIssues = indicators.filter(i => i.includes("MEDIUM"));
        const lowIssues = indicators.filter(i => i.includes("LOW"));
        
        // Compiler version analysis
        const compilerVersions = metadata.pragmas.map(p => {
          const match = p.match(/solidity\s+([^;]+)/);
          return match ? match[1].trim() : "unknown";
        });
        const hasFloatingPragma = compilerVersions.some(v => v.includes("^") || v.includes(">=") || v.includes("~"));
        const hasOutdatedCompiler = compilerVersions.some(v => {
          const versionMatch = v.match(/0\.(\d+)\./);
          if (versionMatch) {
            const major = parseInt(versionMatch[1]);
            return major < 8;
          }
          return false;
        });
        
        // Dependency analysis
        const dependencies = metadata.imports.map(imp => {
          const match = imp.match(/["']([^"']+)["']/);
          return match ? match[1] : imp;
        });
        const hasOpenZeppelin = dependencies.some(d => d.includes("openzeppelin") || d.includes("OpenZeppelin"));
        const hasExternalDependencies = dependencies.length > 0;
        
        // Function security analysis
        const privilegedFunctions = externalFns.filter(f => {
          const fnContent = extractFunctionContent(content, f.name);
          return fnContent && (
            fnContent.includes("transfer") || 
            fnContent.includes("withdraw") || 
            fnContent.includes("setOwner") ||
            fnContent.includes("destroy") ||
            fnContent.includes("kill")
          ) && !fnContent.includes("onlyOwner") && !fnContent.includes("AccessControl");
        });
        
        const contractAnalysis = {
          file: getFileInfo(p),
          metadata: {
            contracts: metadata.contracts,
            interfaces: metadata.interfaces,
            libraries: metadata.libraries,
            compilerVersions,
            hasFloatingPragma,
            hasOutdatedCompiler,
            dependencies,
            hasOpenZeppelin,
            hasExternalDependencies,
          },
          summary: {
            totalFunctions: fns.length,
            external: externalFns.length,
            public: publicFns.length,
            payable: payableFns.length,
            view: viewFns.length,
            stateChanging: fns.filter(f => 
              f.mutability !== "view" && f.mutability !== "pure"
            ).length,
          },
          security: {
            hasReentrancyGuard: content.includes("nonReentrant") || content.includes("ReentrancyGuard"),
            hasAccessControl: content.includes("onlyOwner") || content.includes("AccessControl"),
            hasSafeMath: content.includes("SafeMath") || compilerVersions.some(v => v.match(/0\.8\./)),
            indicators,
            severityBreakdown: {
              critical: criticalIssues.length,
              high: highIssues.length,
              medium: mediumIssues.length,
              low: lowIssues.length,
            },
            privilegedFunctionsWithoutAccessControl: privilegedFunctions.map(f => f.name),
          },
          protocols: detectProtocolType(content),
          functions: {
            external: externalFns.map(f => ({ name: f.name, line: f.lineNumber, mutability: f.mutability })),
            public: publicFns.map(f => ({ name: f.name, line: f.lineNumber, mutability: f.mutability })),
          },
        };
        
        // Step 1.5: External tool analysis (if enabled and available)
        const externalTools: Record<string, unknown> = {};
        const contractDir = path.dirname(p);
        
        if (useExternalTools) {
          // Try Slither if available
          if (isToolInstalled("slither")) {
            try {
              logger.info("Running Slither analysis");
              const slitherResult = executeCommand("slither", [p, "--json", "-"], { 
                cwd: contractDir,
                timeout: config.timeouts.analysis 
              });
              if (slitherResult.success) {
                externalTools.slither = {
                  available: true,
                  status: "completed",
                  output: slitherResult.stdout.substring(0, 5000), // Limit output size
                };
              }
            } catch (e) {
              logger.warn("Slither analysis failed", { error: e });
              externalTools.slither = { available: true, status: "failed", error: String(e) };
            }
          } else {
            externalTools.slither = { available: false, hint: "pip install slither-analyzer" };
          }
          
          // Try Solhint if available
          if (isToolInstalled("solhint")) {
            try {
              logger.info("Running Solhint analysis");
              const solhintResult = executeCommand("solhint", [p], { 
                cwd: contractDir,
                timeout: 30000 
              });
              externalTools.solhint = {
                available: true,
                status: solhintResult.exitCode === 0 ? "passed" : "warnings",
                output: solhintResult.stdout.substring(0, 2000),
              };
            } catch (e) {
              externalTools.solhint = { available: true, status: "failed", error: String(e) };
            }
          } else {
            externalTools.solhint = { available: false, hint: "npm install -g solhint" };
          }
          
          // Try Mythril if available (comprehensive mode)
          if (comprehensiveMode && isToolInstalled("myth")) {
            try {
              logger.info("Running Mythril analysis");
              const mythrilResult = executeCommand("myth", ["analyze", p, "--execution-timeout", "60"], { 
                cwd: contractDir,
                timeout: config.timeouts.analysis 
              });
              externalTools.mythril = {
                available: true,
                status: mythrilResult.exitCode === 0 ? "completed" : "warnings",
                output: mythrilResult.stdout.substring(0, 5000),
              };
            } catch (e) {
              logger.warn("Mythril analysis failed", { error: e });
              externalTools.mythril = { available: true, status: "failed", error: String(e) };
            }
          } else if (comprehensiveMode) {
            externalTools.mythril = { available: false, hint: "pip install mythril" };
          }
        }

        // Step 2: Knowledge base queries (if enabled)
        let knowledgeResults: Record<string, unknown> = {};
        let similarExploits: unknown[] = [];

        if (includeKnowledgeBase) {
          // Build comprehensive query from contract analysis
          const queryParts: string[] = [];
          
          // Add ALL vulnerability indicators to query (comprehensive mode)
          contractAnalysis.security.indicators.forEach(indicator => {
            const lower = indicator.toLowerCase();
            if (lower.includes("reentrancy")) queryParts.push("reentrancy");
            if (lower.includes("access-control") || lower.includes("access control")) queryParts.push("access control");
            if (lower.includes("tx.origin")) queryParts.push("tx.origin phishing");
            if (lower.includes("delegatecall")) queryParts.push("delegatecall");
            if (lower.includes("overflow") || lower.includes("underflow")) queryParts.push("integer overflow");
            if (lower.includes("oracle") || lower.includes("price")) queryParts.push("oracle manipulation");
            if (lower.includes("flash") || lower.includes("flashloan")) queryParts.push("flash loan");
            if (lower.includes("random")) queryParts.push("weak randomness");
            if (lower.includes("dos") || lower.includes("denial")) queryParts.push("denial of service");
            if (lower.includes("validation")) queryParts.push("input validation");
            if (lower.includes("logic")) queryParts.push("logic error");
            if (lower.includes("signature")) queryParts.push("signature");
            if (lower.includes("storage")) queryParts.push("storage");
            if (lower.includes("visibility")) queryParts.push("visibility");
            if (lower.includes("selfdestruct")) queryParts.push("selfdestruct");
          });

          // Add protocol types
          contractAnalysis.protocols.forEach(protocol => {
            queryParts.push(protocol);
          });

          // Add function names that might indicate vulnerabilities
          const externalFnNames = contractAnalysis.functions.external.map(f => f.name);
          const publicFnNames = contractAnalysis.functions.public.map(f => f.name);
          const allFnNames = [...externalFnNames, ...publicFnNames];
          
          // Check for common vulnerable function patterns
          const vulnerablePatterns = ["withdraw", "transfer", "burn", "mint", "approve", "setOwner", "destroy", "kill", "upgrade"];
          for (const pattern of vulnerablePatterns) {
            if (allFnNames.some(name => name.toLowerCase().includes(pattern.toLowerCase()))) {
              queryParts.push(`${pattern} vulnerability`);
            }
          }

          // In comprehensive mode, add category-based queries
          if (comprehensiveMode) {
            const categories = new Set<string>();
            contractAnalysis.security.indicators.forEach((ind: string) => {
              const lower = ind.toLowerCase();
              if (lower.includes("critical")) categories.add("critical vulnerability");
              if (lower.includes("reentrancy")) categories.add("reentrancy attack");
              if (lower.includes("access")) categories.add("access control");
            });
            queryParts.push(...Array.from(categories));
          }

          // Create multiple queries for comprehensive search
          const primaryQuery = queryParts.length > 0 
            ? queryParts.join(" ") 
            : "smart contract security vulnerability";
          
          // Additional targeted queries in comprehensive mode
          const queries = comprehensiveMode ? [
            primaryQuery,
            ...contractAnalysis.security.indicators.slice(0, 3).map((ind: string) => ind.substring(0, 50)),
            ...contractAnalysis.protocols.map(p => `${p} security vulnerability`),
          ] : [primaryQuery];

          logger.info("Querying knowledge base comprehensively", { 
            queries: queries.length,
            limit: knowledgeLimit 
          });

          // Query all collections with multiple queries and aggregate results
          const allSwcResults: any[] = [];
          const allExploitResults: any[] = [];
          const allAuditResults: any[] = [];

          for (const query of queries) {
            const allResults = await searchAll(query, Math.ceil(knowledgeLimit / queries.length));
            
            // Aggregate results, avoiding duplicates
            const existingIds = new Set([
              ...allSwcResults.map(r => r.id),
              ...allExploitResults.map(r => r.id),
              ...allAuditResults.map(r => r.id),
            ]);
            
            for (const result of allResults.swc) {
              if (!existingIds.has(result.id)) {
                allSwcResults.push(formatResult(result));
                existingIds.add(result.id);
              }
            }
            
            for (const result of allResults.exploits) {
              if (!existingIds.has(result.id)) {
                allExploitResults.push(formatResult(result));
                existingIds.add(result.id);
              }
            }
            
            for (const result of allResults.auditFindings) {
              if (!existingIds.has(result.id)) {
                allAuditResults.push(formatResult(result));
                existingIds.add(result.id);
              }
            }
          }
          
          knowledgeResults = {
            swc: allSwcResults.slice(0, knowledgeLimit),
            exploits: allExploitResults.slice(0, knowledgeLimit),
            auditFindings: allAuditResults.slice(0, knowledgeLimit),
          };

          // Step 3: Find similar exploits from ALL sources (comprehensive mode)
          if (includeSimilarExploits) {
            logger.info("Finding similar exploits from all sources");
            
            // Search with contract code
            const similarFromCode = await findSimilarExploits(content, { 
              limit: comprehensiveMode ? knowledgeLimit * 2 : knowledgeLimit 
            });
            
            // Also search with vulnerability indicators
            const similarFromIndicators: any[] = [];
            if (comprehensiveMode && contractAnalysis.security.indicators.length > 0) {
              for (const indicator of contractAnalysis.security.indicators.slice(0, 3)) {
                const similar = await findSimilarExploits(indicator, { limit: 3 });
                similarFromIndicators.push(...similar);
              }
            }
            
            // Combine and deduplicate
            const allSimilar = [...similarFromCode, ...similarFromIndicators];
            const uniqueSimilar = new Map<string, any>();
            
            for (const r of allSimilar) {
              if (!uniqueSimilar.has(r.id)) {
                uniqueSimilar.set(r.id, r);
              }
            }
            
            similarExploits = Array.from(uniqueSimilar.values())
              .slice(0, knowledgeLimit * 2)
              .map(r => ({
                id: r.id,
                similarity: Math.round((1 - r.distance) * 100) + "%",
                name: r.metadata.name,
                protocol: r.metadata.protocol,
                category: r.metadata.category,
                loss: r.metadata.loss,
                date: r.metadata.date,
                source: r.metadata.source,
                description: r.document.substring(0, 500),
                attackVector: r.metadata.attackVector,
              }));
          }
        }

        // Step 4: Generate recommendations
        const recommendations = generateRecommendations(
          contractAnalysis,
          knowledgeResults,
          similarExploits
        );

        // Step 5: Risk assessment
        const riskLevel = assessRisk(contractAnalysis, knowledgeResults, similarExploits);

        logger.info("Comprehensive analysis complete", { 
          path: p, 
          riskLevel,
          indicators: contractAnalysis.security.indicators.length 
        });

        // Collect exploit sources for summary
        const exploitSources = new Set<string>();
        if (Array.isArray(similarExploits)) {
          for (const exp of similarExploits as any[]) {
            if (exp.source) exploitSources.add(exp.source);
          }
        }
        if (Array.isArray(knowledgeResults.exploits)) {
          for (const exp of knowledgeResults.exploits as any[]) {
            if (exp.metadata?.source) exploitSources.add(exp.metadata.source);
          }
        }

        return jsonResponse({
          contract: contractAnalysis,
          externalTools,
          knowledgeBase: includeKnowledgeBase ? {
            queries: knowledgeResults,
            similarExploits,
            sourcesUsed: Array.from(exploitSources),
          } : null,
          riskAssessment: {
            level: riskLevel.level,
            score: riskLevel.score,
            factors: riskLevel.factors,
          },
          recommendations,
          analysisMode: {
            comprehensive: comprehensiveMode,
            knowledgeBaseEnabled: includeKnowledgeBase,
            externalToolsEnabled: useExternalTools,
            similarExploitsEnabled: includeSimilarExploits,
          },
          summary: {
            totalFindings: contractAnalysis.security.indicators.length,
            criticalIssues: contractAnalysis.security.severityBreakdown.critical,
            highIssues: contractAnalysis.security.severityBreakdown.high,
            mediumIssues: contractAnalysis.security.severityBreakdown.medium,
            lowIssues: contractAnalysis.security.severityBreakdown.low,
            similarExploitsFound: similarExploits.length,
            knowledgeBaseMatches: includeKnowledgeBase 
              ? ((Array.isArray(knowledgeResults.exploits) ? (knowledgeResults.exploits as unknown[]).length : 0) + 
                 (Array.isArray(knowledgeResults.swc) ? (knowledgeResults.swc as unknown[]).length : 0) +
                 (Array.isArray(knowledgeResults.auditFindings) ? (knowledgeResults.auditFindings as unknown[]).length : 0))
              : 0,
            externalToolsUsed: Object.values(externalTools).filter((t: any) => t.available && (t.status === "completed" || t.status === "passed")).length,
            totalSources: includeKnowledgeBase 
              ? {
                  swcRegistry: Array.isArray(knowledgeResults.swc) ? (knowledgeResults.swc as unknown[]).length : 0,
                  exploits: Array.isArray(knowledgeResults.exploits) ? (knowledgeResults.exploits as unknown[]).length : 0,
                  auditFindings: Array.isArray(knowledgeResults.auditFindings) ? (knowledgeResults.auditFindings as unknown[]).length : 0,
                  similarExploits: similarExploits.length,
                  exploitSources: Array.from(exploitSources),
                }
              : null,
          },
        });

      } catch (e) {
        logger.error("Comprehensive analysis failed", { path: p, error: e });
        return errorResponse("Analysis failed", { error: String(e) });
      }
    }
  );
}

/**
 * Format a query result for display
 */
function formatResult(result: { 
  id: string; 
  document: string; 
  metadata: Record<string, unknown>; 
  distance: number 
}) {
  return {
    id: result.id,
    relevance: Math.round((1 - result.distance) * 100) + "%",
    metadata: result.metadata,
    excerpt: result.document.substring(0, 300) + (result.document.length > 300 ? "..." : ""),
  };
}

/**
 * Generate security recommendations
 */
function generateRecommendations(
  contractAnalysis: any,
  knowledgeResults: Record<string, unknown>,
  similarExploits: unknown[]
): string[] {
  const recommendations: string[] = [];

  // Check contract security indicators
  if (!contractAnalysis.security.hasReentrancyGuard) {
    recommendations.push("⚠️ Add reentrancy protection (ReentrancyGuard or nonReentrant modifier)");
  }

  if (!contractAnalysis.security.hasAccessControl) {
    recommendations.push("⚠️ Implement access control for privileged functions (onlyOwner or AccessControl)");
  }

  // Check indicators
  contractAnalysis.security.indicators.forEach((indicator: string) => {
    if (indicator.includes("reentrancy")) {
      recommendations.push("🔴 CRITICAL: Implement checks-effects-interactions pattern");
      recommendations.push("🔴 CRITICAL: Add reentrancy guard to all external calls");
    }
    if (indicator.includes("tx.origin")) {
      recommendations.push("🔴 CRITICAL: Replace tx.origin with msg.sender for authorization");
    }
    if (indicator.includes("delegatecall")) {
      recommendations.push("🔴 CRITICAL: Validate delegatecall target addresses");
    }
  });

  // Check similar exploits from ALL sources (DeFiHackLabs, learn-evm-attacks, builtin)
  const exploits = similarExploits as any[];
  const categories = new Set(exploits.map(e => e.category));
  const sources = new Set(exploits.map(e => e.source || "unknown"));

  if (categories.has("reentrancy")) {
    const reentrancyExploits = exploits.filter(e => e.category === "reentrancy");
    recommendations.push(`📚 ${reentrancyExploits.length} similar reentrancy exploits found from ${Array.from(new Set(reentrancyExploits.map(e => e.source))).join(", ")} - review historical attacks`);
    recommendations.push("📚 Implement checks-effects-interactions pattern");
  }
  if (categories.has("flash-loan")) {
    recommendations.push("📚 Implement flash loan attack protections");
    recommendations.push("📚 Use TWAP oracles instead of spot prices");
    recommendations.push("📚 Add slippage protection for all swaps");
  }
  if (categories.has("oracle-manipulation")) {
    recommendations.push("📚 Use multiple oracle sources for price feeds");
    recommendations.push("📚 Implement price deviation checks");
    recommendations.push("📚 Add time-weighted average price (TWAP) protection");
  }
  if (categories.has("access-control")) {
    recommendations.push("📚 Review all privileged functions for proper access control");
    recommendations.push("📚 Use role-based access control (OpenZeppelin AccessControl)");
  }
  if (categories.has("logic-error")) {
    recommendations.push("📚 Review contract logic for edge cases");
    recommendations.push("📚 Add comprehensive unit tests");
  }
  if (categories.has("integer-overflow")) {
    recommendations.push("📚 Use SafeMath or Solidity 0.8+ for arithmetic operations");
  }
  
  // Add source-specific insights
  if (sources.has("DeFiHackLabs")) {
    recommendations.push("📚 DeFiHackLabs exploits matched - review real-world attack patterns");
  }
  if (sources.has("learn-evm-attacks")) {
    recommendations.push("📚 learn-evm-attacks exploits matched - review educational attack reproductions");
  }

  // Check SWC entries (includes attack vectors)
  const swcResults = knowledgeResults.swc as any[] || [];
  if (swcResults.length > 0) {
    const criticalSWC = swcResults.filter(s => s.metadata?.severity === "critical");
    const highSWC = swcResults.filter(s => s.metadata?.severity === "high");
    
    if (criticalSWC.length > 0) {
      recommendations.push(`📋 ${criticalSWC.length} critical SWC/Attack Vector entries matched - review carefully`);
    }
    if (highSWC.length > 0) {
      recommendations.push(`📋 ${highSWC.length} high severity SWC/Attack Vector entries matched`);
    }
    
    // Add specific recommendations from SWC entries
    const swcCategories = new Set(swcResults.map((s: any) => s.metadata?.swc_id || s.id));
    if (swcCategories.has("SWC-107") || Array.from(swcCategories).some((id: any) => String(id).includes("107"))) {
      recommendations.push("📋 SWC-107 (Reentrancy) matched - implement reentrancy guards");
    }
    if (swcCategories.has("SWC-105") || Array.from(swcCategories).some((id: any) => String(id).includes("105"))) {
      recommendations.push("📋 SWC-105 (Unprotected Ether Withdrawal) matched - add access control");
    }
  }

  if (recommendations.length === 0) {
    recommendations.push("✅ No immediate security issues detected, but always perform thorough review");
  }

  return [...new Set(recommendations)]; // Remove duplicates
}

/**
 * Extract function content for analysis
 */
function extractFunctionContent(src: string, functionName: string): string | null {
  const regex = new RegExp(`function\\s+${functionName}\\s*\\([^)]*\\)[^{]*\\{([^}]+(?:\\{[^}]*\\}[^}]*)*)\\}`, 's');
  const match = src.match(regex);
  return match ? match[1] : null;
}

/**
 * Assess overall risk level
 */
function assessRisk(
  contractAnalysis: any,
  knowledgeResults: Record<string, unknown>,
  similarExploits: unknown[]
): { level: string; score: number; factors: string[] } {
  let score = 0;
  const factors: string[] = [];

  // Base score from indicators with severity weighting
  const indicators = contractAnalysis.security.indicators;
  score += contractAnalysis.security.severityBreakdown.critical * 30;
  score += contractAnalysis.security.severityBreakdown.high * 20;
  score += contractAnalysis.security.severityBreakdown.medium * 10;
  score += contractAnalysis.security.severityBreakdown.low * 5;

  // Critical issues
  if (!contractAnalysis.security.hasReentrancyGuard) {
    score += 30;
    factors.push("Missing reentrancy protection");
  }
  if (!contractAnalysis.security.hasAccessControl) {
    score += 20;
    factors.push("Missing access control");
  }
  if (contractAnalysis.metadata.hasOutdatedCompiler) {
    score += 25;
    factors.push("Outdated Solidity compiler version");
  }
  if (contractAnalysis.metadata.hasFloatingPragma) {
    score += 15;
    factors.push("Floating pragma - non-deterministic compilation");
  }
  if (contractAnalysis.security.privilegedFunctionsWithoutAccessControl.length > 0) {
    score += contractAnalysis.security.privilegedFunctionsWithoutAccessControl.length * 15;
    factors.push(`${contractAnalysis.security.privilegedFunctionsWithoutAccessControl.length} privileged functions without access control`);
  }

  // Similar exploits
  const exploits = similarExploits as any[];
  if (exploits.length > 0) {
    score += exploits.length * 5;
    factors.push(`${exploits.length} similar historical exploits found`);
  }

  // SWC matches
  const swcResults = knowledgeResults.swc as any[] || [];
  const criticalSWC = swcResults.filter(s => s.metadata?.severity === "critical");
  if (criticalSWC.length > 0) {
    score += criticalSWC.length * 15;
    factors.push(`${criticalSWC.length} critical SWC entries matched`);
  }

  let level: string;
  if (score >= 70) level = "CRITICAL";
  else if (score >= 50) level = "HIGH";
  else if (score >= 30) level = "MEDIUM";
  else if (score >= 10) level = "LOW";
  else level = "INFO";

  return { level, score, factors };
}


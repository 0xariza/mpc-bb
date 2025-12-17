import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerReadSolidity } from "./read_solidity.js";
import { registerListContracts } from "./list_contracts.js";
import { registerAnalyzeContract } from "./analyze_contract.js";
import { registerComprehensiveAnalysis } from "./comprehensive_analysis.js";

/**
 * Register all analysis tools
 */
export function registerAnalysisTools(server: McpServer): void {
  registerReadSolidity(server);
  registerListContracts(server);
  registerAnalyzeContract(server);
  registerComprehensiveAnalysis(server);
}

// Re-export individual tools for selective use
export { registerReadSolidity } from "./read_solidity.js";
export { registerListContracts } from "./list_contracts.js";
export { registerAnalyzeContract } from "./analyze_contract.js";
export { registerComprehensiveAnalysis } from "./comprehensive_analysis.js";

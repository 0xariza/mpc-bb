import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { logger } from "../core/index.js";
import { registerSystemTools } from "./system/index.js";
import { registerAnalysisTools } from "./analysis/index.js";
// Future imports:
// import { registerKnowledgeTools } from "./knowledge/index.js";
// import { registerTestingTools } from "./testing/index.js";
// import { registerBountyTools } from "./bounty/index.js";

/**
 * Register all MCP tools
 * 
 * Add new tool modules here as they are created.
 */
export function registerAllTools(server: McpServer): void {
  logger.info("Registering MCP tools...");
  
  // Step 1: System & Analysis
  registerSystemTools(server);
  registerAnalysisTools(server);
  
  // Step 2: Knowledge (Coming next)
  // registerKnowledgeTools(server);
  
  // Step 3: Testing
  // registerTestingTools(server);
  
  // Step 6: Bug Bounty
  // registerBountyTools(server);
  
  logger.info("All tools registered");
}

// Re-export for selective use
export { registerSystemTools } from "./system/index.js";
export { registerAnalysisTools } from "./analysis/index.js";

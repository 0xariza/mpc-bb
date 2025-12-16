import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerHealthCheck } from "./health_check.js";
import { registerListTools } from "./list_tools.js";

/**
 * Register all system tools
 */
export function registerSystemTools(server: McpServer): void {
  registerHealthCheck(server);
  registerListTools(server);
}

// Re-export individual tools for selective use
export { registerHealthCheck } from "./health_check.js";
export { registerListTools } from "./list_tools.js";

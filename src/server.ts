import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { config, logger } from "./core/index.js";
import { registerAllTools } from "./tools/index.js";

/**
 * Create and configure the MCP server
 */
export function createServer(): McpServer {
  logger.info("Creating MCP server", { 
    name: config.server.name, 
    version: config.server.version 
  });
  
  const server = new McpServer({ 
    name: config.server.name, 
    version: config.server.version 
  });
  
  registerAllTools(server);
  
  logger.info("MCP server created");
  return server;
}

export default createServer;

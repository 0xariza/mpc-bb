/**
 * MCP Server Entry Point
 * ======================
 * 
 * Minimal entry point:
 * 1. Initialize environment
 * 2. Create server
 * 3. Connect to STDIO transport
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { config, logger, validateConfig } from "./core/index.js";
import { ensureDirectory } from "./utils/index.js";
import { createServer } from "./server.js";

/**
 * Initialize the environment
 */
function initialize(): void {
  validateConfig();
  ensureDirectory(config.paths.data);
  ensureDirectory(config.paths.logs);
  
  logger.info("Environment initialized", { 
    node: process.version, 
    dev: config.isDev 
  });
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  try {
    initialize();
    
    const server = createServer();
    const transport = new StdioServerTransport();
    
    await server.connect(transport);
    
    logger.info("MCP server is running");
    
  } catch (error) {
    logger.error("Startup failed", { 
      error: error instanceof Error ? error.message : error 
    });
    process.exit(1);
  }
}

// Graceful shutdown
process.on("SIGINT", () => { 
  logger.info("Shutting down (SIGINT)"); 
  process.exit(0); 
});

process.on("SIGTERM", () => { 
  logger.info("Shutting down (SIGTERM)"); 
  process.exit(0); 
});

// Start
main();

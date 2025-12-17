/**
 * MCP Server Entry Point
 * ======================
 * 
 * Minimal entry point:
 * 1. Initialize environment
 * 2. Initialize databases
 * 3. Create server
 * 4. Connect to STDIO transport
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { config, logger, validateConfig } from "./core/index.js";
import { ensureDirectory } from "./utils/index.js";
import { createServer } from "./server.js";
import { initializeDatabases } from "./database/index.js";

/**
 * Initialize the environment
 */
async function initialize(): Promise<void> {
  validateConfig();
  
  // Ensure directories exist
  ensureDirectory(config.paths.data);
  ensureDirectory(config.paths.logs);
  ensureDirectory(config.paths.chroma);
  ensureDirectory(config.paths.sqlite);
  
  // Initialize databases
  if (config.features.enableVectorDb || config.features.enableSqlite) {
    logger.info("Initializing databases...");
    await initializeDatabases();
    logger.info("Databases initialized");
  }
  
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
    await initialize();
    
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

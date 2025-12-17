/**
 * Database Module
 * ===============
 * 
 * Exports all database functionality.
 */

import { config, logger } from "../core/index.js";

// Database connections
export { vectorDb, COLLECTIONS, type CollectionName } from "./vector-db.js";
export { sqliteDb } from "./sqlite-db.js";

// Repositories
export * from "./repositories/finding.repo.js";
export * from "./repositories/rule.repo.js";
export * from "./repositories/tool-run.repo.js";

/**
 * Initialize all databases
 */
export async function initializeDatabases(): Promise<void> {
  const { vectorDb } = await import("./vector-db.js");
  const { sqliteDb } = await import("./sqlite-db.js");

  // Initialize SQLite (synchronous)
  if (config.features.enableSqlite) {
    logger.info("Initializing SQLite...");
    sqliteDb.initialize();
  }

  // Initialize ChromaDB (async) if enabled
  if (config.features.enableVectorDb) {
    logger.info("Initializing ChromaDB...");
    await vectorDb.initialize();
  }
}

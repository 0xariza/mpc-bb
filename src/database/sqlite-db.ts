/**
 * SQLite Database Wrapper
 * =======================
 * 
 * Handles structured data:
 * - Findings (with validation status)
 * - Detection rules
 * - Tool runs (performance tracking)
 * - Bug bounty submissions
 */

import Database from "better-sqlite3";
import * as path from "path";
import { config, logger } from "../core/index.js";
import { ensureDirectory } from "../utils/file.utils.js";

/**
 * SQLite database singleton
 */
class SqliteDB {
  private db: Database.Database | null = null;
  private initialized = false;

  /**
   * Initialize the database and create tables
   */
  initialize(): void {
    if (this.initialized) return;
    
    try {
      logger.info("Initializing SQLite...");
      
      // Ensure data directory exists
      ensureDirectory(config.paths.sqlite);
      
      const dbPath = path.join(config.paths.sqlite, "security.db");
      this.db = new Database(dbPath);
      
      // Enable WAL mode for better performance
      this.db.pragma("journal_mode = WAL");
      
      // Create tables
      this.createTables();
      
      this.initialized = true;
      logger.info("SQLite initialized", { path: dbPath });
      
    } catch (error) {
      logger.error("Failed to initialize SQLite", { error });
      throw error;
    }
  }

  /**
   * Create all required tables
   */
  private createTables(): void {
    if (!this.db) throw new Error("Database not initialized");

    // Findings table - stores vulnerability findings
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        contract TEXT,
        function TEXT,
        vulnerability_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        code_snippet TEXT,
        line_number INTEGER,
        tool TEXT,
        pattern TEXT,
        confidence REAL,
        was_valid INTEGER,
        reviewed_at TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Detection rules table - custom pattern rules
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS detection_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        pattern TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        confidence REAL DEFAULT 0.5,
        hits INTEGER DEFAULT 0,
        false_positives INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tool runs table - track tool execution
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tool_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool TEXT NOT NULL,
        target TEXT,
        arguments TEXT,
        success INTEGER,
        findings_count INTEGER,
        duration_ms INTEGER,
        error TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Submissions table - bug bounty submissions
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS submissions (
        id TEXT PRIMARY KEY,
        platform TEXT NOT NULL,
        program TEXT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        bounty_amount REAL,
        finding_id TEXT,
        notes TEXT,
        submitted_at TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (finding_id) REFERENCES findings(id)
      )
    `);

    // Create indexes for better query performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vulnerability_type);
      CREATE INDEX IF NOT EXISTS idx_findings_valid ON findings(was_valid);
      CREATE INDEX IF NOT EXISTS idx_tool_runs_tool ON tool_runs(tool);
      CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
    `);

    logger.debug("Database tables created");
  }

  /**
   * Get the database instance
   */
  getDb(): Database.Database {
    if (!this.db) {
      this.initialize();
    }
    return this.db!;
  }

  /**
   * Execute a raw SQL query
   */
  run(sql: string, params: unknown[] = []): Database.RunResult {
    return this.getDb().prepare(sql).run(...params);
  }

  /**
   * Get a single row
   */
  get<T>(sql: string, params: unknown[] = []): T | undefined {
    return this.getDb().prepare(sql).get(...params) as T | undefined;
  }

  /**
   * Get all matching rows
   */
  all<T>(sql: string, params: unknown[] = []): T[] {
    return this.getDb().prepare(sql).all(...params) as T[];
  }

  /**
   * Check if database is ready
   */
  isReady(): boolean {
    return this.initialized;
  }

  /**
   * Close the database connection
   */
  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
      this.initialized = false;
      logger.info("SQLite connection closed");
    }
  }
}

// Export singleton instance
export const sqliteDb = new SqliteDB();
export default sqliteDb;

/**
 * Tool Runs Repository
 * ====================
 * 
 * Track tool execution for performance and usage analytics.
 */

import { sqliteDb } from "../sqlite-db.js";

export interface ToolRunRecord {
  id: number;
  tool: string;
  target?: string;
  arguments?: string;
  success: boolean;
  findings_count?: number;
  duration_ms: number;
  error?: string;
  created_at: string;
}

export interface RecordToolRunInput {
  tool: string;
  target?: string;
  arguments?: string[];
  success: boolean;
  findingsCount?: number;
  durationMs: number;
  error?: string;
}

/**
 * Record a tool execution
 */
export function recordToolRun(input: RecordToolRunInput): number {
  const result = sqliteDb.run(`
    INSERT INTO tool_runs (tool, target, arguments, success, findings_count, duration_ms, error)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [
    input.tool,
    input.target || null,
    input.arguments ? JSON.stringify(input.arguments) : null,
    input.success ? 1 : 0,
    input.findingsCount || null,
    input.durationMs,
    input.error || null,
  ]);
  
  return Number(result.lastInsertRowid);
}

/**
 * Get recent tool runs
 */
export function getRecentToolRuns(limit: number = 20): ToolRunRecord[] {
  const rows = sqliteDb.all<any>(
    "SELECT * FROM tool_runs ORDER BY created_at DESC LIMIT ?",
    [limit]
  );
  return rows.map(row => ({
    ...row,
    success: Boolean(row.success),
    arguments: row.arguments ? JSON.parse(row.arguments) : undefined,
  }));
}

/**
 * Get tool run statistics
 */
export function getToolRunStats(): {
  totalRuns: number;
  byTool: Record<string, { runs: number; avgDuration: number; successRate: number }>;
  last24Hours: number;
} {
  const totalRuns = sqliteDb.get<{ count: number }>(
    "SELECT COUNT(*) as count FROM tool_runs"
  )?.count || 0;
  
  const byTool: Record<string, { runs: number; avgDuration: number; successRate: number }> = {};
  
  const toolStats = sqliteDb.all<{
    tool: string;
    runs: number;
    avg_duration: number;
    success_rate: number;
  }>(`
    SELECT 
      tool,
      COUNT(*) as runs,
      AVG(duration_ms) as avg_duration,
      AVG(CASE WHEN success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
    FROM tool_runs
    GROUP BY tool
  `);
  
  for (const row of toolStats) {
    byTool[row.tool] = {
      runs: row.runs,
      avgDuration: Math.round(row.avg_duration),
      successRate: Math.round(row.success_rate * 100),
    };
  }
  
  const last24Hours = sqliteDb.get<{ count: number }>(`
    SELECT COUNT(*) as count FROM tool_runs 
    WHERE created_at > datetime('now', '-24 hours')
  `)?.count || 0;
  
  return { totalRuns, byTool, last24Hours };
}

/**
 * Get average duration for a tool
 */
export function getToolAvgDuration(tool: string): number {
  const result = sqliteDb.get<{ avg: number }>(
    "SELECT AVG(duration_ms) as avg FROM tool_runs WHERE tool = ? AND success = 1",
    [tool]
  );
  return result?.avg || 0;
}

/**
 * Clean up old tool runs (keep last N days)
 */
export function cleanupOldRuns(daysToKeep: number = 30): number {
  const result = sqliteDb.run(`
    DELETE FROM tool_runs 
    WHERE created_at < datetime('now', '-' || ? || ' days')
  `, [daysToKeep]);
  
  return result.changes;
}

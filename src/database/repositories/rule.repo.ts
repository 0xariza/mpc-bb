/**
 * Detection Rules Repository
 * ==========================
 * 
 * Data access for custom detection rules.
 */

import { v4 as uuidv4 } from "uuid";
import { sqliteDb } from "../sqlite-db.js";
import { Severity } from "../../core/index.js";

export interface RuleRecord {
  id: string;
  name: string;
  category: string;
  pattern: string;
  description?: string;
  severity: Severity;
  confidence: number;
  hits: number;
  false_positives: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateRuleInput {
  name: string;
  category: string;
  pattern: string;
  description?: string;
  severity: Severity;
  confidence?: number;
}

/**
 * Create a new detection rule
 */
export function createRule(input: CreateRuleInput): string {
  const id = uuidv4();
  
  sqliteDb.run(`
    INSERT INTO detection_rules (id, name, category, pattern, description, severity, confidence)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [
    id,
    input.name,
    input.category,
    input.pattern,
    input.description || null,
    input.severity,
    input.confidence || 0.5,
  ]);
  
  return id;
}

/**
 * Get a rule by ID
 */
export function getRule(id: string): RuleRecord | undefined {
  const row = sqliteDb.get<any>("SELECT * FROM detection_rules WHERE id = ?", [id]);
  if (!row) return undefined;
  return { ...row, enabled: Boolean(row.enabled) };
}

/**
 * Get all enabled rules
 */
export function getEnabledRules(): RuleRecord[] {
  const rows = sqliteDb.all<any>(
    "SELECT * FROM detection_rules WHERE enabled = 1 ORDER BY confidence DESC"
  );
  return rows.map(row => ({ ...row, enabled: Boolean(row.enabled) }));
}

/**
 * Get rules by category
 */
export function getRulesByCategory(category: string): RuleRecord[] {
  const rows = sqliteDb.all<any>(
    "SELECT * FROM detection_rules WHERE category = ? AND enabled = 1",
    [category]
  );
  return rows.map(row => ({ ...row, enabled: Boolean(row.enabled) }));
}

/**
 * Update rule statistics after a hit
 */
export function recordRuleHit(id: string, wasFalsePositive: boolean): void {
  if (wasFalsePositive) {
    sqliteDb.run(`
      UPDATE detection_rules 
      SET hits = hits + 1, false_positives = false_positives + 1, 
          confidence = MAX(0, confidence - 0.05),
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [id]);
  } else {
    sqliteDb.run(`
      UPDATE detection_rules 
      SET hits = hits + 1, 
          confidence = MIN(1, confidence + 0.02),
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [id]);
  }
}

/**
 * Enable/disable a rule
 */
export function setRuleEnabled(id: string, enabled: boolean): void {
  sqliteDb.run(`
    UPDATE detection_rules SET enabled = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `, [enabled ? 1 : 0, id]);
}

/**
 * Get rule statistics
 */
export function getRuleStats(): {
  total: number;
  enabled: number;
  byCategory: Record<string, number>;
  avgConfidence: number;
} {
  const total = sqliteDb.get<{ count: number }>(
    "SELECT COUNT(*) as count FROM detection_rules"
  )?.count || 0;
  
  const enabled = sqliteDb.get<{ count: number }>(
    "SELECT COUNT(*) as count FROM detection_rules WHERE enabled = 1"
  )?.count || 0;
  
  const byCategory: Record<string, number> = {};
  const categoryCounts = sqliteDb.all<{ category: string; count: number }>(
    "SELECT category, COUNT(*) as count FROM detection_rules GROUP BY category"
  );
  for (const row of categoryCounts) {
    byCategory[row.category] = row.count;
  }
  
  const avgConfidence = sqliteDb.get<{ avg: number }>(
    "SELECT AVG(confidence) as avg FROM detection_rules WHERE enabled = 1"
  )?.avg || 0;
  
  return { total, enabled, byCategory, avgConfidence };
}

/**
 * Delete a rule
 */
export function deleteRule(id: string): void {
  sqliteDb.run("DELETE FROM detection_rules WHERE id = ?", [id]);
}

/**
 * Findings Repository
 * ===================
 * 
 * Data access for security findings.
 */

import { v4 as uuidv4 } from "uuid";
import { sqliteDb } from "../sqlite-db.js";
import { Severity, Finding } from "../../core/index.js";

export interface FindingRecord {
  id: string;
  contract?: string;
  function?: string;
  vulnerability_type: string;
  severity: Severity;
  title: string;
  description?: string;
  code_snippet?: string;
  line_number?: number;
  tool?: string;
  pattern?: string;
  confidence?: number;
  was_valid?: boolean;
  reviewed_at?: string;
  notes?: string;
  created_at: string;
}

export interface CreateFindingInput {
  contract?: string;
  function?: string;
  vulnerabilityType: string;
  severity: Severity;
  title: string;
  description?: string;
  codeSnippet?: string;
  lineNumber?: number;
  tool?: string;
  pattern?: string;
  confidence?: number;
}

/**
 * Create a new finding
 */
export function createFinding(input: CreateFindingInput): string {
  const id = uuidv4();
  
  sqliteDb.run(`
    INSERT INTO findings (
      id, contract, function, vulnerability_type, severity, title,
      description, code_snippet, line_number, tool, pattern, confidence
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    id,
    input.contract || null,
    input.function || null,
    input.vulnerabilityType,
    input.severity,
    input.title,
    input.description || null,
    input.codeSnippet || null,
    input.lineNumber || null,
    input.tool || null,
    input.pattern || null,
    input.confidence || null,
  ]);
  
  return id;
}

/**
 * Get a finding by ID
 */
export function getFinding(id: string): FindingRecord | undefined {
  return sqliteDb.get<FindingRecord>(
    "SELECT * FROM findings WHERE id = ?",
    [id]
  );
}

/**
 * Get all findings with optional filters
 */
export function getFindings(filters?: {
  severity?: Severity;
  vulnerabilityType?: string;
  wasValid?: boolean;
  limit?: number;
}): FindingRecord[] {
  let sql = "SELECT * FROM findings WHERE 1=1";
  const params: unknown[] = [];
  
  if (filters?.severity) {
    sql += " AND severity = ?";
    params.push(filters.severity);
  }
  
  if (filters?.vulnerabilityType) {
    sql += " AND vulnerability_type = ?";
    params.push(filters.vulnerabilityType);
  }
  
  if (filters?.wasValid !== undefined) {
    sql += " AND was_valid = ?";
    params.push(filters.wasValid ? 1 : 0);
  }
  
  sql += " ORDER BY created_at DESC";
  
  if (filters?.limit) {
    sql += " LIMIT ?";
    params.push(filters.limit);
  }
  
  return sqliteDb.all<FindingRecord>(sql, params);
}

/**
 * Update finding validation status
 */
export function updateFindingValidation(
  id: string,
  wasValid: boolean,
  notes?: string
): void {
  sqliteDb.run(`
    UPDATE findings 
    SET was_valid = ?, reviewed_at = CURRENT_TIMESTAMP, notes = ?
    WHERE id = ?
  `, [wasValid ? 1 : 0, notes || null, id]);
}

/**
 * Get findings statistics
 */
export function getFindingsStats(): {
  total: number;
  bySeverity: Record<string, number>;
  validated: number;
  falsePositives: number;
  pending: number;
} {
  const total = sqliteDb.get<{ count: number }>(
    "SELECT COUNT(*) as count FROM findings"
  )?.count || 0;
  
  const bySeverity: Record<string, number> = {};
  const severityCounts = sqliteDb.all<{ severity: string; count: number }>(
    "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
  );
  for (const row of severityCounts) {
    bySeverity[row.severity] = row.count;
  }
  
  const validated = sqliteDb.get<{ count: number }>(
    "SELECT COUNT(*) as count FROM findings WHERE was_valid = 1"
  )?.count || 0;
  
  const falsePositives = sqliteDb.get<{ count: number }>(
    "SELECT COUNT(*) as count FROM findings WHERE was_valid = 0"
  )?.count || 0;
  
  const pending = sqliteDb.get<{ count: number }>(
    "SELECT COUNT(*) as count FROM findings WHERE was_valid IS NULL"
  )?.count || 0;
  
  return { total, bySeverity, validated, falsePositives, pending };
}

/**
 * Delete a finding
 */
export function deleteFinding(id: string): void {
  sqliteDb.run("DELETE FROM findings WHERE id = ?", [id]);
}

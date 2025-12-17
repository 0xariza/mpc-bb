/**
 * Solidity Attack Vectors Service
 * ===============================
 * 
 * Parses and analyzes detailed attack vector data from Solidity-Attack-Vectors repository.
 * Extracts descriptions, remediations, code examples, and references.
 */

import * as fs from "fs";
import * as path from "path";
import { logger } from "../core/index.js";
import type { SwcEntry } from "./knowledge.service.js";

export interface AttackVectorDetail {
  id: number;
  name: string;
  category: string;
  description: string;
  remediation: string;
  references: string[];
  codeExamples: string[];
  sourcePath: string;
}

/**
 * Parse a single attack vector markdown file
 */
export function parseAttackVectorFile(filePath: string, id: number, name: string, category: string): AttackVectorDetail | null {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    
    // Extract title (should match name, but verify)
    const titleMatch = content.match(/^##\s+(.+?)$/m);
    const title = titleMatch ? titleMatch[1].trim() : name;
    
    // Extract description section
    const descMatch = content.match(/###\s+Description:\s*\n([\s\S]*?)(?=\n###|$)/);
    const description = descMatch 
      ? descMatch[1].trim().replace(/\n+/g, " ").replace(/\s+/g, " ")
      : "";
    
    // Extract remediation section (may not always be present)
    const remMatch = content.match(/###\s+Remediation:?\s*\n([\s\S]*?)(?=\n###|$)/);
    let remediation = remMatch
      ? remMatch[1].trim().replace(/\n+/g, " ").replace(/\s+/g, " ")
      : "";
    
    // If no remediation section, try to extract from description or provide default
    if (!remediation || remediation.length < 10) {
      remediation = "Review and implement security best practices for this attack vector.";
    }
    
    // Extract references section
    const refMatch = content.match(/###\s+References?:\s*\n([\s\S]*?)(?=\n###|$)/);
    const references: string[] = [];
    if (refMatch) {
      const refText = refMatch[1];
      // Extract URLs and markdown links
      const urlMatches = refText.match(/https?:\/\/[^\s\)]+/g);
      if (urlMatches) {
        references.push(...urlMatches);
      }
      // Extract markdown links [text](url)
      const linkMatches = refText.match(/\[([^\]]+)\]\(([^\)]+)\)/g);
      if (linkMatches) {
        for (const link of linkMatches) {
          const urlMatch = link.match(/\(([^\)]+)\)/);
          if (urlMatch && urlMatch[1]) {
            references.push(urlMatch[1]);
          }
        }
      }
    }
    
    // Extract code examples (code blocks)
    const codeExamples: string[] = [];
    const codeBlockMatches = content.match(/```[\s\S]*?```/g);
    if (codeBlockMatches) {
      for (const block of codeBlockMatches) {
        // Remove markdown code block markers
        const code = block.replace(/```[\w]*\n?/g, "").trim();
        if (code.length > 0 && code.length < 2000) { // Limit size
          codeExamples.push(code);
        }
      }
    }
    
    return {
      id,
      name: title,
      category,
      description: description || `Attack vector: ${name}`,
      remediation: remediation || "No remediation provided",
      references: [...new Set(references)], // Remove duplicates
      codeExamples,
      sourcePath: filePath,
    };
  } catch (error) {
    logger.error("Failed to parse attack vector file", { filePath, error });
    return null;
  }
}

/**
 * Parse all attack vectors from the index and their detailed files
 */
export function parseAllAttackVectors(basePath: string): AttackVectorDetail[] {
  const vectors: AttackVectorDetail[] = [];
  const readmePath = path.join(basePath, "README.md");
  const dataDir = path.join(basePath, "data");
  
  if (!fs.existsSync(readmePath)) {
    logger.warn("Solidity-Attack-Vectors README not found", { path: readmePath });
    return vectors;
  }
  
  if (!fs.existsSync(dataDir)) {
    logger.warn("Solidity-Attack-Vectors data directory not found", { path: dataDir });
    return vectors;
  }
  
  logger.info("Parsing Solidity-Attack-Vectors", { basePath });
  
  // Parse index from README
  const readmeContent = fs.readFileSync(readmePath, "utf-8");
  const lines = readmeContent.split(/\r?\n/);
  
  let inTable = false;
  const indexEntries: Array<{ id: number; name: string; filePath: string }> = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    if (!inTable) {
      if (trimmed.startsWith("Serial No. |")) {
        inTable = true;
      }
      continue;
    }
    
    if (!trimmed || trimmed.startsWith("---")) continue;
    if (!trimmed.includes("|")) break;
    
    const parts = trimmed.split("|").map(p => p.trim());
    if (parts.length < 2) continue;
    
    const idMatch = parts[0].match(/\*\*(\d+)\*\*/);
    const linkMatch = parts[1].match(/\[(.+?)\]\((.+?)\)/);
    
    if (!idMatch || !linkMatch) continue;
    
    const id = parseInt(idMatch[1], 10);
    const name = linkMatch[1].trim();
    const relPath = linkMatch[2].trim();
    
    indexEntries.push({ id, name, filePath: relPath });
  }
  
  logger.info("Found attack vectors in index", { count: indexEntries.length });
  
  // Parse each detailed file
  for (const entry of indexEntries) {
    const filePath = path.join(basePath, entry.filePath);
    
    if (!fs.existsSync(filePath)) {
      logger.warn("Attack vector file not found", { id: entry.id, path: filePath });
      continue;
    }
    
    // Categorize
    const category = categorizeVector(entry.name);
    
    const vector = parseAttackVectorFile(filePath, entry.id, entry.name, category);
    if (vector) {
      vectors.push(vector);
    }
  }
  
  logger.info("Parsed attack vectors", { count: vectors.length });
  return vectors;
}

/**
 * Categorize attack vector by name
 */
function categorizeVector(name: string): string {
  const lower = name.toLowerCase();
  
  if (lower.includes("re-entrancy") || lower.includes("reentrancy")) return "reentrancy";
  if (lower.includes("access control") || lower.includes("ownership") || lower.includes("authorization")) return "access-control";
  if (lower.includes("arithmetic") || lower.includes("over/under") || lower.includes("overflow") || lower.includes("underflow")) return "integer-overflow";
  if (lower.includes("randomness") || lower.includes("entropy")) return "weak-randomness";
  if (lower.includes("timestamp") || lower.includes("block")) return "time-manipulation";
  if (lower.includes("delegatecall")) return "delegatecall";
  if (lower.includes("dos") || lower.includes("denial")) return "dos";
  if (lower.includes("price") || lower.includes("manipulation")) return "oracle-manipulation";
  if (lower.includes("short address") || lower.includes("parameter")) return "input-validation";
  if (lower.includes("validation") || lower.includes("check")) return "improper-validation";
  if (lower.includes("logic") || lower.includes("logical")) return "logic-error";
  if (lower.includes("signature")) return "signature";
  if (lower.includes("storage") || lower.includes("state variable")) return "storage";
  if (lower.includes("visibility")) return "visibility";
  if (lower.includes("selfdestruct")) return "selfdestruct";
  if (lower.includes("pragma") || lower.includes("compiler")) return "compiler";
  if (lower.includes("upgrade") || lower.includes("unprotected")) return "upgrade";
  
  return "other";
}

/**
 * Convert attack vectors to SWC-like entries for knowledge base
 */
export function convertToSwcEntries(vectors: AttackVectorDetail[]): SwcEntry[] {
  return vectors.map(v => ({
    id: `AV-${v.id}`,
    title: v.name,
    description: `${v.description}\n\nRemediation: ${v.remediation}`,
    severity: determineSeverity(v.category, v.name),
    remediation: v.remediation,
  }));
}

/**
 * Determine severity based on category and name
 */
function determineSeverity(category: string, name: string): string {
  const criticalCategories = ["reentrancy", "access-control", "delegatecall", "selfdestruct"];
  const highCategories = ["integer-overflow", "oracle-manipulation", "signature", "upgrade"];
  
  if (criticalCategories.includes(category)) return "critical";
  if (highCategories.includes(category)) return "high";
  if (name.toLowerCase().includes("critical") || name.toLowerCase().includes("unprotected")) return "high";
  
  return "medium";
}

/**
 * Get statistics about parsed attack vectors
 */
export function getAttackVectorStatistics(vectors: AttackVectorDetail[]): {
  total: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
  withCodeExamples: number;
  withReferences: number;
  totalReferences: number;
} {
  const stats = {
    total: vectors.length,
    byCategory: {} as Record<string, number>,
    bySeverity: {} as Record<string, number>,
    withCodeExamples: 0,
    withReferences: 0,
    totalReferences: 0,
  };
  
  for (const vector of vectors) {
    // Category
    stats.byCategory[vector.category] = (stats.byCategory[vector.category] || 0) + 1;
    
    // Severity
    const severity = determineSeverity(vector.category, vector.name);
    stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
    
    // Code examples
    if (vector.codeExamples.length > 0) {
      stats.withCodeExamples++;
    }
    
    // References
    if (vector.references.length > 0) {
      stats.withReferences++;
      stats.totalReferences += vector.references.length;
    }
  }
  
  return stats;
}

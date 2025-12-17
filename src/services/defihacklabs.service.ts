/**
 * DeFiHackLabs Service
 * ====================
 * 
 * Parses and analyzes exploit data from DeFiHackLabs repository.
 * Extracts exploit information, vulnerability patterns, and attack vectors.
 */

import * as fs from "fs";
import * as path from "path";
import { logger } from "../core/index.js";
import { extractMetadata, checkVulnerabilityIndicators } from "../utils/solidity.utils.js";
import type { ExploitRecord } from "./knowledge.service.js";

export interface DeFiHackLabsExploit {
  id: string;
  name: string;
  protocol: string;
  date: string;
  loss?: string;
  category: string;
  description: string;
  attackVector?: string;
  pocCode?: string;
  source: string;
  filePath: string;
  vulnerabilityTypes: string[];
  transactionLinks: string[];
  resources: string[];
}

/**
 * Parse a single exploit file
 */
export function parseExploitFile(filePath: string): DeFiHackLabsExploit | null {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    const fileName = path.basename(filePath, ".sol");
    
    // Extract date from directory structure (YYYY-MM)
    const pathParts = filePath.split(path.sep);
    const dateMatch = pathParts.find(p => /^\d{4}-\d{2}$/.test(p));
    const date = dateMatch ? dateMatch : "unknown";
    
    // Extract protocol name from filename
    const protocolMatch = fileName.match(/^([^_]+)/);
    const protocol = protocolMatch ? protocolMatch[1] : fileName;
    
    // Extract description from comments
    const commentMatch = content.match(/\/\*\s*([^*]+(?:\*(?!\/)[^*]+)*)\*\//s);
    let description = "";
    let attackVector = "";
    const transactionLinks: string[] = [];
    const resources: string[] = [];
    
    if (commentMatch) {
      const commentText = commentMatch[1];
      
      // Extract description (first paragraph)
      const descMatch = commentText.match(/^([^\n]+(?:\n[^\n]+)*?)(?:\n\n|\n\*|$)/);
      if (descMatch) {
        description = descMatch[1]
          .replace(/\n/g, " ")
          .replace(/\s+/g, " ")
          .trim();
      }
      
      // Extract transaction links
      const txMatches = commentText.match(/https?:\/\/[^\s\)]+/g);
      if (txMatches) {
        transactionLinks.push(...txMatches.filter(link => 
          link.includes("etherscan") || 
          link.includes("bscscan") || 
          link.includes("tenderly") ||
          link.includes("dashboard")
        ));
      }
      
      // Extract resource links
      const resourceMatches = commentText.match(/https?:\/\/[^\s\)]+/g);
      if (resourceMatches) {
        resources.push(...resourceMatches.filter(link => 
          !link.includes("etherscan") && 
          !link.includes("bscscan") && 
          !link.includes("tenderly") &&
          !link.includes("dashboard")
        ));
      }
      
      // Try to extract attack vector from comments
      const attackMatch = commentText.match(/(?:attack|exploit|vulnerability)[:\s]+([^\n]+)/i);
      if (attackMatch) {
        attackVector = attackMatch[1].trim();
      }
    }
    
    // Analyze code for vulnerability patterns
    const indicators = checkVulnerabilityIndicators(content);
    const vulnerabilityTypes = categorizeVulnerabilities(indicators, content);
    
    // Extract category from vulnerability types or file content
    const category = determineCategory(vulnerabilityTypes, content, description);
    
    // Generate ID
    const id = `defihacklabs-${date}-${protocol.toLowerCase().replace(/[^a-z0-9]/g, "-")}`;
    
    // Try to extract loss amount from comments or description
    const lossMatch = description.match(/\$[\d,]+(?:\.\d+)?\s*(?:million|M|billion|B|thousand|K)?/i) ||
                     content.match(/loss[:\s]+\$?[\d,]+/i);
    const loss = lossMatch ? lossMatch[0] : undefined;
    
    return {
      id,
      name: `${protocol} Exploit`,
      protocol,
      date: formatDate(date),
      loss,
      category,
      description: description || `${protocol} security exploit`,
      attackVector: attackVector || generateAttackVector(content, vulnerabilityTypes),
      pocCode: content.substring(0, 5000), // Limit code size
      source: "DeFiHackLabs",
      filePath,
      vulnerabilityTypes,
      transactionLinks,
      resources,
    };
  } catch (error) {
    logger.error("Failed to parse exploit file", { filePath, error });
    return null;
  }
}

/**
 * Scan DeFiHackLabs directory and parse all exploits
 */
export function scanDeFiHackLabs(basePath: string): DeFiHackLabsExploit[] {
  const exploits: DeFiHackLabsExploit[] = [];
  const testDir = path.join(basePath, "src", "test");
  
  if (!fs.existsSync(testDir)) {
    logger.warn("DeFiHackLabs test directory not found", { path: testDir });
    return exploits;
  }
  
  logger.info("Scanning DeFiHackLabs directory", { path: testDir });
  
  // Recursively find all .sol files
  function findSolFiles(dir: string): string[] {
    const files: string[] = [];
    
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          files.push(...findSolFiles(fullPath));
        } else if (entry.isFile() && entry.name.endsWith(".sol") && entry.name.includes("_exp")) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      logger.warn("Error reading directory", { dir, error });
    }
    
    return files;
  }
  
  const solFiles = findSolFiles(testDir);
  logger.info("Found exploit files", { count: solFiles.length });
  
  // Parse each file
  for (const file of solFiles) {
    const exploit = parseExploitFile(file);
    if (exploit) {
      exploits.push(exploit);
    }
  }
  
  logger.info("Parsed exploits", { count: exploits.length });
  return exploits;
}

/**
 * Convert DeFiHackLabs exploits to ExploitRecord format
 */
export function convertToExploitRecords(exploits: DeFiHackLabsExploit[]): ExploitRecord[] {
  return exploits.map(exploit => ({
    id: exploit.id,
    name: exploit.name,
    protocol: exploit.protocol,
    date: exploit.date,
    loss: exploit.loss,
    category: exploit.category,
    description: exploit.description,
    attackVector: exploit.attackVector,
    pocCode: exploit.pocCode,
    source: exploit.source,
  }));
}

/**
 * Categorize vulnerabilities from indicators and code
 */
function categorizeVulnerabilities(indicators: string[], content: string): string[] {
  const categories = new Set<string>();
  
  // Map indicators to vulnerability types
  for (const indicator of indicators) {
    const lower = indicator.toLowerCase();
    if (lower.includes("reentrancy")) categories.add("reentrancy");
    if (lower.includes("access-control") || lower.includes("access control")) categories.add("access-control");
    if (lower.includes("tx.origin")) categories.add("phishing");
    if (lower.includes("delegatecall")) categories.add("delegatecall");
    if (lower.includes("overflow") || lower.includes("underflow")) categories.add("integer-overflow");
    if (lower.includes("oracle") || lower.includes("price")) categories.add("oracle-manipulation");
    if (lower.includes("flash") || lower.includes("flashloan")) categories.add("flash-loan");
    if (lower.includes("random")) categories.add("weak-randomness");
    if (lower.includes("dos") || lower.includes("denial")) categories.add("dos");
  }
  
  // Additional pattern detection from code
  if (content.includes("flashloan") || content.includes("flashLoan") || content.includes("flash_loan")) {
    categories.add("flash-loan");
  }
  if (content.match(/\.call\{[^}]*value:/) || content.includes(".transfer(") || content.includes(".send(")) {
    if (!content.includes("nonReentrant") && !content.includes("ReentrancyGuard")) {
      categories.add("reentrancy");
    }
  }
  if (content.includes("tx.origin")) {
    categories.add("access-control");
    categories.add("phishing");
  }
  if (content.match(/oracle|priceFeed|getPrice|latestRoundData/i)) {
    categories.add("oracle-manipulation");
  }
  
  return Array.from(categories);
}

/**
 * Determine primary category
 */
function determineCategory(vulnerabilityTypes: string[], content: string, description: string): string {
  // Priority order for categories
  const priority = [
    "reentrancy",
    "access-control",
    "oracle-manipulation",
    "flash-loan",
    "integer-overflow",
    "delegatecall",
    "weak-randomness",
    "dos",
    "phishing",
  ];
  
  // Check priority order
  for (const cat of priority) {
    if (vulnerabilityTypes.includes(cat)) {
      return cat;
    }
  }
  
  // Fallback: check description
  const descLower = description.toLowerCase();
  if (descLower.includes("reentrancy")) return "reentrancy";
  if (descLower.includes("access control") || descLower.includes("authorization")) return "access-control";
  if (descLower.includes("oracle") || descLower.includes("price")) return "oracle-manipulation";
  if (descLower.includes("flash loan")) return "flash-loan";
  
  return "logic-error"; // Default category
}

/**
 * Generate attack vector from code analysis
 */
function generateAttackVector(content: string, vulnerabilityTypes: string[]): string {
  const steps: string[] = [];
  
  if (vulnerabilityTypes.includes("flash-loan")) {
    steps.push("Flash loan");
  }
  
  if (vulnerabilityTypes.includes("reentrancy")) {
    steps.push("Exploit reentrancy vulnerability");
  }
  
  if (vulnerabilityTypes.includes("oracle-manipulation")) {
    steps.push("Manipulate price oracle");
  }
  
  if (vulnerabilityTypes.includes("access-control")) {
    steps.push("Bypass access control");
  }
  
  if (content.includes("deposit") || content.includes("withdraw")) {
    steps.push("Drain funds");
  }
  
  if (steps.length === 0) {
    return "Exploit vulnerability in contract logic";
  }
  
  return steps.join(" → ");
}

/**
 * Format date from YYYY-MM to YYYY-MM-DD (using first day of month)
 */
function formatDate(dateStr: string): string {
  if (dateStr === "unknown") return new Date().toISOString().split("T")[0];
  if (dateStr.match(/^\d{4}-\d{2}$/)) {
    return `${dateStr}-01`;
  }
  return dateStr;
}

/**
 * Get statistics about parsed exploits
 */
export function getExploitStatistics(exploits: DeFiHackLabsExploit[]): {
  total: number;
  byCategory: Record<string, number>;
  byYear: Record<string, number>;
  byProtocol: Record<string, number>;
  vulnerabilityTypes: Record<string, number>;
} {
  const stats = {
    total: exploits.length,
    byCategory: {} as Record<string, number>,
    byYear: {} as Record<string, number>,
    byProtocol: {} as Record<string, number>,
    vulnerabilityTypes: {} as Record<string, number>,
  };
  
  for (const exploit of exploits) {
    // Category
    stats.byCategory[exploit.category] = (stats.byCategory[exploit.category] || 0) + 1;
    
    // Year
    const year = exploit.date.substring(0, 4);
    stats.byYear[year] = (stats.byYear[year] || 0) + 1;
    
    // Protocol
    stats.byProtocol[exploit.protocol] = (stats.byProtocol[exploit.protocol] || 0) + 1;
    
    // Vulnerability types
    for (const vuln of exploit.vulnerabilityTypes) {
      stats.vulnerabilityTypes[vuln] = (stats.vulnerabilityTypes[vuln] || 0) + 1;
    }
  }
  
  return stats;
}

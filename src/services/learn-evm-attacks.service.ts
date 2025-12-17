/**
 * Learn EVM Attacks Service
 * ==========================
 * 
 * Parses and analyzes exploit data from learn-evm-attacks repository.
 * Extracts exploit information from README files and test code.
 */

import * as fs from "fs";
import * as path from "path";
import { logger } from "../core/index.js";
import { checkVulnerabilityIndicators } from "../utils/solidity.utils.js";
import type { ExploitRecord } from "./knowledge.service.js";

export interface LearnEVMAttackExploit {
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
  network: string[];
  tags: string[];
  vulnerableContracts: string[];
  attackerAddresses: string[];
  attackTxs: string[];
  tokensLost: string[];
  resources: Array<{ title: string; url: string }>;
  reproductionCommand?: string;
}

/**
 * Parse frontmatter from README.md
 */
function parseFrontmatter(content: string): Record<string, unknown> {
  const frontmatter: Record<string, unknown> = {};
  
  // Match YAML frontmatter (between --- markers)
  const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!frontmatterMatch) {
    return frontmatter;
  }
  
  const yamlContent = frontmatterMatch[1];
  const lines = yamlContent.split("\n");
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    
    const colonIndex = trimmed.indexOf(":");
    if (colonIndex === -1) continue;
    
    const key = trimmed.substring(0, colonIndex).trim();
    const valueStr = trimmed.substring(colonIndex + 1).trim();
    
    // Handle array values
    if (valueStr.startsWith("[")) {
      const arrayContent = valueStr.match(/\[(.*)\]/);
      if (arrayContent) {
        const arrayValue = arrayContent[1]
          .split(",")
          .map((v: string) => v.trim().replace(/^["']|["']$/g, ""))
          .filter((v: string) => v.length > 0);
        frontmatter[key] = arrayValue;
      } else {
        frontmatter[key] = valueStr.replace(/^["']|["']$/g, "");
      }
    } else {
      // Remove quotes from string values
      frontmatter[key] = valueStr.replace(/^["']|["']$/g, "");
    }
  }
  
  return frontmatter;
}

/**
 * Extract description from README content
 */
function extractDescription(content: string): string {
  // Remove frontmatter
  const withoutFrontmatter = content.replace(/^---\s*\n[\s\S]*?\n---\s*\n/, "");
  
  // Extract first paragraph or section
  const descMatch = withoutFrontmatter.match(/^##?\s+.*?\n\n([^\n]+(?:\n[^\n]+)*?)(?:\n\n|$)/);
  if (descMatch) {
    return descMatch[1]
      .replace(/\n/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }
  
  // Fallback: first few lines
  const lines = withoutFrontmatter.split("\n").filter(l => l.trim().length > 0);
  if (lines.length > 0) {
    return lines.slice(0, 3).join(" ").trim();
  }
  
  return "";
}

/**
 * Extract step-by-step attack vector
 */
function extractAttackVector(content: string): string {
  const stepMatch = content.match(/##\s+Step-by-step\s*\n([\s\S]*?)(?:\n##|$)/);
  if (stepMatch) {
    const steps = stepMatch[1]
      .split(/\n\d+\./)
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.match(/^##/));
    
    if (steps.length > 0) {
      return steps.join(" → ");
    }
  }
  
  return "";
}

/**
 * Find test files in exploit directory
 */
function findTestFiles(exploitDir: string): string[] {
  const testFiles: string[] = [];
  
  try {
    const entries = fs.readdirSync(exploitDir, { withFileTypes: true });
    
    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith(".sol")) {
        // Skip interface files and utility files
        const lowerName = entry.name.toLowerCase();
        if (
          !lowerName.includes("interface") && 
          !lowerName.includes("interfaces") &&
          !lowerName.includes("utils") &&
          !lowerName.includes("testharness") &&
          !lowerName.includes("test_harness")
        ) {
          // Prefer .attack.sol files, but include any relevant .sol file
          testFiles.push(path.join(exploitDir, entry.name));
        }
      }
    }
    
    // Sort to prioritize .attack.sol files
    testFiles.sort((a, b) => {
      const aIsAttack = a.includes(".attack.sol");
      const bIsAttack = b.includes(".attack.sol");
      if (aIsAttack && !bIsAttack) return -1;
      if (!aIsAttack && bIsAttack) return 1;
      return 0;
    });
  } catch (error) {
    logger.warn("Error reading exploit directory", { dir: exploitDir, error });
  }
  
  return testFiles;
}

/**
 * Parse a single exploit from learn-evm-attacks
 */
export function parseExploit(exploitDir: string, category: string): LearnEVMAttackExploit | null {
  try {
    const readmePath = path.join(exploitDir, "README.md");
    
    if (!fs.existsSync(readmePath)) {
      logger.debug("No README.md found", { dir: exploitDir });
      return null;
    }
    
    const readmeContent = fs.readFileSync(readmePath, "utf-8");
    const frontmatter = parseFrontmatter(readmeContent);
    
    // Extract basic info
    const title = (frontmatter.title as string) || path.basename(exploitDir);
    const description = extractDescription(readmeContent) || (frontmatter.description as string) || "";
    const date = (frontmatter.date as string) || "unknown";
    const lossUsd = frontmatter.loss_usd as number | string;
    const loss = lossUsd ? `$${typeof lossUsd === "number" ? lossUsd.toLocaleString() : lossUsd}` : undefined;
    
    // Extract arrays - handle both array and single value formats
    const network = Array.isArray(frontmatter.network) 
      ? frontmatter.network as string[]
      : frontmatter.network ? [frontmatter.network as string] : [];
    const tags = Array.isArray(frontmatter.tags)
      ? frontmatter.tags as string[]
      : frontmatter.tags ? [frontmatter.tags as string] : [];
    const vulnerableContracts = Array.isArray(frontmatter.vulnerable_contracts)
      ? frontmatter.vulnerable_contracts as string[]
      : frontmatter.vulnerable_contracts ? [frontmatter.vulnerable_contracts as string] : [];
    const attackerAddresses = Array.isArray(frontmatter.attacker_addresses)
      ? frontmatter.attacker_addresses as string[]
      : frontmatter.attacker_addresses ? [frontmatter.attacker_addresses as string] : [];
    const attackTxs = Array.isArray(frontmatter.attack_txs)
      ? frontmatter.attack_txs as string[]
      : frontmatter.attack_txs ? [frontmatter.attack_txs as string] : [];
    const tokensLost = Array.isArray(frontmatter.tokens_lost)
      ? frontmatter.tokens_lost as string[]
      : frontmatter.tokens_lost ? [frontmatter.tokens_lost as string] : [];
    
    // Extract resources
    const resources: Array<{ title: string; url: string }> = [];
    if (Array.isArray(frontmatter.sources)) {
      for (const source of frontmatter.sources) {
        if (typeof source === "object" && source !== null) {
          const src = source as Record<string, unknown>;
          if (src.title && src.url) {
            resources.push({
              title: src.title as string,
              url: src.url as string,
            });
          }
        }
      }
    }
    
    // Find and analyze test files
    const testFiles = findTestFiles(exploitDir);
    let pocCode = "";
    const allVulnerabilityTypes = new Set<string>();
    
    // Analyze all test files, prioritizing .attack.sol files
    for (const testFile of testFiles) {
      try {
        const code = fs.readFileSync(testFile, "utf-8");
        
        // Use the largest/most relevant file as POC code
        if (testFile.includes(".attack.sol") || code.length > pocCode.length) {
          pocCode = code.substring(0, 5000); // Limit size for vector DB
        }
        
        // Analyze code for vulnerabilities
        const indicators = checkVulnerabilityIndicators(code);
        for (const indicator of indicators) {
          const lower = indicator.toLowerCase();
          if (lower.includes("reentrancy")) allVulnerabilityTypes.add("reentrancy");
          if (lower.includes("access-control") || lower.includes("access control")) allVulnerabilityTypes.add("access-control");
          if (lower.includes("delegatecall")) allVulnerabilityTypes.add("delegatecall");
          if (lower.includes("oracle") || lower.includes("price")) allVulnerabilityTypes.add("oracle-manipulation");
          if (lower.includes("flash") || lower.includes("flashloan")) allVulnerabilityTypes.add("flash-loan");
          if (lower.includes("overflow") || lower.includes("underflow")) allVulnerabilityTypes.add("integer-overflow");
          if (lower.includes("validation") || lower.includes("data")) allVulnerabilityTypes.add("improper-validation");
          if (lower.includes("arithmetic") || lower.includes("calculation")) allVulnerabilityTypes.add("logic-error");
        }
        
        // Also check for common patterns in code
        if (code.includes("flashloan") || code.includes("flashLoan") || code.includes("flash_loan")) {
          allVulnerabilityTypes.add("flash-loan");
        }
        if (code.match(/\.call\{[^}]*value:/) && !code.includes("nonReentrant")) {
          allVulnerabilityTypes.add("reentrancy");
        }
        if (code.includes("delegatecall")) {
          allVulnerabilityTypes.add("delegatecall");
        }
      } catch (error) {
        logger.warn("Failed to read test file", { file: testFile, error });
      }
    }
    
    // Add tags to vulnerability types
    for (const tag of tags) {
      const lower = tag.toLowerCase();
      if (lower.includes("reentrancy")) allVulnerabilityTypes.add("reentrancy");
      if (lower.includes("access") || lower.includes("control")) allVulnerabilityTypes.add("access-control");
      if (lower.includes("oracle") || lower.includes("price")) allVulnerabilityTypes.add("oracle-manipulation");
      if (lower.includes("flash") || lower.includes("loan")) allVulnerabilityTypes.add("flash-loan");
      if (lower.includes("delegatecall") || lower.includes("context")) allVulnerabilityTypes.add("delegatecall");
      if (lower.includes("validation") || lower.includes("data")) allVulnerabilityTypes.add("improper-validation");
      if (lower.includes("logic")) allVulnerabilityTypes.add("logic-error");
    }
    
    // Determine category
    let exploitCategory = category.toLowerCase().replace(/_/g, "-");
    if (exploitCategory === "bad-data-validation") exploitCategory = "improper-validation";
    if (exploitCategory === "business-logic") exploitCategory = "logic-error";
    
    // If no vulnerability types found, use category
    if (allVulnerabilityTypes.size === 0) {
      allVulnerabilityTypes.add(exploitCategory);
    }
    
    // Extract attack vector
    const attackVector = extractAttackVector(readmeContent) || generateAttackVectorFromTags(tags, category);
    
    // Generate ID
    const id = `learn-evm-attacks-${date}-${title.toLowerCase().replace(/[^a-z0-9]/g, "-")}`;
    
    return {
      id,
      name: title,
      protocol: title, // Protocol name is usually the title
      date: formatDate(date),
      loss,
      category: exploitCategory,
      description: description || `${title} security exploit`,
      attackVector,
      pocCode: pocCode || undefined,
      source: "learn-evm-attacks",
      filePath: exploitDir,
      vulnerabilityTypes: Array.from(allVulnerabilityTypes),
      network,
      tags,
      vulnerableContracts,
      attackerAddresses,
      attackTxs,
      tokensLost,
      resources,
      reproductionCommand: frontmatter.reproduction_command as string | undefined,
    };
  } catch (error) {
    logger.error("Failed to parse exploit", { dir: exploitDir, error });
    return null;
  }
}

/**
 * Scan learn-evm-attacks directory and parse all exploits
 */
export function scanLearnEVMAttacks(basePath: string): LearnEVMAttackExploit[] {
  const exploits: LearnEVMAttackExploit[] = [];
  const testDir = path.join(basePath, "test");
  
  if (!fs.existsSync(testDir)) {
    logger.warn("learn-evm-attacks test directory not found", { path: testDir });
    return exploits;
  }
  
  logger.info("Scanning learn-evm-attacks directory", { path: testDir });
  
  // Categories to scan
  const categories = [
    "Access_Control",
    "Bad_Data_Validation",
    "Business_Logic",
    "Reentrancy",
    "Bridges",
  ];
  
  for (const category of categories) {
    const categoryDir = path.join(testDir, category);
    
    if (!fs.existsSync(categoryDir)) {
      continue;
    }
    
    try {
      const entries = fs.readdirSync(categoryDir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const exploitDir = path.join(categoryDir, entry.name);
          const exploit = parseExploit(exploitDir, category);
          
          if (exploit) {
            exploits.push(exploit);
          }
        }
      }
    } catch (error) {
      logger.warn("Error reading category directory", { category, error });
    }
  }
  
  logger.info("Parsed learn-evm-attacks exploits", { count: exploits.length });
  return exploits;
}

/**
 * Convert to ExploitRecord format
 */
export function convertToExploitRecords(exploits: LearnEVMAttackExploit[]): ExploitRecord[] {
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
 * Generate attack vector from tags and category
 */
function generateAttackVectorFromTags(tags: string[], category: string): string {
  const steps: string[] = [];
  
  if (tags.some(t => t.toLowerCase().includes("flash"))) {
    steps.push("Flash loan");
  }
  
  if (category === "Reentrancy" || tags.some(t => t.toLowerCase().includes("reentrancy"))) {
    steps.push("Exploit reentrancy vulnerability");
  }
  
  if (category === "Access_Control" || tags.some(t => t.toLowerCase().includes("access"))) {
    steps.push("Bypass access control");
  }
  
  if (tags.some(t => t.toLowerCase().includes("oracle") || t.toLowerCase().includes("price"))) {
    steps.push("Manipulate price oracle");
  }
  
  if (category === "Bridges") {
    steps.push("Exploit bridge vulnerability");
  }
  
  if (steps.length === 0) {
    return "Exploit vulnerability in contract logic";
  }
  
  return steps.join(" → ");
}

/**
 * Format date
 */
function formatDate(dateStr: string): string {
  if (dateStr === "unknown") return new Date().toISOString().split("T")[0];
  // Handle YYYY-MM-DD format
  if (dateStr.match(/^\d{4}-\d{2}-\d{2}$/)) {
    return dateStr;
  }
  // Handle YYYY-MM format
  if (dateStr.match(/^\d{4}-\d{2}$/)) {
    return `${dateStr}-01`;
  }
  return dateStr;
}

/**
 * Get statistics about parsed exploits
 */
export function getExploitStatistics(exploits: LearnEVMAttackExploit[]): {
  total: number;
  byCategory: Record<string, number>;
  byYear: Record<string, number>;
  byNetwork: Record<string, number>;
  vulnerabilityTypes: Record<string, number>;
  totalLoss: number;
} {
  const stats = {
    total: exploits.length,
    byCategory: {} as Record<string, number>,
    byYear: {} as Record<string, number>,
    byNetwork: {} as Record<string, number>,
    vulnerabilityTypes: {} as Record<string, number>,
    totalLoss: 0,
  };
  
  for (const exploit of exploits) {
    // Category
    stats.byCategory[exploit.category] = (stats.byCategory[exploit.category] || 0) + 1;
    
    // Year
    const year = exploit.date.substring(0, 4);
    stats.byYear[year] = (stats.byYear[year] || 0) + 1;
    
    // Network
    for (const net of exploit.network) {
      stats.byNetwork[net] = (stats.byNetwork[net] || 0) + 1;
    }
    
    // Vulnerability types
    for (const vuln of exploit.vulnerabilityTypes) {
      stats.vulnerabilityTypes[vuln] = (stats.vulnerabilityTypes[vuln] || 0) + 1;
    }
    
    // Loss (extract number from string like "$1,500,000")
    if (exploit.loss) {
      const lossMatch = exploit.loss.match(/[\d,]+/);
      if (lossMatch) {
        const lossNum = parseInt(lossMatch[0].replace(/,/g, ""), 10);
        if (!isNaN(lossNum)) {
          stats.totalLoss += lossNum;
        }
      }
    }
  }
  
  return stats;
}

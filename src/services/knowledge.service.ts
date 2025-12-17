/**
 * Knowledge Service
 * =================
 * 
 * Business logic for knowledge base operations:
 * - Ingest data from various sources
 * - Query for similar patterns/exploits
 * - Record and validate findings
 */

import { vectorDb, COLLECTIONS } from "../database/index.js";
import { 
  createFinding, 
  updateFindingValidation, 
  getFindingsStats,
  type CreateFindingInput 
} from "../database/repositories/finding.repo.js";
import { logger } from "../core/index.js";

// ============================================================
// INGESTION
// ============================================================

/**
 * SWC Registry entry
 */
export interface SwcEntry {
  id: string;
  title: string;
  description: string;
  severity?: string;
  remediation?: string;
}

/**
 * Ingest SWC Registry entries
 */
export async function ingestSwcRegistry(entries: SwcEntry[]): Promise<number> {
  logger.info("Ingesting SWC Registry", { count: entries.length });
  
  const ids: string[] = [];
  const documents: string[] = [];
  const metadatas: Record<string, unknown>[] = [];
  
  for (const entry of entries) {
    ids.push(entry.id);
    documents.push(`${entry.title}\n${entry.description}\n${entry.remediation || ""}`);
    metadatas.push({
      swc_id: entry.id,
      title: entry.title,
      severity: entry.severity || "unknown",
      source: "swc_registry",
    });
  }
  
  await vectorDb.add(COLLECTIONS.SWC, { ids, documents, metadatas });
  
  logger.info("SWC Registry ingested", { count: entries.length });
  return entries.length;
}

/**
 * Exploit record
 */
export interface ExploitRecord {
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
}

/**
 * Ingest exploit records
 */
export async function ingestExploits(exploits: ExploitRecord[]): Promise<number> {
  logger.info("Ingesting exploits", { count: exploits.length });
  
  const ids: string[] = [];
  const documents: string[] = [];
  const metadatas: Record<string, unknown>[] = [];
  
  for (const exploit of exploits) {
    ids.push(exploit.id);
    // Enhanced document content for better semantic search
    const docParts = [
      exploit.name,
      exploit.description,
      exploit.attackVector || "",
      exploit.protocol,
      exploit.category,
    ];
    if (exploit.pocCode) {
      // Include first 2000 chars of POC code for pattern matching
      docParts.push(exploit.pocCode.substring(0, 2000));
    }
    documents.push(docParts.join("\n"));
    
    metadatas.push({
      name: exploit.name,
      protocol: exploit.protocol,
      date: exploit.date,
      loss: exploit.loss,
      category: exploit.category,
      source: exploit.source,
      // Additional metadata if available
      ...(exploit.pocCode ? { hasPocCode: true } : {}),
    });
  }
  
  await vectorDb.add(COLLECTIONS.EXPLOITS, { ids, documents, metadatas });
  
  logger.info("Exploits ingested", { count: exploits.length });
  return exploits.length;
}

/**
 * Audit finding record
 */
export interface AuditFindingRecord {
  id: string;
  title: string;
  severity: string;
  category: string;
  protocol: string;
  auditor: string;
  description: string;
  recommendation?: string;
}

/**
 * Ingest audit findings
 */
export async function ingestAuditFindings(findings: AuditFindingRecord[]): Promise<number> {
  logger.info("Ingesting audit findings", { count: findings.length });
  
  const ids: string[] = [];
  const documents: string[] = [];
  const metadatas: Record<string, unknown>[] = [];
  
  for (const finding of findings) {
    ids.push(finding.id);
    documents.push(
      `${finding.title}\n${finding.description}\n${finding.recommendation || ""}`
    );
    metadatas.push({
      title: finding.title,
      severity: finding.severity,
      category: finding.category,
      protocol: finding.protocol,
      auditor: finding.auditor,
      source: "audit",
    });
  }
  
  await vectorDb.add(COLLECTIONS.AUDIT_FINDINGS, { ids, documents, metadatas });
  
  logger.info("Audit findings ingested", { count: findings.length });
  return findings.length;
}

// ============================================================
// QUERYING
// ============================================================

/**
 * Query result
 */
export interface QueryResult {
  id: string;
  document: string;
  metadata: Record<string, unknown>;
  distance: number;
}

/**
 * Find similar exploits
 */
export async function findSimilarExploits(
  query: string,
  options: { limit?: number; category?: string } = {}
): Promise<QueryResult[]> {
  const { limit = 5, category } = options;
  
  const results = await vectorDb.query(COLLECTIONS.EXPLOITS, query, {
    nResults: limit,
    where: category ? { category } : undefined,
  });
  
  return results.ids.map((id, i) => ({
    id,
    document: results.documents[i],
    metadata: results.metadatas[i],
    distance: results.distances[i],
  }));
}

/**
 * Find similar audit findings
 */
export async function findSimilarAuditFindings(
  query: string,
  options: { limit?: number; severity?: string } = {}
): Promise<QueryResult[]> {
  const { limit = 5, severity } = options;
  
  const results = await vectorDb.query(COLLECTIONS.AUDIT_FINDINGS, query, {
    nResults: limit,
    where: severity ? { severity } : undefined,
  });
  
  return results.ids.map((id, i) => ({
    id,
    document: results.documents[i],
    metadata: results.metadatas[i],
    distance: results.distances[i],
  }));
}

/**
 * Query SWC Registry
 */
export async function querySWC(
  query: string,
  limit: number = 5
): Promise<QueryResult[]> {
  const results = await vectorDb.query(COLLECTIONS.SWC, query, { nResults: limit });
  
  return results.ids.map((id, i) => ({
    id,
    document: results.documents[i],
    metadata: results.metadatas[i],
    distance: results.distances[i],
  }));
}

/**
 * Search across all collections
 */
export async function searchAll(
  query: string,
  limit: number = 3
): Promise<{
  exploits: QueryResult[];
  auditFindings: QueryResult[];
  swc: QueryResult[];
}> {
  const [exploits, auditFindings, swc] = await Promise.all([
    findSimilarExploits(query, { limit }),
    findSimilarAuditFindings(query, { limit }),
    querySWC(query, limit),
  ]);
  
  return { exploits, auditFindings, swc };
}

// ============================================================
// FINDINGS MANAGEMENT
// ============================================================

/**
 * Record a new finding and add to vector DB
 */
export async function recordFinding(input: CreateFindingInput): Promise<string> {
  // Save to SQLite
  const id = createFinding(input);
  
  // Add to vector DB for similarity search
  const document = `${input.title}\n${input.description || ""}\n${input.codeSnippet || ""}`;
  
  await vectorDb.add(COLLECTIONS.PATTERNS, {
    ids: [id],
    documents: [document],
    metadatas: [{
      severity: input.severity,
      type: input.vulnerabilityType,
      tool: input.tool,
      pattern: input.pattern,
      source: "self",
    }],
  });
  
  logger.info("Finding recorded", { id, severity: input.severity });
  return id;
}

/**
 * Provide feedback on a finding
 */
export async function provideFeedback(
  findingId: string,
  wasValid: boolean,
  notes?: string
): Promise<void> {
  updateFindingValidation(findingId, wasValid, notes);
  
  // If false positive, add to false positives collection for learning
  if (!wasValid) {
    const finding = await vectorDb.get(COLLECTIONS.PATTERNS, [findingId]);
    if (finding.documents.length > 0) {
      await vectorDb.add(COLLECTIONS.FALSE_POSITIVES, {
        ids: [findingId],
        documents: finding.documents,
        metadatas: [{
          ...finding.metadatas[0],
          notes,
        }],
      });
    }
  }
  
  logger.info("Feedback recorded", { findingId, wasValid });
}

// ============================================================
// STATISTICS
// ============================================================

/**
 * Get knowledge base statistics
 */
export async function getKnowledgeStats(): Promise<{
  vectorDb: Record<string, number>;
  findings: ReturnType<typeof getFindingsStats>;
}> {
  const vectorStats = await vectorDb.getStats();
  const findingsStats = getFindingsStats();
  
  return {
    vectorDb: vectorStats,
    findings: findingsStats,
  };
}

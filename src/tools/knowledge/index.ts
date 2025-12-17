/**
 * Knowledge Tools Module
 * ======================
 * 
 * Tools for managing the security knowledge base.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerIngestSwc } from "./ingest_swc.js";
import { registerIngestExploits } from "./ingest_exploits.js";
import { registerQueryKnowledge } from "./query_knowledge.js";
import { registerFindSimilar } from "./find_similar.js";
import { registerRecordFinding, registerProvideFeedback } from "./record_finding.js";
import { registerKnowledgeStats } from "./knowledge_stats.js";
import { registerAnalyzeDeFiHackLabs } from "./analyze_defihacklabs.js";
import { registerAnalyzeLearnEVMAttacks } from "./analyze_learn_evm_attacks.js";
import { registerAnalyzeAttackVectors } from "./analyze_attack_vectors.js";
import { registerIngestAttackVectors } from "./ingest_attack_vectors.js";

/**
 * Register all knowledge tools
 */
export function registerKnowledgeTools(server: McpServer): void {
  // Ingestion tools
  registerIngestSwc(server);
  registerIngestExploits(server);
  
  // Query tools
  registerQueryKnowledge(server);
  registerFindSimilar(server);
  
  // Finding management
  registerRecordFinding(server);
  registerProvideFeedback(server);
  
  // Statistics
  registerKnowledgeStats(server);
  
  // DeFiHackLabs analysis
  registerAnalyzeDeFiHackLabs(server);
  
  // Learn EVM Attacks analysis
  registerAnalyzeLearnEVMAttacks(server);

  // Solidity Attack Vectors analysis
  registerAnalyzeAttackVectors(server);
  registerIngestAttackVectors(server);
}

// Re-export individual tools
export { registerIngestSwc } from "./ingest_swc.js";
export { registerIngestExploits } from "./ingest_exploits.js";
export { registerQueryKnowledge } from "./query_knowledge.js";
export { registerFindSimilar } from "./find_similar.js";
export { registerRecordFinding, registerProvideFeedback } from "./record_finding.js";
export { registerKnowledgeStats } from "./knowledge_stats.js";
export { registerAnalyzeDeFiHackLabs } from "./analyze_defihacklabs.js";
export { registerAnalyzeLearnEVMAttacks } from "./analyze_learn_evm_attacks.js";
export { registerAnalyzeAttackVectors } from "./analyze_attack_vectors.js";
export { registerIngestAttackVectors } from "./ingest_attack_vectors.js";

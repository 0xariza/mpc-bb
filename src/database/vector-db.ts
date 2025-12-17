/**
 * Vector Database (ChromaDB) Wrapper
 * ===================================
 * 
 * Handles semantic search for:
 * - Historical exploits
 * - Audit findings
 * - Vulnerability patterns
 * - SWC Registry entries
 */

import { ChromaClient, Collection, DefaultEmbeddingFunction } from "chromadb";
import { config, logger } from "../core/index.js";

// Collection names
export const COLLECTIONS = {
  EXPLOITS: "exploits",
  AUDIT_FINDINGS: "audit_findings",
  PATTERNS: "patterns",
  SWC: "swc_registry",
  FALSE_POSITIVES: "false_positives",
} as const;

export type CollectionName = typeof COLLECTIONS[keyof typeof COLLECTIONS];

  /**
   * Vector database singleton
   */
  class VectorDB {
    private client: ChromaClient | null = null;
    private collections: Map<string, Collection> = new Map();
    private initialized = false;
    private embedder: DefaultEmbeddingFunction;

    constructor() {
      // Initialize the default embedding function
      this.embedder = new DefaultEmbeddingFunction();
    }

    /**
     * Initialize the ChromaDB client
     */
    async initialize(): Promise<void> {
      if (this.initialized) return;

      try {
        logger.info("Initializing ChromaDB...");

        this.client = new ChromaClient({
          // ChromaClient expects an HTTP URL, not a filesystem path
          path: config.vectorDb.url,
        });
        
        // Create or get all collections with embedding function
        for (const name of Object.values(COLLECTIONS)) {
          const collection = await this.client.getOrCreateCollection({
            name,
            embeddingFunction: this.embedder,
            metadata: { 
              description: `${name} collection for security knowledge base`,
              created: new Date().toISOString(),
            },
          });
          this.collections.set(name, collection);
          logger.debug(`Collection ready: ${name}`);
        }
      
      this.initialized = true;
      logger.info("ChromaDB initialized", { 
        collections: Object.values(COLLECTIONS).length 
      });
      
    } catch (error) {
      logger.error("Failed to initialize ChromaDB", { error });
      throw error;
    }
  }

  /**
   * Get a collection by name
   */
  getCollection(name: CollectionName): Collection {
    const collection = this.collections.get(name);
    if (!collection) {
      throw new Error(`Collection not found: ${name}. Call initialize() first.`);
    }
    return collection;
  }

  /**
   * Add documents to a collection
   */
  async add(
    collectionName: CollectionName,
    documents: {
      ids: string[];
      documents: string[];
      metadatas?: Record<string, unknown>[];
    }
  ): Promise<void> {
    await this.ensureInitialized();
    
    const collection = this.getCollection(collectionName);
    
    await collection.add({
      ids: documents.ids,
      documents: documents.documents,
      metadatas: documents.metadatas as any,
    });
    
    logger.debug(`Added ${documents.ids.length} documents to ${collectionName}`);
  }

  /**
   * Query a collection for similar documents
   */
  async query(
    collectionName: CollectionName,
    queryText: string,
    options: {
      nResults?: number;
      where?: Record<string, unknown>;
    } = {}
  ): Promise<{
    ids: string[];
    documents: string[];
    metadatas: Record<string, unknown>[];
    distances: number[];
  }> {
    await this.ensureInitialized();
    
    const collection = this.getCollection(collectionName);
    const { nResults = 5, where } = options;
    
    const results = await collection.query({
      queryTexts: [queryText],
      nResults,
      where: where as any,
    });
    
    return {
      ids: results.ids[0] || [],
      documents: (results.documents[0] || []) as string[],
      metadatas: (results.metadatas?.[0] || []) as Record<string, unknown>[],
      distances: results.distances?.[0] || [],
    };
  }

  /**
   * Get documents by IDs
   */
  async get(
    collectionName: CollectionName,
    ids: string[]
  ): Promise<{
    ids: string[];
    documents: string[];
    metadatas: Record<string, unknown>[];
  }> {
    await this.ensureInitialized();
    
    const collection = this.getCollection(collectionName);
    
    const results = await collection.get({
      ids,
    });
    
    return {
      ids: results.ids,
      documents: results.documents as string[],
      metadatas: results.metadatas as Record<string, unknown>[],
    };
  }

  /**
   * Count documents in a collection
   */
  async count(collectionName: CollectionName): Promise<number> {
    await this.ensureInitialized();
    const collection = this.getCollection(collectionName);
    return await collection.count();
  }

  /**
   * Delete documents from a collection
   */
  async delete(collectionName: CollectionName, ids: string[]): Promise<void> {
    await this.ensureInitialized();
    const collection = this.getCollection(collectionName);
    await collection.delete({ ids });
    logger.debug(`Deleted ${ids.length} documents from ${collectionName}`);
  }

  /**
   * Get stats for all collections
   */
  async getStats(): Promise<Record<string, number>> {
    await this.ensureInitialized();
    
    const stats: Record<string, number> = {};
    
    for (const name of Object.values(COLLECTIONS)) {
      stats[name] = await this.count(name);
    }
    
    return stats;
  }

  /**
   * Ensure database is initialized
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  /**
   * Check if database is ready
   */
  isReady(): boolean {
    return this.initialized;
  }
}

// Export singleton instance
export const vectorDb = new VectorDB();
export default vectorDb;

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger } from "../../core/index.js";
import { 
  exists, 
  findSolidityFiles, 
  relativePath 
} from "../../utils/file.utils.js";

/**
 * Register the list_contracts tool
 */
export function registerListContracts(server: McpServer): void {
  server.registerTool(
    "list_contracts",
    {
      title: "List Solidity contracts",
      description: "Find all Solidity files in a directory",
      inputSchema: z.object({
        directory: z.string().describe("Directory path to search"),
        recursive: z.boolean().optional().default(true).describe("Search subdirectories"),
      }),
    },
    async ({ directory, recursive }) => {
      try {
        if (!exists(directory)) return errorResponse("Directory not found", { path: directory });
        
        const files = findSolidityFiles(directory, recursive);
        
        const contracts = files.map(f => ({ 
          path: f, 
          name: f.split("/").pop(), 
          relative: relativePath(directory, f) 
        }));
        
        logger.info("Listed contracts", { directory, count: contracts.length });
        
        return jsonResponse({
          directory,
          count: contracts.length,
          contracts,
        });
        
      } catch (e) {
        logger.error("Failed to list contracts", { directory, error: e });
        return errorResponse(String(e));
      }
    }
  );
}

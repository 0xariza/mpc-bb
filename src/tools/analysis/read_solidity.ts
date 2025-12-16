import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger, isMcpError } from "../../core/index.js";
import { exists, readFile, getFileInfo } from "../../utils/file.utils.js";
import { 
  extractMetadata, 
  extractFunctions, 
  checkVulnerabilityIndicators, 
  detectProtocolType 
} from "../../utils/solidity.utils.js";

/**
 * Register the read_solidity tool
 */
export function registerReadSolidity(server: McpServer): void {
  server.registerTool(
    "read_solidity",
    {
      title: "Read Solidity file",
      description: "Read a Solidity file and extract metadata, functions, and basic analysis",
      inputSchema: z.object({
        path: z.string().describe("Path to the .sol file"),
        includeContent: z.boolean().optional().default(true).describe("Include source code"),
        analyze: z.boolean().optional().default(true).describe("Include vulnerability indicators"),
      }),
    },
    async ({ path: p, includeContent, analyze }) => {
      try {
        if (!exists(p)) return errorResponse("File not found", { path: p });
        if (!p.endsWith(".sol")) return errorResponse("Not a Solidity file", { path: p });
        
        const content = readFile(p);
        const info = getFileInfo(p);
        const meta = extractMetadata(content);
        
        const result: Record<string, unknown> = { 
          file: info, 
          metadata: meta 
        };
        
        if (analyze) {
          result.functions = extractFunctions(content);
          result.vulnerabilityIndicators = checkVulnerabilityIndicators(content);
          result.detectedProtocols = detectProtocolType(content);
        }
        
        if (includeContent) {
          result.content = content;
        }
        
        logger.info("Read solidity", { path: p, contracts: meta.contracts.length });
        return jsonResponse(result);
        
      } catch (e) {
        logger.error("Failed to read solidity", { path: p, error: e });
        return errorResponse(isMcpError(e) ? e.message : String(e));
      }
    }
  );
}

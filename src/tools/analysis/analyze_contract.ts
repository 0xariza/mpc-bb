import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger } from "../../core/index.js";
import { exists, readFile, getFileInfo } from "../../utils/file.utils.js";
import { 
  extractFunctions, 
  checkVulnerabilityIndicators, 
  detectProtocolType 
} from "../../utils/solidity.utils.js";

/**
 * Register the analyze_contract tool
 */
export function registerAnalyzeContract(server: McpServer): void {
  server.registerTool(
    "analyze_contract",
    {
      title: "Analyze Solidity contract",
      description: "Perform quick security analysis on a Solidity file",
      inputSchema: z.object({
        path: z.string().describe("Path to the .sol file"),
      }),
    },
    async ({ path: p }) => {
      try {
        if (!exists(p)) return errorResponse("File not found", { path: p });
        
        const content = readFile(p);
        const fns = extractFunctions(content);
        const externalFns = fns.filter(f => f.visibility === "external");
        const publicFns = fns.filter(f => f.visibility === "public");
        
        const result = {
          file: getFileInfo(p),
          summary: {
            totalFunctions: fns.length,
            external: externalFns.length,
            public: publicFns.length,
            stateChanging: fns.filter(f => 
              f.mutability !== "view" && f.mutability !== "pure"
            ).length,
          },
          security: {
            hasReentrancyGuard: content.includes("nonReentrant") || content.includes("ReentrancyGuard"),
            hasAccessControl: content.includes("onlyOwner") || content.includes("AccessControl"),
            indicators: checkVulnerabilityIndicators(content),
          },
          protocols: detectProtocolType(content),
          functions: {
            external: externalFns.map(f => f.name),
            public: publicFns.map(f => f.name),
          },
        };
        
        logger.info("Analyzed contract", { path: p, indicators: result.security.indicators.length });
        
        return jsonResponse(result);
        
      } catch (e) {
        logger.error("Failed to analyze contract", { path: p, error: e });
        return errorResponse(String(e));
      }
    }
  );
}

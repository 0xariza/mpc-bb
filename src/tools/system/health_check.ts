import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { config, jsonResponse, logger } from "../../core/index.js";
import { checkAllTools } from "../../utils/index.js";

/**
 * Register the health_check tool
 */
export function registerHealthCheck(server: McpServer): void {
  server.registerTool(
    "health_check",
    {
      title: "Health check",
      description: "Check server status and available security tools",
      inputSchema: z.object({
        verbose: z.boolean().optional().default(false).describe("Include system details"),
      }),
    },
    async ({ verbose }) => {
      const tools = checkAllTools();
      const installed = Object.values(tools).filter(Boolean).length;
      
      const result: Record<string, unknown> = {
        status: "healthy",
        server: { 
          name: config.server.name, 
          version: config.server.version 
        },
        tools: { 
          installed, 
          total: Object.keys(tools).length, 
          available: tools 
        },
      };
      
      if (verbose) {
        result.system = { 
          node: process.version, 
          platform: process.platform,
          uptime: `${Math.floor(process.uptime())}s`,
        };
        result.paths = config.paths;
      }
      
      logger.info("Health check", { installed });
      return jsonResponse(result);
    }
  );
}

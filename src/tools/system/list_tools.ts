import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, logger, AllowedCommand } from "../../core/index.js";
import { checkAllTools, getInstallHint } from "../../utils/index.js";

/**
 * Register the list_tools tool
 */
export function registerListTools(server: McpServer): void {
  server.registerTool(
    "list_tools",
    {
      title: "List security tools",
      description: "List all security tools and their installation status",
      inputSchema: z.object({}), // Empty schema for zero-argument tool
    },
    async () => {
      const tools = checkAllTools();
      
      const toolList = Object.entries(tools).map(([name, installed]) => ({ 
        name, 
        installed, 
        hint: installed ? null : getInstallHint(name as AllowedCommand) 
      }));
      
      return jsonResponse({
        tools: toolList,
        summary: {
          installed: toolList.filter(t => t.installed).length,
          missing: toolList.filter(t => !t.installed).length,
        }
      });
    }
  );
}

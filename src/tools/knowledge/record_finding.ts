/**
 * Record Finding Tool
 * ===================
 * 
 * Record a new security finding for learning and tracking.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger, Severity } from "../../core/index.js";
import { recordFinding, provideFeedback } from "../../services/knowledge.service.js";

/**
 * Register the record_finding tool
 */
export function registerRecordFinding(server: McpServer): void {
  server.tool(
    "record_finding",
    "Record a new security finding to the knowledge base for learning",
    {
      title: z.string().describe("Title of the finding"),
      vulnerabilityType: z.string().describe("Type of vulnerability (reentrancy, access-control, etc.)"),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).describe("Severity level"),
      description: z.string().optional().describe("Detailed description"),
      contract: z.string().optional().describe("Affected contract name or path"),
      function: z.string().optional().describe("Affected function name"),
      codeSnippet: z.string().optional().describe("Relevant code snippet"),
      lineNumber: z.number().optional().describe("Line number in the contract"),
      tool: z.string().optional().describe("Tool that found this (slither, mythril, manual)"),
      pattern: z.string().optional().describe("Pattern ID if applicable"),
      confidence: z.number().optional().describe("Confidence score 0-1"),
    },
    async (input) => {
      try {
        const id = await recordFinding({
          title: input.title,
          vulnerabilityType: input.vulnerabilityType,
          severity: input.severity as Severity,
          description: input.description,
          contract: input.contract,
          function: input.function,
          codeSnippet: input.codeSnippet,
          lineNumber: input.lineNumber,
          tool: input.tool,
          pattern: input.pattern,
          confidence: input.confidence,
        });
        
        logger.info("Finding recorded", { id, severity: input.severity });
        
        return jsonResponse({
          success: true,
          id,
          message: `Finding recorded with ID: ${id}`,
          finding: {
            id,
            title: input.title,
            severity: input.severity,
            vulnerabilityType: input.vulnerabilityType,
          },
        });
        
      } catch (e) {
        logger.error("Failed to record finding", { error: e });
        return errorResponse("Failed to record finding", { error: String(e) });
      }
    }
  );
}

/**
 * Register the provide_feedback tool
 */
export function registerProvideFeedback(server: McpServer): void {
  server.tool(
    "provide_feedback",
    "Provide feedback on a finding (valid/false positive) to improve detection",
    {
      findingId: z.string().describe("ID of the finding to update"),
      wasValid: z.boolean().describe("Whether the finding was a valid vulnerability"),
      notes: z.string().optional().describe("Additional notes about the finding"),
    },
    async ({ findingId, wasValid, notes }) => {
      try {
        await provideFeedback(findingId, wasValid, notes);
        
        logger.info("Feedback recorded", { findingId, wasValid });
        
        return jsonResponse({
          success: true,
          message: `Feedback recorded for finding ${findingId}`,
          findingId,
          wasValid,
          notes,
          impact: wasValid 
            ? "Finding confirmed - will improve similar detection confidence"
            : "False positive recorded - will reduce similar detection confidence",
        });
        
      } catch (e) {
        logger.error("Failed to record feedback", { findingId, error: e });
        return errorResponse("Failed to record feedback", { error: String(e) });
      }
    }
  );
}

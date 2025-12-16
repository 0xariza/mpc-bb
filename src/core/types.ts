export interface ToolResponse {
  // Allow extra fields so this matches the MCP SDK's CallToolResult shape
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

export function jsonResponse(data: unknown): ToolResponse {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

export function errorResponse(msg: string, details?: unknown): ToolResponse {
  return { 
    content: [{ type: "text", text: JSON.stringify({ error: msg, details }, null, 2) }], 
    isError: true 
  };
}

export interface SolidityMetadata {
  pragmas: string[];
  imports: string[];
  contracts: string[];
  interfaces: string[];
  libraries: string[];
}

export interface SolidityFunction {
  name: string;
  visibility: "public" | "external" | "internal" | "private";
  mutability: "pure" | "view" | "payable" | "nonpayable";
  modifiers: string[];
  lineNumber?: number;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  recommendation?: string;
}

export type AllowedCommand = "slither" | "myth" | "forge" | "echidna-test" | "solhint" | "surya" | "aderyn" | "halmos";

export interface CommandResult {
  success: boolean;
  command: string;
  stdout: string;
  stderr: string;
  duration: number;
  exitCode: number;
}

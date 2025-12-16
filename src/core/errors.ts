export class McpError extends Error {
  constructor(
    public override message: string, 
    public code: string, 
    public details?: unknown
  ) {
    super(message);
    this.name = "McpError";
  }
  
  toJSON() { 
    return { 
      name: this.name, 
      code: this.code, 
      message: this.message, 
      details: this.details 
    }; 
  }
}

export class FileError extends McpError {
  constructor(msg: string, public path: string) { 
    super(msg, "FILE_ERROR"); 
  }
}

export class ToolNotFoundError extends McpError {
  constructor(public tool: string, public hint?: string) { 
    super(`Tool not found: ${tool}`, "TOOL_NOT_FOUND"); 
  }
}

export class ToolExecutionError extends McpError {
  constructor(msg: string, public tool: string) { 
    super(msg, "TOOL_EXEC_ERROR"); 
  }
}

export function isMcpError(e: unknown): e is McpError { 
  return e instanceof McpError; 
}

import { execSync } from "child_process";
import { 
  AllowedCommand, 
  CommandResult, 
  ToolNotFoundError, 
  ToolExecutionError,
  config 
} from "../core/index.js";

const HINTS: Record<AllowedCommand, string> = {
  slither: "pip install slither-analyzer",
  myth: "pip install mythril",
  forge: "curl -L https://foundry.paradigm.xyz | bash && foundryup",
  "echidna-test": "https://github.com/crytic/echidna",
  solhint: "npm install -g solhint",
  surya: "npm install -g surya",
  aderyn: "cargo install aderyn",
  halmos: "pip install halmos",
};

export function isToolInstalled(tool: string): boolean {
  try { 
    execSync(`which ${tool}`, { stdio: "pipe" }); 
    return true; 
  } catch { 
    return false; 
  }
}

export function getInstallHint(tool: AllowedCommand): string { 
  return HINTS[tool] || `Install ${tool}`; 
}

export function checkAllTools(): Record<string, boolean> {
  const tools: AllowedCommand[] = [
    "slither", "myth", "forge", "echidna-test", 
    "solhint", "surya", "aderyn", "halmos"
  ];
  return Object.fromEntries(tools.map(t => [t, isToolInstalled(t)]));
}

export function executeCommand(
  cmd: AllowedCommand, 
  args: string[], 
  opts: { cwd?: string; timeout?: number } = {}
): CommandResult {
  if (!isToolInstalled(cmd)) {
    throw new ToolNotFoundError(cmd, getInstallHint(cmd));
  }
  
  const { cwd = process.cwd(), timeout = config.timeouts.default } = opts;
  const full = `${cmd} ${args.join(" ")}`;
  const start = Date.now();
  
  try {
    const stdout = execSync(full, { 
      encoding: "utf-8", 
      cwd, 
      timeout, 
      maxBuffer: 50 * 1024 * 1024 
    });
    return { 
      success: true, 
      command: full, 
      stdout, 
      stderr: "", 
      duration: Date.now() - start, 
      exitCode: 0 
    };
  } catch (e: any) {
    if (e.stdout) {
      return { 
        success: true, 
        command: full, 
        stdout: e.stdout, 
        stderr: e.stderr || "", 
        duration: Date.now() - start, 
        exitCode: e.status || 1 
      };
    }
    throw new ToolExecutionError(e.message, cmd);
  }
}

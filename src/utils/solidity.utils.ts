import { SolidityMetadata, SolidityFunction } from "../core/index.js";

export function extractMetadata(src: string): SolidityMetadata {
  return {
    pragmas: (src.match(/pragma\s+solidity\s+[^;]+;/g) || []).map(s => s.trim()),
    imports: (src.match(/import\s+[^;]+;/g) || []).map(s => s.trim()),
    contracts: (src.match(/contract\s+(\w+)/g) || []).map(s => s.replace("contract ", "")),
    interfaces: (src.match(/interface\s+(\w+)/g) || []).map(s => s.replace("interface ", "")),
    libraries: (src.match(/library\s+(\w+)/g) || []).map(s => s.replace("library ", "")),
  };
}

export function extractFunctions(src: string): SolidityFunction[] {
  const fns: SolidityFunction[] = [];
  const re = /function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?\s*(view|pure|payable)?/g;
  let m;
  
  while ((m = re.exec(src))) {
    const line = (src.substring(0, m.index).match(/\n/g) || []).length + 1;
    fns.push({
      name: m[1],
      visibility: (m[2] || "internal") as SolidityFunction["visibility"],
      mutability: (m[3] || "nonpayable") as SolidityFunction["mutability"],
      modifiers: [],
      lineNumber: line,
    });
  }
  
  return fns;
}

export function checkVulnerabilityIndicators(src: string): string[] {
  const indicators: string[] = [];
  
  // Reentrancy checks
  if ((src.includes(".call{") || src.includes(".call(") || src.includes(".send(") || src.includes(".transfer(")) && !src.includes("nonReentrant") && !src.includes("ReentrancyGuard")) {
    indicators.push("CRITICAL: Potential reentrancy - external call without guard");
  }
  if (src.match(/\.call\{[^}]*value:/) && !src.includes("nonReentrant")) {
    indicators.push("CRITICAL: ETH transfer via call without reentrancy protection");
  }
  
  // Access control
  if (src.includes("tx.origin")) {
    indicators.push("CRITICAL: tx.origin usage - vulnerable to phishing attacks");
  }
  if (src.match(/function\s+\w+.*external.*\{[^}]*\b(transfer|withdraw|withdrawAll|setOwner|changeOwner|destroy|kill)\b/i) && !src.includes("onlyOwner") && !src.includes("AccessControl")) {
    indicators.push("HIGH: Privileged function without access control");
  }
  
  // Dangerous operations
  if (src.includes("selfdestruct") && !src.includes("onlyOwner")) {
    indicators.push("CRITICAL: selfdestruct without access control");
  }
  if (src.includes("delegatecall") && !src.match(/require\(.*==.*msg\.sender/i)) {
    indicators.push("CRITICAL: delegatecall without proper validation");
  }
  
  // Integer overflow/underflow
  if (src.match(/\+\+|--|\+\s*[^=]|-\s*[^=]/) && !src.includes("SafeMath") && !src.match(/pragma\s+solidity\s+[>=]0\.8/)) {
    indicators.push("HIGH: Unchecked arithmetic - potential overflow/underflow");
  }
  
  // Unchecked external calls
  if (src.match(/\.call\(|\.send\(|\.transfer\(/) && !src.match(/require\(.*success|if\s*\(.*success/)) {
    indicators.push("MEDIUM: Unchecked external call return value");
  }
  
  // Front-running vulnerabilities
  if (src.match(/block\.timestamp|block\.number|now\b/) && src.match(/require\(.*block\.(timestamp|number)/)) {
    indicators.push("MEDIUM: Time-dependent logic - potential front-running");
  }
  
  // Gas griefing
  if (src.match(/for\s*\([^)]*\)\s*\{[^}]*\.call\(/)) {
    indicators.push("MEDIUM: Loop with external calls - gas griefing risk");
  }
  
  // Missing events
  const stateChangingFns = src.match(/function\s+(\w+).*\{/g) || [];
  const events = src.match(/event\s+\w+/g) || [];
  if (stateChangingFns.length > events.length * 2) {
    indicators.push("LOW: Missing event emissions for state changes");
  }
  
  // Assembly usage
  if (src.includes("assembly")) {
    indicators.push("HIGH: Inline assembly - requires careful security review");
  }
  
  // Uninitialized storage
  if (src.match(/storage\s+\w+\s+\w+;/) && !src.match(/=\s*[^;]+;/)) {
    indicators.push("HIGH: Uninitialized storage pointer");
  }
  
  // Floating pragma
  const pragmas = src.match(/pragma\s+solidity\s+([^;]+);/g) || [];
  if (pragmas.some(p => p.includes("^") || p.includes(">=") || p.includes("~"))) {
    indicators.push("MEDIUM: Floating pragma - use fixed version for production");
  }
  
  // Outdated compiler
  if (src.match(/pragma\s+solidity\s+0\.(4|5|6|7)\./)) {
    indicators.push("HIGH: Outdated Solidity version - known vulnerabilities");
  }
  
  // Missing zero address checks
  if (src.match(/function\s+\w+.*address.*\{/) && !src.match(/require\(.*!=.*address\(0\)/)) {
    indicators.push("MEDIUM: Missing zero address validation");
  }
  
  // Unprotected payable functions
  if (src.match(/function\s+\w+.*payable.*external.*\{/) && !src.match(/onlyOwner|AccessControl/)) {
    indicators.push("HIGH: Unprotected payable function");
  }
  
  // Missing return value checks
  if (src.match(/\.transfer\(|\.send\(/) && !src.match(/require\(.*success/)) {
    indicators.push("MEDIUM: Missing return value check for transfer/send");
  }
  
  // Weak randomness
  if (src.match(/block\.(timestamp|number|hash|difficulty|gaslimit)/) && src.match(/random|Random/)) {
    indicators.push("CRITICAL: Weak randomness source - predictable values");
  }
  
  // DoS with failed call
  if (src.match(/for\s*\([^)]*\)\s*\{[^}]*\.call\(/) && !src.match(/continue|break/)) {
    indicators.push("MEDIUM: DoS risk - loop with external calls may fail");
  }
  
  // Shadowing state variables
  const stateVars = src.match(/^\s*(uint|int|bool|address|string|bytes|mapping)\s+\w+/gm) || [];
  const localVars = src.match(/function\s+\w+.*\([^)]*\)[^{]*\{[^}]*\b(uint|int|bool|address|string|bytes)\s+(\w+)/g) || [];
  // Simple check - in production would need AST
  if (stateVars.length > 0 && localVars.length > 0) {
    indicators.push("LOW: Potential variable shadowing - verify manually");
  }
  
  return indicators;
}

export function detectProtocolType(src: string): string[] {
  const protos: string[] = [];
  
  if (src.includes("transfer(") || src.includes("balanceOf(")) protos.push("ERC20");
  if (src.includes("ownerOf(") || src.includes("tokenURI(")) protos.push("ERC721");
  if (src.includes("IVault") || src.includes("getPoolTokens")) protos.push("Balancer");
  if (src.includes("getReserves") || src.includes("UniswapV2")) protos.push("Uniswap");
  if (src.includes("AggregatorV3") || src.includes("latestRoundData")) protos.push("Chainlink");
  if (src.includes("Ownable") || src.includes("AccessControl")) protos.push("OpenZeppelin");
  
  return protos;
}

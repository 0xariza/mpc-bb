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
  
  if (src.includes(".call{") && !src.includes("nonReentrant")) {
    indicators.push("Potential reentrancy: external call without guard");
  }
  if (src.includes("tx.origin")) {
    indicators.push("tx.origin usage - phishing vulnerability");
  }
  if (src.includes("selfdestruct")) {
    indicators.push("selfdestruct present");
  }
  if (src.includes("delegatecall")) {
    indicators.push("delegatecall usage - verify target");
  }
  if (src.includes("assembly")) {
    indicators.push("Inline assembly - requires careful review");
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

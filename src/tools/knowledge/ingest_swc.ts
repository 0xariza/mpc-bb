/**
 * Ingest SWC Registry Tool
 * ========================
 * 
 * Fetch and ingest the Smart Contract Weakness Classification registry.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { jsonResponse, errorResponse, logger } from "../../core/index.js";
import { ingestSwcRegistry, type SwcEntry } from "../../services/knowledge.service.js";

// SWC Registry data (curated list of common weaknesses)
const SWC_REGISTRY: SwcEntry[] = [
  {
    id: "SWC-100",
    title: "Function Default Visibility",
    description: "Functions that do not have a function visibility type specified are public by default. This can lead to a vulnerability if a developer forgot to set the visibility and a malicious user is able to make unauthorized or unintended state changes.",
    severity: "medium",
    remediation: "Functions can be specified as being external, public, internal or private. Make a conscious decision about function visibility.",
  },
  {
    id: "SWC-101",
    title: "Integer Overflow and Underflow",
    description: "An overflow/underflow happens when an arithmetic operation reaches the maximum or minimum size of a type. For instance, if a number is stored in uint8, it means that the number is stored in an 8-bits unsigned number ranging from 0 to 255.",
    severity: "high",
    remediation: "Use SafeMath library or Solidity 0.8+ which has built-in overflow checks.",
  },
  {
    id: "SWC-102",
    title: "Outdated Compiler Version",
    description: "Using an outdated compiler version can be problematic especially if there are publicly disclosed bugs and issues that affect the current compiler version.",
    severity: "low",
    remediation: "Use a recent version of the Solidity compiler.",
  },
  {
    id: "SWC-103",
    title: "Floating Pragma",
    description: "Contracts should be deployed with the same compiler version that they have been tested with. Locking the pragma helps to ensure that contracts do not accidentally get deployed using a different compiler version.",
    severity: "low",
    remediation: "Lock the pragma version to a specific compiler version.",
  },
  {
    id: "SWC-104",
    title: "Unchecked Call Return Value",
    description: "The return value of a message call is not checked. Execution will resume even if the called contract throws an exception.",
    severity: "medium",
    remediation: "Check the return value of low-level calls and handle failures appropriately.",
  },
  {
    id: "SWC-105",
    title: "Unprotected Ether Withdrawal",
    description: "Due to missing or insufficient access controls, malicious parties can withdraw some or all Ether from the contract account.",
    severity: "critical",
    remediation: "Implement proper access controls on withdrawal functions.",
  },
  {
    id: "SWC-106",
    title: "Unprotected SELFDESTRUCT Instruction",
    description: "Due to missing or insufficient access controls, malicious parties can self-destruct the contract.",
    severity: "critical",
    remediation: "Implement proper access controls on selfdestruct or avoid using it entirely.",
  },
  {
    id: "SWC-107",
    title: "Reentrancy",
    description: "One of the major dangers of calling external contracts is that they can take over the control flow. A reentrancy attack occurs when a contract calls another contract before updating its state.",
    severity: "critical",
    remediation: "Use checks-effects-interactions pattern, reentrancy guards, or pull payment pattern.",
  },
  {
    id: "SWC-108",
    title: "State Variable Default Visibility",
    description: "Labeling the visibility explicitly makes it easier to catch incorrect assumptions about who can access the variable.",
    severity: "low",
    remediation: "Variables can be specified as being public, internal or private. Make a conscious decision.",
  },
  {
    id: "SWC-109",
    title: "Uninitialized Storage Pointer",
    description: "Uninitialized local storage variables can point to unexpected storage locations in the contract.",
    severity: "high",
    remediation: "Initialize all storage pointers or use memory keyword.",
  },
  {
    id: "SWC-110",
    title: "Assert Violation",
    description: "The assert() function is meant to assert invariants. A failing assert() signals that something is fundamentally wrong.",
    severity: "medium",
    remediation: "Use assert only for invariants. Use require for input validation.",
  },
  {
    id: "SWC-111",
    title: "Use of Deprecated Functions",
    description: "Several functions and operators are deprecated in Solidity. Using them can lead to unintended effects.",
    severity: "low",
    remediation: "Replace deprecated functions with their modern equivalents.",
  },
  {
    id: "SWC-112",
    title: "Delegatecall to Untrusted Callee",
    description: "Delegatecall is a special variant of a message call that executes code in the context of the calling contract.",
    severity: "critical",
    remediation: "Only delegatecall to trusted contracts. Avoid user-supplied addresses.",
  },
  {
    id: "SWC-113",
    title: "DoS with Failed Call",
    description: "External calls can fail accidentally or deliberately, which can cause a DoS condition in the contract.",
    severity: "medium",
    remediation: "Use pull over push pattern for external calls.",
  },
  {
    id: "SWC-114",
    title: "Transaction Order Dependence",
    description: "The outcome of a transaction can be influenced by other transactions in the mempool (front-running).",
    severity: "medium",
    remediation: "Use commit-reveal schemes or other front-running mitigation techniques.",
  },
  {
    id: "SWC-115",
    title: "Authorization through tx.origin",
    description: "tx.origin is a global variable that returns the address that originally sent the transaction. Using it for authorization is vulnerable to phishing attacks.",
    severity: "high",
    remediation: "Use msg.sender for authorization instead of tx.origin.",
  },
  {
    id: "SWC-116",
    title: "Block values as a proxy for time",
    description: "Block timestamps and block numbers can be manipulated by miners to some degree.",
    severity: "low",
    remediation: "Avoid using block.timestamp for critical logic or use time windows.",
  },
  {
    id: "SWC-117",
    title: "Signature Malleability",
    description: "The ecrecover function can return different addresses for a valid signature due to signature malleability.",
    severity: "medium",
    remediation: "Use OpenZeppelin's ECDSA library which handles malleability.",
  },
  {
    id: "SWC-118",
    title: "Incorrect Constructor Name",
    description: "Before Solidity 0.4.22, constructors were defined as functions with the same name as the contract. A typo could make it a regular function.",
    severity: "critical",
    remediation: "Use the constructor keyword (Solidity 0.4.22+).",
  },
  {
    id: "SWC-119",
    title: "Shadowing State Variables",
    description: "Contracts can inherit state variables from parent contracts. A state variable shadowing another can lead to unexpected behavior.",
    severity: "medium",
    remediation: "Avoid using the same variable names in child and parent contracts.",
  },
  {
    id: "SWC-120",
    title: "Weak Sources of Randomness",
    description: "Using block variables like block.timestamp, block.difficulty, or blockhash for randomness is insecure.",
    severity: "high",
    remediation: "Use Chainlink VRF or other secure randomness sources.",
  },
  {
    id: "SWC-121",
    title: "Missing Protection against Signature Replay",
    description: "Without proper nonce management, signatures can be replayed across transactions or chains.",
    severity: "high",
    remediation: "Include nonces and chain IDs in signed messages.",
  },
  {
    id: "SWC-122",
    title: "Lack of Proper Signature Verification",
    description: "Failure to properly verify signatures can lead to unauthorized actions.",
    severity: "critical",
    remediation: "Use OpenZeppelin's ECDSA library and verify all signature components.",
  },
  {
    id: "SWC-123",
    title: "Requirement Violation",
    description: "The require() function should be used to ensure valid conditions. A failed require() should indicate a bug or invalid input.",
    severity: "medium",
    remediation: "Ensure require conditions are correct and comprehensive.",
  },
  {
    id: "SWC-124",
    title: "Write to Arbitrary Storage Location",
    description: "A malicious actor may be able to write to any storage location, potentially corrupting the contract state.",
    severity: "critical",
    remediation: "Validate all array indices and storage slot calculations.",
  },
  {
    id: "SWC-125",
    title: "Incorrect Inheritance Order",
    description: "Solidity uses C3 linearization for multiple inheritance. Incorrect ordering can lead to unexpected behavior.",
    severity: "medium",
    remediation: "Order inheritance from most base-like to most derived.",
  },
  {
    id: "SWC-126",
    title: "Insufficient Gas Griefing",
    description: "If a contract makes an external call and the callee runs out of gas, the calling contract may fail unexpectedly.",
    severity: "medium",
    remediation: "Forward enough gas or use call{gas: amount}().",
  },
  {
    id: "SWC-127",
    title: "Arbitrary Jump with Function Type Variable",
    description: "Function type variables can be used to jump to arbitrary code locations.",
    severity: "critical",
    remediation: "Avoid using function type variables with user-controlled data.",
  },
  {
    id: "SWC-128",
    title: "DoS With Block Gas Limit",
    description: "Operations that loop over unbounded data structures can exceed the block gas limit.",
    severity: "medium",
    remediation: "Implement pagination or limit iteration counts.",
  },
  {
    id: "SWC-129",
    title: "Typographical Error",
    description: "A typo can introduce bugs. Common examples include using = instead of == or += instead of =+.",
    severity: "medium",
    remediation: "Use linters and code review to catch typos.",
  },
  {
    id: "SWC-130",
    title: "Right-To-Left-Override control character (U+202E)",
    description: "Malicious actors can use Unicode control characters to make code appear different than it actually is.",
    severity: "high",
    remediation: "Disallow special Unicode characters in source code.",
  },
  {
    id: "SWC-131",
    title: "Presence of unused variables",
    description: "Unused variables may indicate bugs or incomplete implementation.",
    severity: "low",
    remediation: "Remove unused variables.",
  },
  {
    id: "SWC-132",
    title: "Unexpected Ether balance",
    description: "Contracts can receive Ether via selfdestruct or as coinbase reward, bypassing receive/fallback functions.",
    severity: "medium",
    remediation: "Don't rely on address(this).balance for logic.",
  },
  {
    id: "SWC-133",
    title: "Hash Collisions With Multiple Variable Length Arguments",
    description: "Using abi.encodePacked with multiple variable-length arguments can lead to hash collisions.",
    severity: "medium",
    remediation: "Use abi.encode instead of abi.encodePacked for variable-length arguments.",
  },
  {
    id: "SWC-134",
    title: "Message call with hardcoded gas amount",
    description: "The transfer() and send() functions use a hardcoded gas stipend of 2300, which can cause issues.",
    severity: "medium",
    remediation: "Use call{value: amount}('') instead of transfer() or send().",
  },
  {
    id: "SWC-135",
    title: "Code With No Effects",
    description: "Code that does not affect the state or produce outputs may indicate a bug.",
    severity: "low",
    remediation: "Remove code with no effects or fix the underlying bug.",
  },
  {
    id: "SWC-136",
    title: "Unencrypted Private Data On-Chain",
    description: "Private data stored on-chain is visible to anyone who inspects the blockchain.",
    severity: "high",
    remediation: "Never store sensitive data on-chain. Use encryption or off-chain storage.",
  },
];

/**
 * Register the ingest_swc tool
 */
export function registerIngestSwc(server: McpServer): void {
  server.tool(
    "ingest_swc",
    "Ingest the SWC (Smart Contract Weakness Classification) Registry into the knowledge base",
    {
      fetchLatest: z.boolean()
        .optional()
        .default(false)
        .describe("Attempt to fetch the latest SWC data from GitHub"),
    },
    async ({ fetchLatest }) => {
      try {
        let entries = SWC_REGISTRY;
        
        if (fetchLatest) {
          // In a real implementation, fetch from GitHub
          // For now, use the built-in registry
          logger.info("Using built-in SWC Registry (fetching not implemented)");
        }
        
        const count = await ingestSwcRegistry(entries);
        
        return jsonResponse({
          success: true,
          message: `Ingested ${count} SWC entries`,
          entries: entries.map(e => ({ id: e.id, title: e.title, severity: e.severity })),
        });
        
      } catch (e) {
        logger.error("Failed to ingest SWC", { error: e });
        return errorResponse("Failed to ingest SWC Registry", { error: String(e) });
      }
    }
  );
}

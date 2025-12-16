# Blockchain Security MCP Server

MCP server for blockchain security analysis and bug bounty hunting.

## Quick Start

```bash
cd blockchain-security-mcp
npm install
npm run dev
```

## Add to Cursor

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blockchain-security": {
      "command": "npx",
      "args": ["tsx", "/YOUR/PATH/blockchain-security-mcp/src/index.ts"]
    }
  }
}
```

Restart Cursor and test: "Run a health check on the security scanner"

## Architecture

```
src/
├── index.ts          # Entry point (minimal)
├── server.ts         # MCP server setup
├── core/             # Shared core
│   ├── config.ts     # Configuration
│   ├── logger.ts     # Logging
│   ├── types.ts      # TypeScript types
│   ├── errors.ts     # Custom errors
│   └── index.ts      # Barrel export
├── tools/            # MCP tool handlers (thin layer)
│   ├── system.tools.ts     # Health check, utilities
│   ├── analysis.tools.ts   # File reading, analysis
│   └── index.ts            # Register all tools
├── utils/            # Utility functions
│   ├── command.utils.ts    # Shell commands
│   ├── file.utils.ts       # File operations
│   ├── solidity.utils.ts   # Solidity parsing
│   └── index.ts
├── services/         # Business logic (Step 2+)
├── database/         # Data layer (Step 2+)
└── patterns/         # Exploit patterns (Step 4+)
```

## Available Tools

| Tool | Description |
|------|-------------|
| `health_check` | Check server status and available tools |
| `list_tools` | List security tools with install hints |
| `read_solidity` | Read .sol file with metadata extraction |
| `list_contracts` | Find all contracts in a directory |
| `analyze_contract` | Quick security analysis |

## Design Principles

1. **Separation of Concerns**
   - `tools/` - Thin handlers, input validation, response formatting
   - `services/` - Business logic (coming in Step 2+)
   - `utils/` - Pure utility functions
   - `core/` - Shared infrastructure

2. **Single Responsibility**
   - Each file does one thing well
   - Easy to test, extend, maintain

3. **Barrel Exports**
   - Each folder has `index.ts`
   - Clean imports: `from "./core/index.js"`

4. **Type Safety**
   - All types in `core/types.ts`
   - Zod for runtime validation

## Roadmap

- [x] Step 1: Foundation & Architecture
- [ ] Step 2: Knowledge Base (ChromaDB + SQLite)
- [ ] Step 3: Static Analysis Tools (Slither, Mythril)
- [ ] Step 4: Exploit Patterns (Balancer, Curve, etc.)
- [ ] Step 5: PoC Generation
- [ ] Step 6: Bug Bounty Workflow

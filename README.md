# Blockchain Security MCP Server

MCP server for blockchain security analysis and bug bounty hunting.

## Quick Start

```bash
npm install
npm run build
npm run dev
```

## Add to Cursor

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blockchain-security": {
      "command": "npx",
      "args": ["tsx", "/YOUR/PATH/mpc-bb/src/index.ts"]
    }
  }
}
```

Restart Cursor and test: "Run a health check on the security scanner"

## Architecture

```
src/
├── index.ts              # Entry point - initializes environment, starts server
├── server.ts             # MCP server creation and configuration
│
├── core/                 # Shared infrastructure
│   ├── config.ts         # Configuration (paths, RPC URLs, timeouts)
│   ├── logger.ts         # Winston-based logging
│   ├── types.ts          # TypeScript types and response helpers
│   ├── errors.ts         # Custom error classes
│   └── index.ts          # Barrel export
│
├── tools/                # MCP tool handlers (organized by category)
│   ├── system/           # System tools
│   │   ├── health_check.ts
│   │   ├── list_tools.ts
│   │   └── index.ts      # Registers system tools
│   ├── analysis/         # Analysis tools
│   │   ├── read_solidity.ts
│   │   ├── list_contracts.ts
│   │   ├── analyze_contract.ts
│   │   └── index.ts      # Registers analysis tools
│   └── index.ts          # Registers all tools
│
├── utils/                # Pure utility functions
│   ├── command.utils.ts  # Safe shell command execution
│   ├── file.utils.ts     # File operations
│   ├── solidity.utils.ts # Solidity parsing and analysis
│   └── index.ts          # Barrel export
│
├── services/             # Business logic layer (Step 2+)
├── database/             # Data persistence layer (Step 2+)
└── patterns/             # Exploit pattern library (Step 4+)
```

## Available Tools

### System Tools
| Tool | Description |
|------|-------------|
| `health_check` | Check server status, available tools, and system information |
| `list_tools` | List all security tools with installation status and hints |

### Analysis Tools
| Tool | Description |
|------|-------------|
| `read_solidity` | Read Solidity file with metadata extraction (functions, imports, etc.) |
| `list_contracts` | Find all Solidity contracts in a directory (recursive) |
| `analyze_contract` | Perform quick security analysis on a contract |

## Design Principles

1. **Separation of Concerns**
   - `tools/` - Thin handlers: input validation, tool registration, response formatting
   - `services/` - Business logic (coming in Step 2+)
   - `utils/` - Pure, reusable utility functions
   - `core/` - Shared infrastructure (config, logging, types, errors)

2. **Modular Tool Organization**
   - Tools grouped by category (`system/`, `analysis/`)
   - Each category has its own registration function
   - Easy to add new tool categories

3. **Single Responsibility**
   - Each file does one thing well
   - Tool handlers are thin wrappers around utility functions
   - Easy to test, extend, and maintain

4. **Barrel Exports**
   - Each folder has `index.ts` for clean imports
   - Consistent import pattern: `from "./core/index.js"`

5. **Type Safety**
   - All types defined in `core/types.ts`
   - Zod schemas for runtime validation
   - Custom error classes for better error handling

6. **Configuration Management**
   - Centralized config in `core/config.ts`
   - Environment variable support
   - Path resolution and validation

## Configuration

The server uses environment variables for configuration:

- `NODE_ENV` - Set to `production` for production mode
- `ETH_RPC_URL` - Ethereum RPC endpoint (default: `https://eth.llamarpc.com`)
- `POLYGON_RPC_URL` - Polygon RPC endpoint
- `ARBITRUM_RPC_URL` - Arbitrum RPC endpoint

Paths are automatically resolved relative to the project root:
- `data/` - Data directory for persistent storage
- `logs/` - Log files directory

## Roadmap

- [x] Step 1: Foundation & Architecture
  - [x] Core infrastructure (config, logger, types, errors)
  - [x] System tools (health check, tool listing)
  - [x] Analysis tools (read, list, analyze contracts)
  - [x] Utility functions (commands, files, Solidity parsing)
- [ ] Step 2: Knowledge Base (ChromaDB + SQLite)
- [ ] Step 3: Static Analysis Tools (Slither, Mythril)
- [ ] Step 4: Exploit Patterns (Balancer, Curve, etc.)
- [ ] Step 5: PoC Generation
- [ ] Step 6: Bug Bounty Workflow

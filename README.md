# Blockchain Security MCP Server

MCP server for comprehensive blockchain security analysis and bug bounty hunting. Features static analysis, knowledge base integration, and historical exploit pattern matching.

## Quick Start

### Prerequisites

- Node.js 18+
- Docker and Docker Compose (for ChromaDB vector database)

### Setup

1. **Install dependencies:**
```bash
npm install
npm run build
```

2. **Start ChromaDB (required for knowledge base):**
```bash
docker-compose up -d
```

3. **Start the MCP server:**
```bash
npm run dev
```

4. **Ingest knowledge base data (first time setup):**
```bash
# Ingest SWC registry and attack vectors
ingest_swc
ingest_attack_vectors

# Ingest historical exploits from all sources
ingest_exploits source="all"
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
│   │   ├── comprehensive_analysis.ts  # Comprehensive security analysis
│   │   └── index.ts      # Registers analysis tools
│   ├── knowledge/        # Knowledge base tools
│   │   ├── ingest_exploits.ts
│   │   ├── ingest_swc.ts
│   │   ├── ingest_attack_vectors.ts
│   │   ├── query_knowledge.ts
│   │   ├── knowledge_stats.ts
│   │   ├── analyze_defihacklabs.ts
│   │   ├── analyze_learn_evm_attacks.ts
│   │   ├── analyze_attack_vectors.ts
│   │   ├── find_similar.ts
│   │   ├── record_finding.ts
│   │   └── index.ts      # Registers knowledge tools
│   └── index.ts          # Registers all tools
│
├── services/             # Business logic layer
│   ├── knowledge.service.ts      # Knowledge base operations
│   ├── defihacklabs.service.ts   # DeFiHackLabs parser
│   ├── learn-evm-attacks.service.ts  # learn-evm-attacks parser
│   └── solidity-attack-vectors.service.ts  # Attack vectors parser
│
├── database/             # Data persistence layer
│   ├── index.ts          # Database initialization
│   ├── vector-db.ts      # ChromaDB integration
│   ├── sqlite-db.ts      # SQLite integration
│   └── repositories/     # Data access layer
│
└── utils/                # Pure utility functions
    ├── command.utils.ts  # Safe shell command execution
    ├── file.utils.ts     # File operations
    ├── solidity.utils.ts # Solidity parsing and analysis
    └── index.ts          # Barrel export
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
| `comprehensive_analysis` | **Comprehensive security analysis** - combines static analysis, external tools (Slither, Solhint, Mythril), and all knowledge base sources. Features multi-query aggregation, similar exploit detection, risk assessment, and detailed recommendations. |

### Knowledge Base Tools

#### Data Ingestion
| Tool | Description |
|------|-------------|
| `ingest_exploits` | Ingest historical DeFi exploits from multiple sources (`builtin`, `defihacklabs`, `learn-evm-attacks`, `rekt`, `all`) |
| `ingest_swc` | Ingest SWC Registry entries (Smart Contract Weakness Classification) |
| `ingest_attack_vectors` | Ingest Solidity Attack Vectors from the comprehensive attack vector repository |

#### Query & Analysis
| Tool | Description |
|------|-------------|
| `query_knowledge` | Semantic search across all knowledge base collections (SWC, exploits, audit findings) |
| `knowledge_stats` | Get statistics about the knowledge base (total entries, breakdown by source, category, etc.) |
| `find_similar` | Find similar exploits or findings based on code patterns and vulnerability indicators |
| `record_finding` | Record a new security finding for future reference |

#### Source Analysis
| Tool | Description |
|------|-------------|
| `analyze_defihacklabs` | Analyze and provide statistics on DeFiHackLabs repository exploits |
| `analyze_learn_evm_attacks` | Analyze and provide statistics on learn-evm-attacks repository |
| `analyze_attack_vectors` | Analyze and provide statistics on Solidity Attack Vectors repository |

## Knowledge Base Sources

The knowledge base integrates multiple security data sources:

1. **SWC Registry** - 37 official Smart Contract Weakness Classification entries
2. **Solidity Attack Vectors** - 54+ detailed attack vectors with code examples and remediations
3. **DeFiHackLabs** - Real-world exploit reproductions with POC code
4. **learn-evm-attacks** - Educational exploit reproductions with detailed attack steps
5. **Historical Exploits** - Curated list of major DeFi hacks (The DAO, Poly Network, Ronin, etc.)

### External Knowledge Sources

The system can parse and ingest data from external repositories placed in the `resource/` folder:

- `resource/DeFiHackLabs/` - DeFiHackLabs repository
- `resource/learn-evm-attacks/` - learn-evm-attacks repository  
- `resource/Solidity-Attack-Vectors/` - Solidity Attack Vectors repository

These are automatically parsed and converted to the knowledge base format when using `ingest_exploits` or `ingest_attack_vectors`.

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

### Environment Variables

The server uses environment variables for configuration:

- `NODE_ENV` - Set to `production` for production mode
- `ETH_RPC_URL` - Ethereum RPC endpoint (default: `https://eth.llamarpc.com`)
- `POLYGON_RPC_URL` - Polygon RPC endpoint
- `ARBITRUM_RPC_URL` - Arbitrum RPC endpoint

### Paths

Paths are automatically resolved relative to the project root:
- `data/` - Data directory for persistent storage (SQLite, ChromaDB)
- `logs/` - Log files directory
- `resource/` - External knowledge source repositories (gitignored)

### ChromaDB Configuration

ChromaDB runs via Docker Compose and is accessible at `http://localhost:8000`. The vector database persists data in `data/chroma/`.

### External Security Tools (Optional)

The `comprehensive_analysis` tool can integrate with external security tools if installed:

- **Slither**: `pip install slither-analyzer`
- **Solhint**: `npm install -g solhint`
- **Mythril**: `pip install mythril`

These are optional - the analysis works without them but provides more comprehensive results when available.

## Features

### ✅ Implemented

- **Core Infrastructure**: Config, logging, error handling, type safety
- **Static Analysis**: Solidity parsing, vulnerability pattern detection, function extraction
- **Knowledge Base**: 
  - ChromaDB vector database for semantic search
  - SQLite for structured data storage
  - Multi-source knowledge ingestion (SWC, exploits, attack vectors)
  - Semantic search and similarity matching
- **Comprehensive Analysis**: 
  - Static analysis with 50+ vulnerability checks
  - External tool integration (Slither, Solhint, Mythril)
  - Multi-source knowledge base queries
  - Similar exploit detection
  - Risk assessment and recommendations
- **External Knowledge Sources**:
  - DeFiHackLabs integration
  - learn-evm-attacks integration
  - Solidity Attack Vectors integration
- **Analysis Tools**: Contract reading, listing, quick analysis, comprehensive analysis

### 🚧 Roadmap

- [ ] Step 4: Advanced Exploit Patterns
  - [ ] Pattern library expansion
  - [ ] Automated pattern matching
- [ ] Step 5: PoC Generation
  - [ ] Automated proof-of-concept generation
  - [ ] Test case generation
- [ ] Step 6: Bug Bounty Workflow
  - [ ] Finding management
  - [ ] Report generation
  - [ ] Integration with bug bounty platforms

## Usage Examples

### Comprehensive Security Analysis

```bash
# Run comprehensive analysis on a contract
comprehensive_analysis path="contracts/Vault.sol" comprehensiveMode=true useExternalTools=true
```

This will:
- Perform static analysis with 50+ vulnerability checks
- Query all knowledge base sources (SWC, exploits, attack vectors)
- Find similar historical exploits
- Run external tools (if available)
- Generate risk assessment and recommendations

### Knowledge Base Operations

```bash
# Ingest all exploit data
ingest_exploits source="all"

# Query knowledge base
query_knowledge query="reentrancy vulnerability" limit=10

# Get knowledge base statistics
knowledge_stats

# Find similar exploits
find_similar contractPath="contracts/Vault.sol"
```

## Contributing

1. Clone the repository
2. Install dependencies: `npm install`
3. Start ChromaDB: `docker-compose up -d`
4. Make your changes
5. Test thoroughly
6. Submit a pull request

## License

[Add your license here]

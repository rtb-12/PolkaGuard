# Configuration Reference

PolkaGuard supports extensive configuration through JSON files and CLI arguments. This guide covers all available options.

## 📁 Configuration File Structure

### Default Configuration Path
- **Initialize**: `polkaguard --path ./contracts init`
- **Custom path**: `polkaguard --path ./contracts in### Configuration Templates

Create reusable configuration templates:

```bash
# High-security template
cp polkaguard.json high-security.json
# Edit high-security.json to enable all security checks

# Performance template  
cp polkaguard.json performance.json
# Edit performance.json to optimize for large contracts

# Use template
polkaguard --path contract.sol --config-path ./templates/high-security.json analyze
```

#### High-Security Template Example

```json
{
  "enabled_checks": ["compatibility", "security", "best-practices"],
  "severity_threshold": "low",
  "output_format": "json",
  "compiler_settings": {
    "optimizer": false,
    "runs": 1,
    "version": "0.8.0",
    "evm_version": "paris"
  },
  "analysis_settings": {
    "security_checks": {
      "check_reentrancy": true,
      "check_access_control": true,
      "check_arithmetic": true,
      "check_external_calls": true,
      "check_selfdestruct": true,
      "check_timestamp_dependency": true
    },
    "best_practices": {
      "require_events": true,
      "require_modifiers": true,
      "require_constructor": true,
      "require_spdx": true,
      "require_version_pragma": true,
      "require_natspec": true
    }
  }
}
```

#### Performance Template Example

```json
{
  "enabled_checks": ["compatibility", "resources"],
  "severity_threshold": "high",
  "output_format": "text", 
  "analysis_settings": {
    "memory_limits": {
      "max_stack_size": 131072,
      "max_heap_size": 262144,
      "warn_on_large_arrays": false,
      "large_array_threshold": 5000
    }
  },
  "polkavm_settings": {
    "check_evm_compatibility": true,
    "check_memory_constraints": false,
    "check_gas_usage": true,
    "check_storage_usage": true
  }
}
``` ./config/polkaguard.json`

### Complete Configuration Example

```json
{
  "enabled_checks": [
    "compatibility",
    "security",
    "resources",
    "best-practices"
  ],
  "severity_threshold": "medium",
  "output_format": "text",
  "compiler_settings": {
    "optimizer": true,
    "runs": 200,
    "version": "0.8.0",
    "evm_version": "paris"
  },
  "analysis_settings": {
    "memory_limits": {
      "max_stack_size": 32768,
      "max_heap_size": 65536,
      "warn_on_large_arrays": true,
      "large_array_threshold": 1000
    },
    "security_checks": {
      "check_reentrancy": true,
      "check_access_control": true,
      "check_arithmetic": true,
      "check_external_calls": true,
      "check_selfdestruct": true,
      "check_timestamp_dependency": true
    },
    "best_practices": {
      "require_events": true,
      "require_modifiers": true,
      "require_constructor": true,
      "require_spdx": true,
      "require_version_pragma": true,
      "require_natspec": true
    }
  },
  "polkavm_settings": {
    "check_evm_compatibility": true,
    "check_memory_constraints": true,
    "check_gas_usage": true,
    "check_storage_usage": true,
    "allowed_opcodes": [
      "ADD", "SUB", "MUL", "DIV", "SDIV", "MOD", "SMOD", "EXP",
      "NOT", "LT", "GT", "SLT", "SGT", "EQ", "ISZERO", "AND", "OR", "XOR",
      "BYTE", "SHL", "SHR", "SAR", "ADDMOD", "MULMOD", "SIGNEXTEND",
      "KECCAK256", "ADDRESS", "BALANCE", "ORIGIN", "CALLER", "CALLVALUE",
      "CALLDATALOAD", "CALLDATASIZE", "CALLDATACOPY", "CODESIZE", "CODECOPY",
      "GASPRICE", "EXTCODESIZE", "EXTCODECOPY", "RETURNDATASIZE", "RETURNDATACOPY",
      "EXTCODEHASH", "BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER", "DIFFICULTY",
      "GASLIMIT", "POP", "MLOAD", "MSTORE", "MSTORE8", "SLOAD", "SSTORE",
      "JUMP", "JUMPI", "PC", "MSIZE", "GAS", "JUMPDEST",
      "PUSH1", "PUSH2", "PUSH3", "PUSH4", "PUSH5", "PUSH6", "PUSH7", "PUSH8",
      "PUSH9", "PUSH10", "PUSH11", "PUSH12", "PUSH13", "PUSH14", "PUSH15", "PUSH16",
      "PUSH17", "PUSH18", "PUSH19", "PUSH20", "PUSH21", "PUSH22", "PUSH23", "PUSH24",
      "PUSH25", "PUSH26", "PUSH27", "PUSH28", "PUSH29", "PUSH30", "PUSH31", "PUSH32",
      "DUP1", "DUP2", "DUP3", "DUP4", "DUP5", "DUP6", "DUP7", "DUP8",
      "DUP9", "DUP10", "DUP11", "DUP12", "DUP13", "DUP14", "DUP15", "DUP16",
      "SWAP1", "SWAP2", "SWAP3", "SWAP4", "SWAP5", "SWAP6", "SWAP7", "SWAP8",
      "SWAP9", "SWAP10", "SWAP11", "SWAP12", "SWAP13", "SWAP14", "SWAP15", "SWAP16",
      "LOG0", "LOG1", "LOG2", "LOG3", "LOG4", "CREATE", "CALL", "CALLCODE",
      "RETURN", "DELEGATECALL", "CREATE2", "STATICCALL", "REVERT", "INVALID", "SELFDESTRUCT"
    ],
    "forbidden_opcodes": [
      "SELFDESTRUCT",
      "EXTCODESIZE", 
      "EXTCODECOPY",
      "EXTCODEHASH",
      "BLOBHASH",
      "BLOBBASEFEE"
    ]
  }
}
```

## 🏗️ Configuration Sections

### Root Configuration

Controls the main analysis behavior:

```json
{
  "enabled_checks": ["compatibility", "security", "resources", "best-practices"],
  "severity_threshold": "medium",
  "output_format": "text"
}
```

**Available Checks:**
- `compatibility`: PolkaVM compatibility analysis
- `security`: Security vulnerability detection  
- `resources`: Resource usage estimation
- `best-practices`: Code quality and style checks

**Severity Levels:**
- `low`: Informational suggestions
- `medium`: Important issues requiring attention
- `high`: Critical issues that prevent deployment

**Output Formats:**
- `text`: Human-readable output with colors and emojis
- `json`: Structured JSON output for automation

### Compiler Settings

Controls Solidity compilation behavior:

```json
{
  "compiler_settings": {
    "optimizer": true,
    "runs": 200,
    "version": "0.8.0",
    "evm_version": "paris"
  }
}
```

**Available EVM Versions:**
- `homestead`, `tangerineWhistle`, `spuriousDragon`
- `byzantium`, `constantinople`, `petersburg`
- `istanbul`, `berlin`, `london`, `paris`

### Analysis Settings

Configures detailed analysis behavior:

#### Memory Limits

Controls resource consumption during analysis:

```json
{
  "analysis_settings": {
    "memory_limits": {
      "max_stack_size": 32768,
      "max_heap_size": 65536,
      "warn_on_large_arrays": true,
      "large_array_threshold": 1000
    }
  }
}
```

**Recommended Values:**
- **Small contracts**: max_stack_size=16384, max_heap_size=32768
- **Medium contracts**: max_stack_size=32768, max_heap_size=65536  
- **Large contracts**: max_stack_size=65536, max_heap_size=131072

#### Security Checks

Fine-tune security analysis:

```json
{
  "analysis_settings": {
    "security_checks": {
      "check_reentrancy": true,
      "check_access_control": true,
      "check_arithmetic": true,
      "check_external_calls": true,
      "check_selfdestruct": true,
      "check_timestamp_dependency": true
    }
  }
}
```

#### Best Practices

Configure code quality checks:

```json
{
  "analysis_settings": {
    "best_practices": {
      "require_events": true,
      "require_modifiers": true,
      "require_constructor": true,
      "require_spdx": true,
      "require_version_pragma": true,
      "require_natspec": true
    }
  }
}
```

### PolkaVM Settings

PolkaVM-specific compatibility configuration:

```json
{
  "polkavm_settings": {
    "check_evm_compatibility": true,
    "check_memory_constraints": true,
    "check_gas_usage": true,
    "check_storage_usage": true,
    "allowed_opcodes": ["ADD", "SUB", "MUL", "..."],
    "forbidden_opcodes": ["SELFDESTRUCT", "EXTCODESIZE", "EXTCODECOPY", "EXTCODEHASH", "BLOBHASH", "BLOBBASEFEE"]
  }
}
```

**Forbidden Opcodes**: These EVM opcodes are not compatible with PolkaVM:
- `SELFDESTRUCT`: Contract self-destruction not supported
- `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`: External code inspection not available
- `BLOBHASH`, `BLOBBASEFEE`: Blob transaction features not supported

## 🌐 Network Configuration

Network settings are built-in but can be referenced:

### Built-in Networks

| Network  | Token | Decimals | Storage Deposit/Byte | Price (USD) |
| -------- | ----- | -------- | -------------------- | ----------- |
| Polkadot | DOT   | 10       | 1,000,000,000        | $7.00       |
| Kusama   | KSM   | 12       | 100,000,000          | $25.00      |
| Westend  | WND   | 12       | 100,000,000          | $0.00       |
| Rococo   | ROC   | 12       | 100,000,000          | $0.00       |
| Local    | UNIT  | 12       | 100,000,000          | $0.00       |

### Cost Calculation Parameters

Each network includes precise cost calculation settings:

```rust
// Example: Polkadot network configuration
NetworkConfig {
    name: "Polkadot",
    token_symbol: "DOT",
    token_decimals: 10,
    ref_time_price_per_unit: 100,      // plancks per ref_time unit
    proof_size_price_per_byte: 1000,   // plancks per proof_size byte
    storage_deposit_per_byte: 1_000_000_000, // plancks per storage byte
    token_price_usd: 7.0,
}
```

## 🚀 CLI Override Options

Command-line arguments override configuration file settings:

### Global Options

```bash
--network <NETWORK>        # Override network (polkadot|kusama|westend|rococo|local)
--checks <CHECKS>          # Override enabled checks (comma-separated)
--format <FORMAT>          # Override output format (text|json)
--stack-size <SIZE>        # Override stack size in bytes
--heap-size <SIZE>         # Override heap size in bytes
```

### Examples

```bash
# Override network and format
polkaguard --path contract.sol --network kusama --format json analyze

# Override memory limits
polkaguard --path contract.sol --stack-size 131072 --heap-size 262144 analyze

# Override specific checks
polkaguard --path contract.sol --checks security,compatibility analyze

# Use custom configuration file
polkaguard --path contract.sol --config-path ./custom-config.json analyze
```

## 🔧 Configuration Validation

PolkaGuard validates configuration on startup:

### Validation Rules

- **Memory limits**: Must be multiples of 4096 bytes
- **Check names**: Must be valid check identifiers
- **Network names**: Must be supported network identifiers
- **Severity threshold**: Must be valid severity level
- **File paths**: Must be accessible and readable

### Error Handling

```bash
# Invalid configuration example
polkaguard --path contract.sol --network invalid analyze
# Error: Unsupported network 'invalid'. Available: polkadot, kusama, westend, rococo, local

# Invalid memory size
polkaguard --path contract.sol --stack-size 1000 analyze
# Error: Stack size must be a multiple of 4096 bytes
```

## 🛠️ Advanced Usage

### Environment Variables

Set default values using environment variables:

```bash
export POLKAGUARD_NETWORK=kusama
export POLKAGUARD_FORMAT=json
export POLKAGUARD_STACK_SIZE=131072

# Now defaults to Kusama network with JSON output
polkaguard --path contract.sol analyze
```

### Configuration Templates

Create reusable configuration templates:

```bash
# High-security template
cp polkaguard.toml high-security.toml
# Edit high-security.toml to enable all security checks

# Performance template
cp polkaguard.toml performance.toml
# Edit performance.toml to optimize for large contracts

# Use template
polkaguard --path contract.sol --config-path ./templates/high-security.toml analyze
```

### Batch Processing

Process multiple contracts with consistent configuration:

```bash
# Process all contracts in directory
for contract in contracts/*.sol; do
    polkaguard --path "$contract" --config-path ./production.json analyze
done

# Process with different configurations for different contract types
for contract in contracts/tokens/*.sol; do
    polkaguard --path "$contract" --config-path ./templates/token-security.json analyze
done

for contract in contracts/defi/*.sol; do
    polkaguard --path "$contract" --config-path ./templates/defi-analysis.json analyze
done
```


# PolkaGuard

<div align="center">
  <img src="assets/PolkaGuard.png" alt="PolkaGuard Logo" width="200"/>

[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

</div>

A comprehensive Rust-based CLI tool for analyzing Solidity smart contracts targeting PolkaVM deployment via the pallet-revive module.

## 🚀 Key Features

### ✅ **Smart Contract Analysis**

- **PolkaVM Compatibility**: Detects EVM-incompatible opcodes (`selfdestruct`, `extcodesize`, etc.)
- **Security Vulnerabilities**: Reentrancy detection, unchecked calls, access control validation
- **Resource Estimation**: ref_time, proof_size, storage usage with complexity metrics
- **Best Practices**: SPDX license, pragma directives, function visibility, NatSpec documentation
- **Syntax Linting**: Comprehensive code quality checks with severity levels

### 💰 **Multi-Network Cost Calculations**

- **Polkadot** (DOT): 10 decimal places, mainnet pricing
- **Kusama** (KSM): 12 decimal places, canary network
- **Westend** (WND): 12 decimal places, testnet (no USD value)
- **Rococo** (ROC): 12 decimal places, testnet (no USD value)
- **Local** (UNIT): 12 decimal places, development environment

### 🔧 **Advanced CLI Features**

- **Selective Analysis**: `--checks compatibility,security,resources,best-practices`
- **Network Selection**: `--network polkadot|kusama|westend|rococo|local`
- **Multiple Output Formats**: Text with colors/emojis and structured JSON
- **Memory Configuration**: Custom `--stack-size` and `--heap-size` limits
- **Contract Disassembly**: PolkaVM bytecode generation with `--overwrite` support
- **Initialization**: Project setup with `init` command

## 📦 Installation

### Prerequisites

- **Rust 1.70+**: [Install Rust](https://rustup.rs/)
- **Solidity Compiler**: `npm install -g solc` or download from [releases](https://github.com/ethereum/solidity/releases)
-  **Resolc Compiler**: download from [releases](https://github.com/paritytech/revive/releases)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/rtb-12/polkaguard.git
cd polkaguard

# Build optimized release
cargo build --release

# Run directly
./target/release/polkaguard --help

# Install globally (optional)
cargo install --path .
```

## 🎯 Quick Start

### Basic Analysis

```bash
# Analyze with default Polkadot network
polkaguard --path ./contracts/MyContract.sol analyze

# Selective checks
polkaguard --path ./contracts/MyContract.sol --checks security,compatibility analyze

# Different network with JSON output
polkaguard --path ./contracts/MyContract.sol --network kusama --format json analyze
```

### Network Cost Comparison

```bash
# Compare costs across networks
polkaguard --path ./contracts/MyContract.sol --network polkadot analyze
polkaguard --path ./contracts/MyContract.sol --network kusama analyze
polkaguard --path ./contracts/MyContract.sol --network westend analyze
```

### Advanced Usage

```bash
# Custom memory limits
polkaguard --path ./contracts/MyContract.sol --stack-size 65536 --heap-size 131072 analyze

# Contract disassembly
polkaguard --path ./contracts/MyContract.sol --overwrite disassemble

# Project initialization
polkaguard --path ./contracts init --config-path ./polkaguard.json
```

## 📊 Sample Output

### Text Output (Polkadot Network)

```
Resource Usage Analysis:
------------------------
1. Resource Usage Estimation:
   - Computation Time (ref_time): 36000 units
   - State Proof Size: 1.37 KB bytes
   - Storage Deposit: 0.000000 DOT
   - Storage Usage: 0.00 B bytes

2. Cost Implications:
   Network: Polkadot (DOT)
   - Computation Cost: 0.000360 DOT (3600000 plancks)
   - Proof Size Cost: 0.000140 DOT (1400000 plancks)
   - Storage Deposit: 0.000000 DOT (0 plancks)
   - Total Estimated Cost: 0.000500 DOT (≈ $0.00 USD)

   📊 Cost Calculation Methodology:
     • ref_time: 36000 units × 100 plancks/unit = 3600000 plancks
     • proof_size: 1400 bytes × 1000 plancks/byte = 1400000 plancks
     • storage_deposit: 0 bytes × 1000000000 plancks/byte = 0 plancks
     • 1 DOT = 10^10 plancks
```

### JSON Output Structure

```json
{
  "analysis_results": {
    "contract_name": "Owner",
    "complexity": 11,
    "compatibility_issues": [],
    "security_vulnerabilities": ["Potential reentrancy vulnerability"],
    "resource_usage": {
      "ref_time": 36000,
      "proof_size": 1400,
      "storage_deposit": 0,
      "storage_usage": 0
    },
    "cost_breakdown": {
      "network": {
        "name": "Polkadot",
        "token_symbol": "DOT",
        "token_decimals": 10,
        "ref_time_price_per_unit": 100,
        "proof_size_price_per_byte": 1000,
        "storage_deposit_per_byte": 1000000000,
        "token_price_usd": 7.0
      },
      "total_cost_tokens": 0.0005,
      "total_cost_usd": 0.0035
    },
    "best_practices": []
  }
}
```

## 🎮 CLI Commands

### Core Commands

```bash
# Initialize project with config
polkaguard --path ./contracts init [--config-path ./config.json]

# Analyze contract (supports all check types)
polkaguard --path ./contract.sol analyze

# List available checks
polkaguard --path ./contracts list-checks

# Disassemble to PolkaVM bytecode
polkaguard --path ./contract.sol disassemble [--overwrite]

# Version information
polkaguard --version --help
```

### Global Options

```bash
--path <PATH>              Path to contract or directory
--network <NETWORK>        polkadot|kusama|westend|rococo|local (default: polkadot)
--checks <CHECKS>          compatibility,security,resources,best-practices
--format <FORMAT>          text|json (default: text)
--stack-size <SIZE>        Custom stack size in bytes
--heap-size <SIZE>         Custom heap size in bytes
--overwrite               Overwrite existing .pvm files
```

## 🧪 Testing

Run the comprehensive test suite with **21 tests** covering all features:

```bash
# Make executable and run tests
chmod +x test_polkaguard.sh
./test_polkaguard.sh
```

### Test Coverage

- **Tests 1-2**: Project initialization
- **Tests 3-11**: Contract analysis with different networks and options
- **Tests 12-15**: Check listing and help functionality
- **Tests 16-19**: Contract disassembly and bytecode generation
- **Tests 20**: Version information
- **Test 21**: Network cost comparison across all 5 networks

## 📚 Documentation

**📖 [Complete Documentation Hub](docs/README.md)** - Comprehensive guides and references

### Quick Links

- **[Cost Calculation Guide](DOT_COST_IMPLEMENTATION.md)**: Detailed DOT/KSM cost methodology
- **[Configuration Reference](docs/CONFIG.md)**: Complete configuration options and examples
- **[Network Guide](docs/NETWORKS.md)**: Multi-network support and cost comparisons
- **[Development Guide](docs/DEVELOPMENT.md)**: Architecture, contributing, and extending PolkaGuard

### Key Resources

- **21 Automated Tests**: Run `./test_polkaguard.sh` for comprehensive validation
- **5 Network Support**: Polkadot, Kusama, Westend, Rococo, Local with accurate cost calculations
- **Production Ready**: Extensive testing, robust error handling, precise cost calculations

## 🚀 Production Ready

PolkaGuard has been extensively tested with:

- ✅ **21 automated tests** covering all functionality
- ✅ **5 network configurations** (Polkadot, Kusama, Westend, Rococo, Local)
- ✅ **Accurate DOT/KSM cost calculations** with plancks precision
- ✅ **Comprehensive security analysis** with reentrancy detection
- ✅ **PolkaVM compatibility checks** for pallet-revive deployment

> **⚠️ Development Notice**: Some advanced features are still in active development. If you encounter any errors or unexpected behavior, please [raise an issue](https://github.com/rtb-12/polkaguard/issues) with detailed information about your use case and the error encountered. Your feedback helps improve PolkaGuard!

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Polkadot](https://polkadot.network/) team for PolkaVM and pallet-revive
- [Solidity](https://soliditylang.org/) team for the compiler
- Rust and Cargo communities for excellent tooling

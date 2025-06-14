# PolkaVM Fork Mode Setup Guide

This guide shows how to use PolkaGuard's new PolkaVM-compatible local fork mode using Hardhat and the hardhat-polkadot ecosystem.

## 🚀 Quick Start

### 1. Check Dependencies and Start Fork

```bash
# Check what's installed and start the fork with auto-setup
polkaguard run-fork --auto-install

# Or run in daemon mode (background)
polkaguard run-fork --daemon
```

### 2. Stop Running Fork

```bash
# Stop the background fork daemon
polkaguard run-fork --stop
```

### 3. Custom Configuration

```bash
# Specify custom paths and port
polkaguard run-fork \
  --port 9545 \
  --node-binary ./target/release/substrate-node \
  --adapter-binary ./target/release/revive-eth-rpc \
  --project-dir ./my-polkavm-project
```

## 📋 What PolkaGuard Does Automatically

### ✅ Dependency Management

- **Node.js Check**: Verifies Node.js ≥16 is installed
- **npm Check**: Ensures npm package manager is available
- **Binary Detection**: Auto-finds Substrate node and ETH-RPC adapter
- **Installation Guidance**: Provides step-by-step installation instructions if dependencies are missing

### ⚙️ Configuration Auto-Generation

PolkaGuard automatically creates:

**`hardhat.config.js`** - Complete Hardhat configuration:

```javascript
require("hardhat-polkadot");
require("dotenv").config();

module.exports = {
  solidity: {
    version: "0.8.28",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  resolc: {
    compilerSource: "binary",
    compilerPath: process.env.RESOLC_PATH || "resolc",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    hardhat: {
      polkavm: true,
      nodeConfig: {
        nodeBinaryPath: "substrate-node",
        rpcPort: 8545,
        dev: true,
      },
      adapterConfig: {
        adapterBinaryPath: "revive-eth-rpc",
        dev: true,
        rpcPort: 8545,
      },
    },
  },
};
```

**`.env`** - Environment configuration:

```bash
POLKAVM_RPC_PORT=8545
SUBSTRATE_NODE_PATH=substrate-node
ETH_RPC_ADAPTER_PATH=revive-eth-rpc
```

**`package.json`** - NPM project with dependencies:

```json
{
  "devDependencies": {
    "@nomicfoundation/hardhat-toolbox": "^5.0.0",
    "hardhat": "^2.19.0",
    "hardhat-polkadot": "^1.0.0",
    "hardhat-polkadot-resolc": "^1.0.0",
    "hardhat-polkadot-node": "^1.0.0",
    "dotenv": "^16.0.0"
  }
}
```

### 🔄 Process Management

- **Background Mode**: Run fork as daemon with `--daemon`
- **PID Tracking**: Stores process ID in `.polkaguard_fork.pid`
- **Auto-Cleanup**: Graceful shutdown on Ctrl+C or CLI exit
- **Health Checks**: Monitors if fork process is still running
- **Port Management**: Uses fixed port 8545 (configurable with `--port`)

### 🌐 RPC Endpoint

Once running, your PolkaVM fork provides:

- **HTTP RPC**: `http://localhost:8545`
- **Compatible with**: MetaMask, web3.js, ethers.js
- **Test Accounts**: Pre-funded accounts with mnemonic: `"test test test test test test test test test test test junk"`

## 💡 Example Usage Scenarios

### Development Workflow

```bash
# Start fork in background
polkaguard run-fork --daemon

# Deploy and test contracts
# (use any Ethereum tooling pointing to http://localhost:8545)

# Analyze contracts for PolkaVM compatibility
polkaguard --path ./MyContract.sol analyze

# Stop fork when done
polkaguard run-fork --stop
```

### Integration with Analysis

```bash
# Analyze contract and start fork for testing
polkaguard --path ./MyContract.sol analyze
polkaguard run-fork --daemon

# Run additional checks
polkaguard --path ./MyContract.sol memory-analysis
polkaguard --path ./MyContract.sol disassemble

# Clean up
polkaguard run-fork --stop
```

## 🔧 Binary Dependencies

### Required Binaries

1. **Substrate Node** (with pallet-revive):

   - Auto-detected names: `substrate-node`, `polkadot-parachain`, `substrate`
   - Custom path: `--node-binary /path/to/your/node`

2. **ETH-RPC Adapter**:
   - Auto-detected names: `revive-eth-rpc`, `eth-rpc`
   - Custom path: `--adapter-binary /path/to/revive-eth-rpc`

### Building Required Binaries

If you don't have the required binaries, you'll need to build them:

```bash
# Build Substrate node with pallet-revive
git clone https://github.com/paritytech/substrate-contracts-node
cd substrate-contracts-node
cargo build --release
# Binary: ./target/release/substrate-contracts-node

# Build ETH-RPC adapter
git clone https://github.com/paritytech/revive-ethereum
cd revive-ethereum
cargo build --release --bin revive-eth-rpc
# Binary: ./target/release/revive-eth-rpc
```

## 🛠️ Advanced Configuration

### Custom Project Directory

```bash
polkaguard run-fork --project-dir /path/to/my/hardhat/project
```

### Different Port

```bash
polkaguard run-fork --port 9545
```

### Status Check (JSON output)

```bash
polkaguard --format json run-fork --stop
```

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Check what's using port 8545
lsof -i :8545

# Use different port
polkaguard run-fork --port 9545
```

### Missing Dependencies

```bash
# Check dependency status
polkaguard run-fork --auto-install
# Follow the installation instructions provided
```

### Process Not Stopping

```bash
# Force stop if needed
pkill -f "hardhat node"

# Clean up PID file
rm .polkaguard_fork.pid
```

### Check Fork Status

The fork manager provides detailed status information:

- Current running status
- Process ID (if running)
- RPC endpoint URL
- Project directory location
- Dependency installation status

## 🔗 Integration Examples

### MetaMask Configuration

1. Start fork: `polkaguard run-fork --daemon`
2. Add network to MetaMask:
   - Network Name: "PolkaVM Local"
   - RPC URL: "http://localhost:8545"
   - Chain ID: 31337
   - Currency Symbol: "ETH"

### Web3.js Integration

```javascript
const Web3 = require("web3");
const web3 = new Web3("http://localhost:8545");

// Deploy and interact with contracts normally
// PolkaVM compatibility handled transparently
```

This setup provides a complete PolkaVM-compatible development environment with automatic dependency management, configuration generation, and process lifecycle management.

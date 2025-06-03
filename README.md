# PolkaGuard

A Rust-based CLI tool for analyzing Solidity smart contracts intended for deployment on PolkaVM via the pallet-revive module.

## Overview

PolkaGuard bridges the gap between Solidity's EVM-based environment and PolkaVM's RISC-V architecture, ensuring seamless integration and optimal performance. It provides comprehensive analysis of smart contracts to ensure compatibility and security when deploying to the Polkadot ecosystem.

## Features

- **PolkaVM Compatibility Checks**

  - Detects EVM-specific features incompatible with PolkaVM
  - Validates contract structure against PolkaVM requirements
  - Identifies assembly code usage

- **Security Analysis**

  - Reentrancy vulnerability detection
  - Unchecked send/call detection
  - Integer overflow checks
  - Access control validation

- **Resource Usage Estimation**

  - Gas cost estimation
  - Storage usage calculation
  - Contract size analysis
  - Complexity metrics

- **Best Practices Validation**
  - Compiler version specification
  - Input validation
  - Event emission
  - Access control modifiers

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/polkaguard.git
cd polkaguard

# Build the project
cargo build --release

# Install globally
cargo install --path .
```

## Usage

```bash
# Basic usage
polkaguard --path ./contracts/MyContract.sol

# With specific checks
polkaguard --path ./contracts/MyContract.sol --checks security,compatibility

# Output in JSON format
polkaguard --path ./contracts/MyContract.sol --format json

# Enable verbose output
polkaguard --path ./contracts/MyContract.sol --verbose
```

## Configuration

PolkaGuard can be configured through a configuration file. Create a `polkaguard.json` file:

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
    "version": "0.8.0"
  }
}
```

## Requirements

- Rust 1.70 or higher
- Solidity compiler (solc)
- PolkaVM toolchain

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Polkadot team for the PolkaVM implementation
- Solidity team for the compiler
- All contributors and users of PolkaGuard

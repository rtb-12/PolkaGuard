# Development Guide

This guide covers contributing to PolkaGuard, extending functionality, and understanding the internal architecture.

## 🏗️ Architecture Overview

### Project Structure

```
PolkaGuard/
├── src/
│   ├── main.rs              # Entry point and CLI setup
│   ├── cli/                 # Command-line interface
│   │   ├── mod.rs          # CLI structure and argument parsing
│   │   └── handler.rs      # Command handlers and business logic
│   ├── analyzer/           # Smart contract analysis engine
│   │   └── mod.rs          # Resource estimation and complexity analysis
│   ├── config/             # Configuration management
│   │   └── mod.rs          # Network configs and cost calculations
│   ├── linter/             # Code quality and best practices
│   │   └── mod.rs          # Syntax and style checking
│   ├── models/             # Data structures and types
│   │   └── mod.rs          # Analysis results and report models
│   └── utils/              # Utility functions
│       └── mod.rs          # Helper functions and common code
├── docs/                   # Documentation
├── contracts/              # Sample contracts for testing
└── test_polkaguard.sh     # Comprehensive test suite
```

### Core Components

#### 1. CLI Module (`src/cli/`)

- **Purpose**: Handle command-line arguments and user interaction
- **Key Features**: Network selection, check filtering, output formatting
- **Technologies**: `clap` for argument parsing

#### 2. Analyzer Module (`src/analyzer/`)

- **Purpose**: Core contract analysis and resource estimation
- **Key Features**: Complexity metrics, resource usage calculation
- **Technologies**: Solidity AST parsing, custom algorithms

#### 3. Config Module (`src/config/`)

- **Purpose**: Multi-network configuration and cost calculations
- **Key Features**: Network-specific pricing, plancks conversion
- **Technologies**: `serde` for serialization

#### 4. Linter Module (`src/linter/`)

- **Purpose**: Code quality and security analysis
- **Key Features**: Security vulnerability detection, best practices
- **Technologies**: Pattern matching, AST traversal

## 🛠️ Development Setup

### Prerequisites

```bash
# Install Rust (latest stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install Solidity compiler
npm install -g solc

# Verify installations
rustc --version  # Should be 1.70+
solc --version   # Should be 0.8.x
```

### Local Development

```bash
# Clone and setup
git clone https://github.com/rtb-12/polkaguard.git
cd polkaguard

# Install dependencies and build
cargo build

# Run tests
cargo test

# Run comprehensive test suite
chmod +x test_polkaguard.sh
./test_polkaguard.sh

# Run with debugging
RUST_LOG=debug cargo run -- --path ./contracts/MyContract.sol analyze
```

### Development Workflow

1. **Feature Development**:

   ```bash
   # Create feature branch
   git checkout -b feature/new-analysis-check

   # Make changes and test
   cargo test
   ./test_polkaguard.sh

   # Format and lint
   cargo fmt
   cargo clippy -- -D warnings
   ```

2. **Testing Strategy**:

   ```bash
   # Unit tests
   cargo test

   # Integration tests
   cargo test --test integration

   # End-to-end tests
   ./test_polkaguard.sh
   ```

## 🔧 Extending PolkaGuard

### Adding New Analysis Checks

#### 1. Define Check Type

Add to `src/cli/mod.rs`:

```rust
// ...existing code...
#[derive(Debug, Clone, PartialEq)]
pub enum CheckType {
    Compatibility,
    Security,
    Resources,
    BestPractices,
    NewCheck,  // Add your new check type
}

impl FromStr for CheckType {
    // ...existing code...
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            // ...existing cases...
            "newcheck" => Ok(CheckType::NewCheck),
            _ => Err(format!("Unknown check type: {}", s)),
        }
    }
}
```

#### 2. Implement Analysis Logic

Add to `src/analyzer/mod.rs`:

```rust
// ...existing code...
impl ContractAnalyzer {
    // ...existing methods...

    pub fn analyze_new_check(&self, source_code: &str) -> Vec<AnalysisIssue> {
        let mut issues = Vec::new();

        // Your analysis logic here
        if source_code.contains("dangerous_pattern") {
            issues.push(AnalysisIssue {
                issue_type: "new_check".to_string(),
                severity: Severity::Warning,
                message: "Detected dangerous pattern".to_string(),
                line: None,
                column: None,
            });
        }

        issues
    }
}
```

#### 3. Integrate with Handler

Update `src/cli/handler.rs`:

```rust
// ...existing code...
pub fn handle_analyze(/* parameters */) -> Result<()> {
    // ...existing code...

    // Add new check integration
    if enabled_checks.contains(&CheckType::NewCheck) {
        let new_check_issues = analyzer.analyze_new_check(&source_code);
        analysis_results.extend(new_check_issues);
    }

    // ...existing code...
}
```

### Adding New Networks

#### 1. Define Network Configuration

Add to `src/config/mod.rs`:

```rust
// ...existing code...
impl NetworkConfig {
    // ...existing networks...

    pub fn new_network() -> Self {
        Self {
            name: "NewNetwork".to_string(),
            token_symbol: "NEW".to_string(),
            token_decimals: 12,
            ref_time_price_per_unit: 100,
            proof_size_price_per_byte: 1000,
            storage_deposit_per_byte: 100_000_000,
            token_price_usd: 5.0,
        }
    }
}
```

#### 2. Update CLI Arguments

Modify `src/cli/mod.rs`:

```rust
// ...existing code...
#[derive(Debug, Clone)]
pub enum Network {
    // ...existing networks...
    NewNetwork,
}

impl FromStr for Network {
    // ...existing code...
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            // ...existing cases...
            "newnetwork" => Ok(Network::NewNetwork),
            _ => Err(format!("Unsupported network: {}", s)),
        }
    }
}
```

#### 3. Add Network Support

Update `src/cli/handler.rs`:

```rust
// ...existing code...
fn get_network_config(network: &Network) -> NetworkConfig {
    match network {
        // ...existing cases...
        Network::NewNetwork => NetworkConfig::new_network(),
    }
}
```

### Adding Output Formats

#### 1. Define Format Type

Add to `src/cli/mod.rs`:

```rust
// ...existing code...
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Text,
    Json,
    Xml,  // New format
}
```

#### 2. Implement Formatter

Create `src/formatters/xml.rs`:

```rust
use crate::models::AnalysisResult;
use anyhow::Result;

pub fn format_xml(results: &AnalysisResult) -> Result<String> {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<analysis>\n");

    // Add your XML formatting logic
    xml.push_str(&format!("  <contract_name>{}</contract_name>\n", results.contract_name));
    // ... more formatting

    xml.push_str("</analysis>\n");
    Ok(xml)
}
```

#### 3. Integrate with Handler

Update output handling in `src/cli/handler.rs`:

```rust
// ...existing code...
match output_format {
    OutputFormat::Text => print_text_output(&analysis_results),
    OutputFormat::Json => print_json_output(&analysis_results)?,
    OutputFormat::Xml => {
        let xml_output = format_xml(&analysis_results)?;
        println!("{}", xml_output);
    }
}
```

## 📋 Contributing Guidelines

### Code Style

Follow Rust conventions:

```rust
// Use descriptive names
fn calculate_storage_deposit_cost(bytes: u64, network: &NetworkConfig) -> u64 {
    bytes * network.storage_deposit_per_byte
}

// Document public APIs
/// Calculates the total cost breakdown for contract execution
///
/// # Arguments
/// * `ref_time` - Computational time units
/// * `proof_size` - State proof size in bytes
/// * `storage` - Storage usage in bytes
/// * `network` - Network configuration for pricing
///
/// # Returns
/// Complete cost breakdown with token amounts and USD estimation
pub fn calculate_cost_breakdown(
    ref_time: u64,
    proof_size: u64,
    storage: u64,
    network: &NetworkConfig,
) -> CostBreakdown {
    // Implementation
}
```

### Pull Request Process

1. **Fork and Branch**:

   ```bash
   git checkout -b feature/descriptive-name
   ```

2. **Make Changes**:

   - Follow existing code patterns
   - Add tests for new functionality
   - Update documentation

3. **Test Thoroughly**:

   ```bash
   cargo test
   ./test_polkaguard.sh
   cargo clippy
   ```

4. **Submit PR**:
   - Clear description of changes
   - Reference related issues
   - Include test results

### Issue Reporting

When reporting bugs:

1. **Environment Details**:

   - PolkaGuard version: `polkaguard --version`
   - Rust version: `rustc --version`
   - OS and architecture

2. **Reproduction Steps**:

   - Exact command used
   - Input contract content
   - Expected vs actual behavior

3. **Logs**:
   ```bash
   RUST_LOG=debug polkaguard --path contract.sol analyze 2>&1 | tee debug.log
   ```

## 🔮 Future Development

### Roadmap Items

1. **Enhanced Analysis**:

   - Gas optimization suggestions
   - Cross-contract dependency analysis
   - Formal verification integration

2. **Ecosystem Integration**:

   - IDE plugins (VS Code, IntelliJ)
   - CI/CD integrations (GitHub Actions)
   - Package manager support

3. **Advanced Features**:
   - Real-time cost monitoring
   - Historical cost analysis
   - Contract upgrade impact analysis

### Architecture Evolution

The codebase is designed for extensibility:

- **Plugin System**: Future support for external analysis modules
- **API Layer**: RESTful API for web integration
- **Database Layer**: Historical analysis data storage
- **Caching Layer**: Performance optimization for large codebases

### Contributing Areas

Great places to contribute:

- **New Analysis Checks**: Security patterns, gas optimizations
- **Network Support**: Additional Polkadot parachains
- **Output Formats**: XML, YAML, custom formats
- **Performance**: Optimization and caching
- **Documentation**: Examples, tutorials, guides

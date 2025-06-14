use clap::{Parser, Subcommand};

mod handler;
pub use handler::handle_command;

/// Generate long about text with features and capabilities
fn get_long_about() -> &'static str {
    r#"
🌟 PolkaGuard - The Ultimate Smart Contract Security Guardian 🌟

🔍 FEATURES:
  • 🚀 PolkaVM Compatibility Analysis
  • 🔐 Zero-Knowledge Proof Generation
  • 🎯 Exploit Pattern Detection
  • 💰 Gas & Memory Optimization
  • 📊 Comprehensive Security Reports
  • ⚡ Multi-Network Support

🎨 SUPPORTED NETWORKS:
  • 🔴 Polkadot    • 🟡 Kusama     • 🔵 Westend
  • 🟠 Rococo      • 🟢 Local Development

💎 Advanced cryptographic proofs ensure your contract analysis
   results are tamper-proof and verifiable on-chain.
    "#
}

/// Custom help template with enhanced formatting
fn get_help_template() -> &'static str {
    r#"{about-section}

{before-help}🔧 USAGE:
    {usage}

{all-args}

💡 EXAMPLES:
    # Analyze a contract
    polkaguard -p contract.sol analyze

    # Generate ZK proof
    polkaguard -p contract.sol prove --output-dir ./proofs

    # Generate exploit report proof
    polkaguard -p contract.sol exploit-report -r report.md -c 0x123... -e "reentrancy"

🌐 For more information, visit: https://github.com/rtb-12/PolkaGuard
{after-help}"#
}

#[derive(Parser, Debug)]
#[command(
    author, 
    version, 
    about = get_ascii_banner(),
    long_about = get_long_about(),
    help_template = get_help_template()
)]
pub struct Cli {
    /// 📁 Path to the Solidity contract file or directory to analyze
    #[arg(short, long)]
    pub path: String,

    /// 🔊 Enable verbose output with detailed analysis information
    #[arg(short, long)]
    pub verbose: bool,

    /// 📄 Output format (json, text) - choose your preferred result format
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// 🎯 Run specific analysis checks (comma-separated list) - target specific vulnerabilities
    #[arg(short, long, value_delimiter = ',')]
    pub checks: Option<Vec<String>>,

    /// 📚 Stack size for PolkaVM (in bytes) - optimize for your contract's needs
    #[arg(long)]
    pub stack_size: Option<u32>,

    /// 💾 Heap size for PolkaVM (in bytes) - control memory allocation
    #[arg(long)]
    pub heap_size: Option<u32>,

    /// ⚡ Optimization level (0-3, s, z) - balance between speed and size
    #[arg(short, long)]
    pub optimization: Option<String>,

    /// 🔨 Path to solc executable - use custom Solidity compiler
    #[arg(long)]
    pub solc: Option<String>,

    /// 🐛 Generate debug information for detailed analysis
    #[arg(short, long)]
    pub debug: bool,

    /// ⚠️  Overwrite existing files without prompting - use with caution
    #[arg(long)]
    pub overwrite: bool,

    /// 🌐 Target network for cost calculations and compatibility
    #[arg(
        short,
        long,
        default_value = "polkadot",
        help = "🌐 Target network: polkadot🔴, kusama🟡, westend🔵, rococo🟠, local🟢"
    )]
    pub network: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// 🚀 Initialize a new PolkaGuard configuration with optimal settings
    Init {
        /// Path to save the configuration file
        #[arg(short, long, default_value = "polkaguard.json")]
        config_path: String,
    },
    /// 🔍 Analyze a Solidity contract for PolkaVM compatibility and security issues
    Analyze,
    /// 🔐 Generate tamper-proof zero-knowledge proof of analysis results
    Prove {
        /// Output directory for proof artifacts
        #[arg(short, long, default_value = "./zk_proofs")]
        output_dir: String,
        /// Generate Solidity verifier contract for on-chain verification
        #[arg(long)]
        generate_verifier: bool,
        /// Circuit type to use (groth16, plonk)
        #[arg(long, default_value = "groth16")]
        circuit_type: String,
        /// Security level in bits (128, 192, 256)
        #[arg(long, default_value = "128")]
        security_level: u32,
    },
    /// ✅ Verify a zero-knowledge proof and validate its authenticity
    Verify {
        /// Path to the proof file
        #[arg(short, long)]
        proof_path: String,
        /// Path to verification key (optional, can be embedded in proof)
        #[arg(long)]
        verification_key: Option<String>,
    },
    /// 📋 List all available security analysis checks and their descriptions
    ListChecks,
    /// ℹ️  Show detailed information about a specific security check
    CheckInfo {
        /// Name of the security check to get detailed information about
        check_name: String,
    },
    /// 🔧 Disassemble a PolkaVM contract bytecode for low-level analysis
    Disassemble,
    /// 📊 Analyze contract memory usage patterns and optimization opportunities
    MemoryAnalysis,
    /// 🚨 Generate ZK proof of exploit knowledge from markdown security report
    ExploitReport {
        /// 📋 Path to the markdown exploit report containing vulnerability details
        #[arg(short, long)]
        report_path: String,
        /// 🏠 Contract address the exploit targets - specify the vulnerable contract
        #[arg(short, long)]
        contract_address: String,
        /// 🔍 Exploit signature/pattern to prove knowledge of - your security fingerprint
        #[arg(short, long)]
        exploit_signature: String,
        /// 💾 Output directory for proof artifacts and verification files
        #[arg(short, long, default_value = "./exploit_proofs")]
        output_dir: String,
        /// ⛓️  Generate Solidity verifier contract for on-chain verification
        #[arg(long)]
        generate_verifier: bool,
        /// 📦 Chunk size for Merkle tree leaves (in bytes) - optimize for report size
        #[arg(long, default_value = "32")]
        chunk_size: usize,
        /// 🌳 Merkle tree height (log2 of max leaves) - balance between proof size and capacity
        #[arg(long, default_value = "20")]
        tree_height: u32,
    },
}

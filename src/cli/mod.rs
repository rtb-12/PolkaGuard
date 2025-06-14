use clap::{Parser, Subcommand};

mod handler;
pub use handler::handle_command;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to the Solidity contract file or directory
    #[arg(short, long)]
    pub path: String,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Output format (json, text)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Run specific analysis checks (comma-separated list)
    #[arg(short, long, value_delimiter = ',')]
    pub checks: Option<Vec<String>>,

    /// Stack size for PolkaVM (in bytes)
    #[arg(long)]
    pub stack_size: Option<u32>,

    /// Heap size for PolkaVM (in bytes)
    #[arg(long)]
    pub heap_size: Option<u32>,

    /// Optimization level (0-3, s, z)
    #[arg(short, long)]
    pub optimization: Option<String>,

    /// Path to solc executable
    #[arg(long)]
    pub solc: Option<String>,

    /// Generate debug information
    #[arg(short, long)]
    pub debug: bool,

    /// Overwrite existing files without prompting
    #[arg(long)]
    pub overwrite: bool,

    /// Target network for cost calculations (polkadot, kusama, westend, rococo, local)
    #[arg(
        short,
        long,
        default_value = "polkadot",
        help = "Target network for cost calculations. Available: polkadot, kusama, westend, rococo, local"
    )]
    pub network: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Initialize a new PolkaGuard configuration
    Init {
        /// Path to save the configuration file
        #[arg(short, long, default_value = "polkaguard.json")]
        config_path: String,
    },
    /// Analyze a Solidity contract for PolkaVM compatibility
    Analyze,
    /// Generate zero-knowledge proof of analysis results
    Prove {
        /// Output directory for proof artifacts
        #[arg(short, long, default_value = "./zk_proofs")]
        output_dir: String,
        /// Generate Solidity verifier contract
        #[arg(long)]
        generate_verifier: bool,
        /// Circuit type to use (groth16, plonk)
        #[arg(long, default_value = "groth16")]
        circuit_type: String,
        /// Security level in bits (128, 192, 256)
        #[arg(long, default_value = "128")]
        security_level: u32,
    },
    /// Verify a zero-knowledge proof
    Verify {
        /// Path to the proof file
        #[arg(short, long)]
        proof_path: String,
        /// Path to verification key (optional, can be embedded in proof)
        #[arg(long)]
        verification_key: Option<String>,
    },
    /// List all available analysis checks
    ListChecks,
    /// Show detailed information about a specific check
    CheckInfo {
        /// Name of the check to get information about
        check_name: String,
    },
    /// Disassemble a PolkaVM contract
    Disassemble,
    /// Analyze contract memory usage
    MemoryAnalysis,
    /// Generate ZK proof of exploit knowledge from markdown report
    ExploitReport {
        /// Path to the markdown exploit report
        #[arg(short, long)]
        report_path: String,
        /// Contract address the exploit targets
        #[arg(short, long)]
        contract_address: String,
        /// Exploit signature/pattern to prove knowledge of
        #[arg(short, long)]
        exploit_signature: String,
        /// Output directory for proof artifacts
        #[arg(short, long, default_value = "./exploit_proofs")]
        output_dir: String,
        /// Generate Solidity verifier contract
        #[arg(long)]
        generate_verifier: bool,
        /// Chunk size for Merkle tree leaves (in bytes)
        #[arg(long, default_value = "32")]
        chunk_size: usize,
        /// Merkle tree height (log2 of max leaves)
        #[arg(long, default_value = "20")]
        tree_height: u32,
    },
}

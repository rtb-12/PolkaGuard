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
} 
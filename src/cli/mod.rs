use clap::{Parser, Subcommand};
use anyhow::Result;

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

    /// Run specific analysis checks
    #[arg(short, long)]
    pub checks: Option<Vec<String>>,

    /// Stack size for PolkaVM (in bytes)
    #[arg(long, default_value = "32768")]
    pub stack_size: u32,

    /// Heap size for PolkaVM (in bytes)
    #[arg(long, default_value = "65536")]
    pub heap_size: u32,

    /// Optimization level (0-3, s, z)
    #[arg(short, long, default_value = "3")]
    pub optimization: String,

    /// Path to solc executable
    #[arg(long)]
    pub solc: Option<String>,

    /// Generate debug information
    #[arg(short)]
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
    /// List all available analysis checks
    ListChecks,
    /// Show detailed information about a specific check
    CheckInfo {
        /// Name of the check to get information about
        check_name: String,
    },
    /// Disassemble a PolkaVM contract
    Disassemble {
        /// Path to the PolkaVM contract file
        #[arg(short, long)]
        contract_path: String,
    },
    /// Analyze contract memory usage
    MemoryAnalysis {
        /// Path to the contract file
        #[arg(short, long)]
        contract_path: String,
    },
} 
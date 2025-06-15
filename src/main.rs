mod analyzer;
mod cli;
mod config;
mod deployment;
mod fork;
mod linter;
mod models;
mod utils;
mod zk;

use crate::cli::Cli;
use anyhow::Result;
use clap::Parser;
use std::env;

/// Display creative version information
fn display_version_info() {
    let version = env!("CARGO_PKG_VERSION");
    println!("\n🌟 ═══════════════════════════════════════════════════════════════ 🌟");
    println!("🛡️                       POLKAGUARD v{}                       🛡️", version);
    println!("⚡                 Smart Contract Security Guardian               ⚡");
    println!("🔐               Zero-Knowledge Proof Powered Suite             🔐");
    println!("🌟 ═══════════════════════════════════════════════════════════════ 🌟");
    println!("📅 Built for the future of Web3 security");
    println!("🚀 Powered by advanced cryptographic proofs");
    println!("🌐 Multi-network compatible (Polkadot ecosystem)");
    println!("💎 Ensuring tamper-proof contract analysis");
    println!("");
    println!("🔗 GitHub: https://github.com/rtb-12/PolkaGuard");
    println!("📚 Documentation: https://github.com/rtb-12/PolkaGuard/tree/main/docs");
    println!("");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    // Check if version flag is used and display custom version
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        display_version_info();
        return Ok(());
    }
    
    // Set up signal handlers for graceful cleanup
    setup_signal_handlers().await?;
    
    let cli = Cli::parse();
    crate::cli::handle_command(&cli).await?;
    Ok(())
}

/// Setup signal handlers for graceful cleanup of fork processes
async fn setup_signal_handlers() -> Result<()> {
    use signal_hook::consts::SIGINT;
    use signal_hook_tokio::Signals;
    use futures_util::stream::StreamExt;
    
    let mut signals = Signals::new(&[SIGINT])?;
    
    tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            match signal {
                SIGINT => {
                    println!("\n🛑 Received interrupt signal, cleaning up...");
                    // The cleanup will be handled by the ForkManager's Drop trait
                    std::process::exit(0);
                }
                _ => unreachable!(),
            }
        }
    });
    
    Ok(())
}
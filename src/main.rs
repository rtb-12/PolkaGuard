mod analyzer;
mod cli;
mod utils;
mod models;
mod config;

use anyhow::Result;
use clap::Parser;
use crate::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::handle_command(&cli.command).await?;
    Ok(())
} 
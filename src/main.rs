mod analyzer;
mod cli;
mod config;
mod linter;
mod models;
mod utils;
mod zk;

use crate::cli::Cli;
use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::handle_command(&cli).await?;
    Ok(())
}
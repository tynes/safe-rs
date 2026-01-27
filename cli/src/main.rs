// CLI-specific lint overrides
#![allow(clippy::print_stdout, reason = "CLI tools print to stdout")]
#![allow(clippy::print_stderr, reason = "CLI tools print to stderr")]
#![allow(clippy::unwrap_used, reason = "CLI can unwrap for user-facing errors")]
#![allow(clippy::expect_used, reason = "CLI can expect for user-facing errors")]

mod bundle;
mod cli;
mod commands;
mod output;
mod sig_parser;
mod wallet;

use clap::Parser;
use cli::{Cli, Commands};
use color_eyre::eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Send(args) => commands::send::run(args, cli.json).await,
        Commands::Call(args) => commands::call::run(args, cli.json).await,
        Commands::Info(args) => commands::info::run(args, cli.json).await,
        Commands::Create(args) => commands::create::run(args, cli.json).await,
    }
}

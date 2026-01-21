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

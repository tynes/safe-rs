use clap::Parser;
use color_eyre::eyre::Result;
use safe_rs_cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();
    safe_rs_cli::run(cli.command, cli.json).await
}

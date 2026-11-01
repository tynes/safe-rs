use clap::{CommandFactory, FromArgMatches};
use color_eyre::eyre::Result;
use safe_rs_cli::config_file::ConfigFile;
use safe_rs_cli::{Cli, RunConfig};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // `$SAFE_RS_HOME/config.toml` fills in flags that neither the command line
    // nor the environment gave.
    let command = ConfigFile::load()?.apply(Cli::command());
    let cli = Cli::from_arg_matches(&command.get_matches()).unwrap_or_else(|e| e.exit());
    safe_rs_cli::run(cli.command, RunConfig::terminal(cli.json)).await
}

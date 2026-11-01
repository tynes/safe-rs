//! `$SAFE_RS_HOME/config.toml`: defaults every CLI built on this crate reads,
//! so `safe` and the CLIs that embed it share one configuration.
//!
//! Each setting is the default of a flag, used only when neither the flag nor
//! its environment variable is given:
//!
//! ```toml
//! rpc_url = "https://polygon.drpc.org"   # --rpc-url, ETH_RPC_URL
//! safe = "0x…"                           # --safe, SAFE_ADDRESS
//! hd_wallet = "treasury"                 # --hd-wallet, SAFE_HD_WALLET
//! password_file = "~/.safe-rs/password"  # --password-file, SAFE_PASSWORD_FILE
//! keystore = "~/.foundry/keystores/me"   # --keystore
//! hd_key = "treasury:3"                  # --hd-key
//! ```
//!
//! `keystore` and `hd_key` pick the signer only when no other signer flag
//! (`--private-key` / `PRIVATE_KEY`, `--keystore`, `--hd-key`,
//! `--interactive`) is given. Private keys and passwords never go here.

use std::path::{Path, PathBuf};

use alloy::primitives::Address;
use clap::builder::ArgPredicate;
use clap::parser::ValueSource;
use clap::{ArgMatches, Command};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::cli::SignerArgs;
use crate::paths;

/// The file name under the data directory.
pub const FILE_NAME: &str = "config.toml";

/// The settings in `config.toml`. Unknown keys are refused, so a typo does
/// not go unnoticed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ConfigFile {
    pub rpc_url: Option<Url>,
    pub safe: Option<Address>,
    pub hd_wallet: Option<String>,
    pub password_file: Option<PathBuf>,
    pub keystore: Option<PathBuf>,
    pub hd_key: Option<String>,
}

/// Why `config.toml` could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// No data directory: no home directory and no `SAFE_RS_HOME`
    #[error("{0}")]
    Home(String),
    #[error("cannot read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// The flag ids a setting is the default of, with the signer flags that
/// override it (for the signer settings only).
const SIGNER_FLAGS: [&str; 5] = ["private_key", "keystore", "hd_key", "ledger", "interactive"];

impl ConfigFile {
    /// `config.toml` in the data directory (`$SAFE_RS_HOME`, or
    /// `~/.safe-rs`); empty settings if there is no such file.
    pub fn load() -> Result<Self, ConfigError> {
        let home = paths::home().map_err(|e| ConfigError::Home(e.to_string()))?;
        Self::load_from(&home)
    }

    /// `config.toml` in `home`; empty settings if there is no such file.
    pub fn load_from(home: &Path) -> Result<Self, ConfigError> {
        let path = Self::path(home);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(ConfigError::Read { path, source }),
        };
        toml::from_str(&text).map_err(|source| ConfigError::Parse { path, source })
    }

    /// Where the file lives under `home`.
    pub fn path(home: &Path) -> PathBuf {
        home.join(FILE_NAME)
    }

    /// `command` (and all its subcommands) with these settings as the
    /// defaults of the matching flags. Apply it before parsing:
    ///
    /// ```no_run
    /// use clap::{CommandFactory, FromArgMatches};
    /// use safe_rs_cli::config_file::ConfigFile;
    /// use safe_rs_cli::Cli;
    ///
    /// let command = ConfigFile::load().unwrap().apply(Cli::command());
    /// let cli = Cli::from_arg_matches(&command.get_matches()).unwrap();
    /// ```
    #[must_use]
    pub fn apply(&self, command: Command) -> Command {
        let defaults = self.defaults();
        if defaults.is_empty() {
            return command;
        }
        apply_defaults(command, &defaults)
    }

    /// (flag id, default, whether another signer flag overrides it)
    fn defaults(&self) -> Vec<(&'static str, String, bool)> {
        let path = |p: &PathBuf| p.to_string_lossy().into_owned();
        let mut defaults = Vec::new();
        if let Some(url) = &self.rpc_url {
            defaults.push(("rpc_url", url.to_string(), false));
        }
        if let Some(safe) = &self.safe {
            defaults.push(("safe", safe.to_string(), false));
        }
        if let Some(wallet) = &self.hd_wallet {
            defaults.push(("hd_wallet", wallet.clone(), false));
        }
        if let Some(file) = &self.password_file {
            defaults.push(("password_file", path(file), false));
        }
        if let Some(keystore) = &self.keystore {
            defaults.push(("keystore", path(keystore), true));
        }
        if let Some(key) = &self.hd_key {
            defaults.push(("hd_key", key.clone(), true));
        }
        defaults
    }
}

/// Drops a configured `--keystore` or `--hd-key` from `signer` when another
/// signer flag was given on the command line or in the environment.
/// [`ConfigFile::apply`] arranges this for the flags it finds, but clap does
/// not apply it to flags a host made global, so such a host calls this on
/// the matches it parsed `signer` from.
pub fn settle_signer(signer: &mut SignerArgs, matches: &ArgMatches) {
    let given = |id: &str| {
        matches.ids().any(|i| i == id)
            && matches!(
                matches.value_source(id),
                Some(ValueSource::CommandLine | ValueSource::EnvVariable)
            )
    };
    let configured = |id: &str| matches!(matches.value_source(id), Some(ValueSource::DefaultValue));
    let other_given = |id: &str| SIGNER_FLAGS.iter().any(|flag| *flag != id && given(flag));
    if signer.keystore.is_some() && configured("keystore") && other_given("keystore") {
        signer.keystore = None;
    }
    if signer.hd_key.is_some() && configured("hd_key") && other_given("hd_key") {
        signer.hd_key = None;
    }
}

fn apply_defaults(command: Command, defaults: &[(&'static str, String, bool)]) -> Command {
    let subcommands: Vec<String> = command
        .get_subcommands()
        .map(|sc| sc.get_name().to_string())
        .collect();
    let mut command = command;
    for (id, value, is_signer) in defaults {
        let Some(arg) = command.get_arguments().find(|a| a.get_id() == *id) else {
            continue;
        };
        // Only flags the `safe` CLI reads from the environment (or the signer
        // flags) take a default: `safe info <SAFE>` keeps its own fallback.
        if arg.get_long().is_none() || arg.is_positional() {
            continue;
        }
        if *id == "safe" && arg.get_env().is_none() {
            continue;
        }
        let value = value.clone();
        let is_signer = *is_signer;
        let others: Vec<&'static str> = SIGNER_FLAGS
            .iter()
            .copied()
            .filter(|flag| flag != id)
            .filter(|flag| command.get_arguments().any(|a| a.get_id() == *flag))
            .collect();
        command = command.mut_arg(*id, move |arg| {
            let arg = arg.required(false).default_value(value);
            if !is_signer {
                return arg;
            }
            arg.default_value_ifs(others.into_iter().map(|flag| {
                let when = if flag == "interactive" {
                    ArgPredicate::Equals("true".into())
                } else {
                    ArgPredicate::IsPresent
                };
                (flag, when, None)
            }))
        });
    }
    for name in subcommands {
        command = command.mut_subcommand(name, |sc| apply_defaults(sc, defaults));
    }
    command
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, FromArgMatches};

    use super::*;
    use crate::{Cli, Commands};

    fn parse(config: &ConfigFile, args: &[&str]) -> Result<Cli, clap::Error> {
        let mut command = config.apply(Cli::command());
        let matches = command.try_get_matches_from_mut([&["safe"], args].concat())?;
        Cli::from_arg_matches(&matches)
    }

    fn info(cli: Cli) -> crate::cli::InfoArgs {
        match cli.command {
            Commands::Info(args) => args,
            _ => panic!("expected info"),
        }
    }

    #[test]
    fn a_missing_file_is_empty_settings_and_unknown_keys_are_refused() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            ConfigFile::load_from(home.path()).unwrap(),
            ConfigFile::default()
        );
        std::fs::write(ConfigFile::path(home.path()), "rpc_uri = \"http://x\"\n").unwrap();
        assert!(matches!(
            ConfigFile::load_from(home.path()),
            Err(ConfigError::Parse { .. })
        ));
        std::fs::write(
            ConfigFile::path(home.path()),
            "rpc_url = \"http://rpc.test\"\nkeystore = \"/keys/me.json\"\n",
        )
        .unwrap();
        let config = ConfigFile::load_from(home.path()).unwrap();
        assert_eq!(config.rpc_url.unwrap().as_str(), "http://rpc.test/");
        assert_eq!(config.keystore.unwrap(), PathBuf::from("/keys/me.json"));
    }

    #[test]
    fn settings_fill_in_flags_that_were_not_given() {
        let config = ConfigFile {
            rpc_url: Some("http://rpc.test".parse().unwrap()),
            keystore: Some("/keys/me.json".into()),
            ..ConfigFile::default()
        };
        let args = info(
            parse(
                &config,
                &["info", "0x1111111111111111111111111111111111111111"],
            )
            .unwrap(),
        );
        assert_eq!(args.rpc.rpc_url.as_str(), "http://rpc.test/");
        assert_eq!(args.signer.keystore.as_deref(), Some("/keys/me.json"));

        // A flag wins over the setting.
        let args = info(
            parse(
                &config,
                &[
                    "info",
                    "0x1111111111111111111111111111111111111111",
                    "--rpc-url",
                    "http://flag.test",
                ],
            )
            .unwrap(),
        );
        assert_eq!(args.rpc.rpc_url.as_str(), "http://flag.test/");
    }

    #[test]
    fn another_signer_flag_overrides_the_configured_signer() {
        let config = ConfigFile {
            rpc_url: Some("http://rpc.test".parse().unwrap()),
            keystore: Some("/keys/me.json".into()),
            ..ConfigFile::default()
        };
        let args = info(parse(&config, &["info", "--private-key", "0x01"]).unwrap());
        assert_eq!(args.signer.keystore, None);
        assert_eq!(args.signer.private_key.as_deref(), Some("0x01"));

        let args = info(parse(&config, &["info", "--interactive"]).unwrap());
        assert_eq!(args.signer.keystore, None);
    }

    #[test]
    fn the_positional_safe_of_info_keeps_its_fallback() {
        let config = ConfigFile {
            rpc_url: Some("http://rpc.test".parse().unwrap()),
            safe: Some(Address::repeat_byte(0x11)),
            ..ConfigFile::default()
        };
        let args = info(parse(&config, &["info"]).unwrap());
        assert_eq!(args.safe, None);
    }

    /// A host that makes the signer flags global, as `polymarket` does.
    #[derive(clap::Parser)]
    #[command(mut_arg("private_key", |a| a.global(true)), mut_arg("keystore", |a| a.global(true)))]
    struct Host {
        #[command(flatten)]
        signer: SignerArgs,
        #[command(subcommand)]
        command: HostCommand,
    }

    #[derive(clap::Subcommand)]
    enum HostCommand {
        Show,
    }

    #[test]
    fn settle_signer_drops_the_configured_signer_of_a_host_with_global_flags() {
        let config = ConfigFile {
            keystore: Some("/keys/me.json".into()),
            ..ConfigFile::default()
        };
        for args in [
            &["host", "--private-key", "0x01", "show"][..],
            &["host", "show", "--private-key", "0x01"][..],
        ] {
            let mut command = config.apply(Host::command());
            let matches = command.try_get_matches_from_mut(args).unwrap();
            let mut host = Host::from_arg_matches(&matches).unwrap();
            settle_signer(&mut host.signer, &matches);
            assert_eq!(host.signer.keystore, None, "{args:?}");
            assert_eq!(host.signer.private_key.as_deref(), Some("0x01"));
        }
        let mut command = config.apply(Host::command());
        let matches = command.try_get_matches_from_mut(["host", "show"]).unwrap();
        let mut host = Host::from_arg_matches(&matches).unwrap();
        settle_signer(&mut host.signer, &matches);
        assert_eq!(host.signer.keystore.as_deref(), Some("/keys/me.json"));
    }

    #[test]
    fn the_whole_tree_stays_valid() {
        let config = ConfigFile {
            rpc_url: Some("http://rpc.test".parse().unwrap()),
            safe: Some(Address::repeat_byte(0x11)),
            hd_wallet: Some("treasury".into()),
            password_file: Some("/p".into()),
            keystore: Some("/k".into()),
            hd_key: Some("treasury:2".into()),
        };
        config.apply(Cli::command()).debug_assert();
    }
}

//! `$SAFE_RS_HOME/config.toml`: defaults every CLI built on this crate reads,
//! so `safe` and the CLIs that embed it share one configuration.
//!
//! Each setting is the default of a flag, used only when neither the flag nor
//! its environment variable is given:
//!
//! ```toml
//! rpc_url = "https://polygon.drpc.org"   # --rpc-url, ETH_RPC_URL
//! safe = "0x…"                           # --safe, SAFE_ADDRESS
//! password_file = "~/.safe-rs/password"  # --password-file, ETH_PASSWORD
//! keystore = "~/.foundry/keystores/me"   # --keystore, ETH_KEYSTORE
//! account = "me"                         # --account, ETH_KEYSTORE_ACCOUNT
//! mnemonic = "treasury"                  # --mnemonic
//! ```
//!
//! `keystore`, `account` and `mnemonic` pick the signer (or, under
//! `--rotate`, the HD wallet) only when no other wallet option (such as
//! `--private-key` / `PRIVATE_KEY` or `--ledger`) is given. Private keys,
//! phrases and passwords never go here.

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
    pub password_file: Option<PathBuf>,
    pub keystore: Option<PathBuf>,
    pub account: Option<String>,
    /// An HD wallet name or path. A phrase never goes here.
    pub mnemonic: Option<String>,
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

/// The ids of the wallet options: any one given overrides a configured
/// signer.
const SIGNER_FLAGS: [&str; 10] = [
    "private_key",
    "keystore_path",
    "keystore_account_name",
    "mnemonic",
    "interactive",
    "ledger",
    "trezor",
    "aws",
    "gcp",
    "turnkey",
];

/// The wallet options that are switches, given when `true`.
const SWITCHES: [&str; 6] = ["interactive", "ledger", "trezor", "aws", "gcp", "turnkey"];

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
        if let Some(file) = &self.password_file {
            defaults.push(("keystore_password_file", path(file), false));
        }
        if let Some(keystore) = &self.keystore {
            defaults.push(("keystore_path", path(keystore), true));
        }
        if let Some(account) = &self.account {
            defaults.push(("keystore_account_name", account.clone(), true));
        }
        if let Some(wallet) = &self.mnemonic {
            defaults.push(("mnemonic", wallet.clone(), true));
        }
        defaults
    }
}

/// Drops a configured `--keystore`, `--account` or `--mnemonic` from
/// `signer` when another wallet option was given on the command line or in the environment.
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
            && (!SWITCHES.contains(&id) || matches.get_flag(id))
    };
    let configured = |id: &str| matches!(matches.value_source(id), Some(ValueSource::DefaultValue));
    let other_given = |id: &str| SIGNER_FLAGS.iter().any(|flag| *flag != id && given(flag));
    if configured("keystore_path") && other_given("keystore_path") {
        signer.keystore_path = None;
    }
    if configured("keystore_account_name") && other_given("keystore_account_name") {
        signer.keystore_account_name = None;
    }
    if configured("mnemonic") && other_given("mnemonic") {
        signer.mnemonic = None;
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
                let when = if SWITCHES.contains(&flag) {
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
        assert_eq!(args.signer.keystore_path.as_deref(), Some("/keys/me.json"));

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
        assert_eq!(args.signer.keystore_path, None);
        assert_eq!(args.signer.private_key.as_deref(), Some("0x01"));

        let args = info(parse(&config, &["info", "--interactive"]).unwrap());
        assert_eq!(args.signer.keystore_path, None);

        let args = info(parse(&config, &["info", "--ledger"]).unwrap());
        assert_eq!(args.signer.keystore_path, None);
        assert!(args.signer.ledger);

        let args = info(parse(&config, &["info", "--account", "me"]).unwrap());
        assert_eq!(args.signer.keystore_path, None);
        assert_eq!(args.signer.keystore_account_name.as_deref(), Some("me"));
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
    #[command(
        mut_arg("private_key", |a| a.global(true)),
        mut_arg("keystore_path", |a| a.global(true)),
        mut_arg("ledger", |a| a.global(true))
    )]
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
            &["host", "show", "--ledger", "--private-key", "0x01"][..],
        ] {
            let mut command = config.apply(Host::command());
            let matches = command.try_get_matches_from_mut(args).unwrap();
            let mut host = Host::from_arg_matches(&matches).unwrap();
            settle_signer(&mut host.signer, &matches);
            assert_eq!(host.signer.keystore_path, None, "{args:?}");
            assert_eq!(host.signer.private_key.as_deref(), Some("0x01"));
        }
        let mut command = config.apply(Host::command());
        let matches = command.try_get_matches_from_mut(["host", "show"]).unwrap();
        let mut host = Host::from_arg_matches(&matches).unwrap();
        settle_signer(&mut host.signer, &matches);
        assert_eq!(host.signer.keystore_path.as_deref(), Some("/keys/me.json"));
    }

    #[test]
    fn the_whole_tree_stays_valid() {
        let config = ConfigFile {
            rpc_url: Some("http://rpc.test".parse().unwrap()),
            safe: Some(Address::repeat_byte(0x11)),
            password_file: Some("/p".into()),
            keystore: Some("/k".into()),
            account: Some("me".into()),
            mnemonic: Some("treasury".into()),
        };
        config.apply(Cli::command()).debug_assert();
    }
}

//! The wallet options are `cast`'s, one to one: the same ids, flags, short
//! flags, aliases, value names, defaults and environment variables as
//! `foundry_wallets::WalletOpts`, which `cast send` flattens. The gas payer
//! takes the same set with a `--gas-payer-` prefix.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use clap::{Arg, Args, Command};
use foundry_wallets::WalletOpts;
use safe_rs_cli::args::{GasPayerArgs, SignerArgs};

/// What a user sees of a flag.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    long: Option<String>,
    short: Option<char>,
    aliases: Vec<String>,
    value_name: Option<Vec<String>>,
    default: Vec<String>,
    env: Option<String>,
    takes_value: bool,
}

fn shape(arg: &Arg) -> Shape {
    let mut aliases: Vec<String> = arg
        .get_all_aliases()
        .unwrap_or_default()
        .into_iter()
        .map(str::to_string)
        .collect();
    aliases.sort();
    Shape {
        long: arg.get_long().map(str::to_string),
        short: arg.get_short(),
        aliases,
        value_name: arg
            .get_value_names()
            .map(|names| names.iter().map(ToString::to_string).collect()),
        default: arg
            .get_default_values()
            .iter()
            .map(|v| v.to_string_lossy().into_owned())
            .collect(),
        env: arg.get_env().map(|e| e.to_string_lossy().into_owned()),
        takes_value: arg.get_action().takes_values(),
    }
}

fn args<T: Args>() -> Vec<Arg> {
    T::augment_args(Command::new("t"))
        .get_arguments()
        .cloned()
        .collect()
}

/// The `cast` wallet options this CLI takes: all but Tempo's.
fn cast_args() -> Vec<Arg> {
    args::<WalletOpts>()
        .into_iter()
        .filter(|arg| !arg.get_id().as_str().starts_with("tempo"))
        .filter(|arg| !arg.get_long().is_some_and(|l| l.starts_with("tempo")))
        .collect()
}

#[test]
fn the_signer_flags_are_casts() {
    let ours = args::<SignerArgs>();
    let cast = cast_args();
    assert_eq!(
        cast.len(),
        16,
        "{:?}",
        cast.iter().map(Arg::get_id).collect::<Vec<_>>()
    );
    for theirs in &cast {
        let id = theirs.get_id().as_str();
        let mine = ours
            .iter()
            .find(|a| a.get_id().as_str() == id)
            .unwrap_or_else(|| panic!("cast's {id} is missing"));
        let mut expected = shape(theirs);
        // The one addition: PRIVATE_KEY, which `safe` has always read.
        if id == "private_key" {
            assert_eq!(expected.env, None);
            expected.env = Some("PRIVATE_KEY".to_string());
        }
        assert_eq!(shape(mine), expected, "{id}");
    }
    for mine in &ours {
        let id = mine.get_id().as_str();
        assert!(
            cast.iter().any(|a| a.get_id().as_str() == id),
            "{id} is not a cast option"
        );
    }
}

#[test]
fn the_gas_payer_flags_are_casts_prefixed() {
    let ours = args::<GasPayerArgs>();
    let cast = cast_args();
    assert_eq!(ours.len(), cast.len());
    for theirs in &cast {
        let id = format!("gas_payer_{}", theirs.get_id().as_str());
        let mine = ours
            .iter()
            .find(|a| a.get_id().as_str() == id)
            .unwrap_or_else(|| panic!("{id} is missing"));
        let expected = shape(theirs);
        let got = shape(mine);
        let prefixed = |s: &str| format!("gas-payer-{s}");
        assert_eq!(got.long, expected.long.as_deref().map(prefixed), "{id}");
        assert_eq!(got.short, None, "{id}: short flags belong to the signer");
        let aliases: Vec<String> = expected.aliases.iter().map(|a| prefixed(a)).collect();
        assert_eq!(got.aliases, aliases, "{id}");
        assert_eq!(got.default, expected.default, "{id}");
        assert_eq!(got.takes_value, expected.takes_value, "{id}");
        let env = match theirs.get_id().as_str() {
            "private_key" => Some("PRIVATE_KEY".to_string()),
            _ => expected.env,
        };
        assert_eq!(got.env, env.map(|e| format!("GAS_PAYER_{e}")), "{id}");
    }
}

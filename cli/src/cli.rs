use std::fmt;
use std::path::PathBuf;

use alloy::eips::BlockId;
use alloy::primitives::{Address, U256};
use clap::{Args, Parser, Subcommand, ValueEnum};
use safe_rs::{ChainAddresses, SpecId};
use url::Url;

#[derive(Parser)]
#[command(name = "safe")]
#[command(about = "Cast-like CLI for Safe transactions", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Execute transaction(s) through a Safe
    Send(Box<SendArgs>),

    /// Simulate a call from the Safe without executing (dry-run)
    Call(CallArgs),

    /// Display Safe configuration (owners, threshold, nonce, modules, guard, ...)
    Info(InfoArgs),

    /// Deploy a new Safe deterministically (same address across chains)
    Create(CreateArgs),
}

#[derive(Args, Clone)]
pub struct RpcArgs {
    /// RPC endpoint URL
    #[arg(long, env = "ETH_RPC_URL")]
    pub rpc_url: Url,
}

#[derive(Args, Clone)]
pub struct SafeArgs {
    /// Safe contract address
    #[arg(long, env = "SAFE_ADDRESS")]
    pub safe: Address,
}

/// Local fork simulation settings.
#[derive(Args, Clone)]
pub struct SimArgs {
    /// Block to fork from: a number, hash or tag (default: latest). Execution is
    /// simulated in the block after it.
    #[arg(long, value_parser = parse_block_id)]
    pub block: Option<BlockId>,

    /// EVM specification used for simulation
    #[arg(long, value_enum, default_value_t = EvmSpec::Osaka)]
    pub spec: EvmSpec,

    /// Seconds between blocks, used for the simulated block's timestamp
    #[arg(long, default_value_t = 12)]
    pub block_time: u64,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum EvmSpec {
    Cancun,
    Prague,
    Osaka,
}

/// Safe versions `safe create` can deploy, newest first.
#[derive(ValueEnum, Clone, Copy, Debug, Default)]
pub enum SafeVersion {
    #[default]
    #[value(name = "1.5.0")]
    V1_5_0,
    #[value(name = "1.4.1")]
    V1_4_1,
}

impl From<EvmSpec> for SpecId {
    fn from(spec: EvmSpec) -> Self {
        match spec {
            EvmSpec::Cancun => SpecId::CANCUN,
            EvmSpec::Prague => SpecId::PRAGUE,
            EvmSpec::Osaka => SpecId::OSAKA,
        }
    }
}

impl From<SafeVersion> for ChainAddresses {
    fn from(version: SafeVersion) -> Self {
        match version {
            SafeVersion::V1_5_0 => ChainAddresses::v1_5_0(),
            SafeVersion::V1_4_1 => ChainAddresses::v1_4_1(),
        }
    }
}

impl fmt::Display for SafeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SafeVersion::V1_5_0 => "1.5.0",
            SafeVersion::V1_4_1 => "1.4.1",
        })
    }
}

/// Parses a decimal block number, or anything `BlockId` accepts (tag, hex
/// number, block hash).
pub fn parse_block_id(s: &str) -> Result<BlockId, String> {
    if let Ok(number) = s.parse::<u64>() {
        return Ok(BlockId::number(number));
    }
    s.parse::<BlockId>().map_err(|e| e.to_string())
}

#[derive(Parser, Clone)]
pub struct SendArgs {
    /// Target address (for single call mode)
    #[arg(value_name = "TO")]
    pub to: Option<Address>,

    /// Function signature (e.g., "transfer(address,uint256)")
    #[arg(value_name = "SIG")]
    pub sig: Option<String>,

    /// Function arguments
    #[arg(value_name = "ARGS")]
    pub args: Vec<String>,

    #[command(flatten)]
    pub safe: SafeArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// ETH value to send (in wei)
    #[arg(long, default_value = "0")]
    pub value: U256,

    /// Call specification for multicall mode (format: "0xAddr:sig(types):arg1,arg2")
    #[arg(long = "call", value_name = "CALL")]
    pub calls: Vec<String>,

    /// Path to Safe TX Bundler JSON file
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Use MultiSendCallOnly (safer, no delegatecall)
    #[arg(long)]
    pub call_only: bool,

    /// Only simulate, don't sign or broadcast the outer transaction
    #[arg(long)]
    pub simulate_only: bool,

    /// Skip simulation and execute directly (use with caution)
    #[arg(long)]
    pub skip_simulation: bool,

    /// Explicit safeTxGas. The default, 0, makes a failing inner call revert the
    /// whole transaction instead of consuming the Safe nonce
    #[arg(long)]
    pub safe_tx_gas: Option<U256>,

    /// Safe nonce to sign for; fails if the on-chain nonce differs
    #[arg(long)]
    pub nonce: Option<U256>,

    /// Gas limit of the outer transaction (default: simulated gas + 20%)
    #[arg(long)]
    pub gas_limit: Option<u64>,

    /// maxFeePerGas of the outer transaction in wei (default: node estimate)
    #[arg(long)]
    pub max_fee_per_gas: Option<u128>,

    /// maxPriorityFeePerGas of the outer transaction in wei (default: node estimate)
    #[arg(long)]
    pub max_priority_fee_per_gas: Option<u128>,

    /// Write the signed transaction as JSON to PATH ("-" for stdout) before it
    /// is broadcast
    #[arg(long, value_name = "PATH", conflicts_with = "simulate_only")]
    pub raw_out: Option<String>,

    /// Sign the transaction but do not broadcast it (writes it to --raw-out,
    /// stdout by default)
    #[arg(long, conflicts_with_all = ["simulate_only"])]
    pub no_submit: bool,

    /// Seconds to wait for the receipt after broadcasting
    #[arg(long, default_value_t = 120)]
    pub timeout: u64,

    /// Print call traces of the simulated transaction
    #[arg(long)]
    pub trace: bool,

    #[command(flatten)]
    pub sim: SimArgs,

    /// MultiSend address (default: canonical v1.4.1)
    #[arg(long)]
    pub multi_send: Option<Address>,

    /// MultiSendCallOnly address (default: canonical v1.4.1)
    #[arg(long)]
    pub multi_send_call_only: Option<Address>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub no_confirm: bool,

    #[command(flatten)]
    pub wallet: WalletArgs,

    #[command(flatten)]
    pub payer: PayerArgs,
}

#[derive(Parser, Clone)]
pub struct CallArgs {
    /// Target address
    #[arg(value_name = "TO")]
    pub to: Address,

    /// Function signature (e.g., "balanceOf(address)")
    #[arg(value_name = "SIG")]
    pub sig: String,

    /// Function arguments
    #[arg(value_name = "ARGS")]
    pub args: Vec<String>,

    #[command(flatten)]
    pub safe: SafeArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// ETH value to send (in wei)
    #[arg(long, default_value = "0")]
    pub value: U256,

    /// Print call traces
    #[arg(long)]
    pub trace: bool,

    #[command(flatten)]
    pub sim: SimArgs,
}

#[derive(Parser, Clone)]
pub struct InfoArgs {
    /// Safe contract address (default: the Safe that `safe create` deploys for
    /// the signer when run without options; the newest Safe version that has
    /// one)
    #[arg(value_name = "SAFE")]
    pub safe: Option<Address>,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// Block to read at: a number, hash or tag (default: latest)
    #[arg(long, value_parser = parse_block_id)]
    pub block: Option<BlockId>,

    #[command(flatten)]
    pub wallet: WalletArgs,
}

#[derive(Parser, Clone)]
pub struct CreateArgs {
    #[command(flatten)]
    pub rpc: RpcArgs,

    /// Salt nonce for CREATE2 (default: 0)
    #[arg(long, default_value = "0")]
    pub salt_nonce: U256,

    /// Additional owner address (repeatable, signer is always included)
    #[arg(long = "owner", value_name = "ADDR")]
    pub owners: Vec<Address>,

    /// Signature threshold (default: 1)
    #[arg(long, default_value = "1")]
    pub threshold: u64,

    /// Only compute and display the address, don't deploy
    #[arg(long)]
    pub compute_only: bool,

    /// Custom fallback handler address
    #[arg(long)]
    pub fallback_handler: Option<Address>,

    /// Safe singleton address (default: based on --safe-version)
    #[arg(long)]
    pub singleton: Option<Address>,

    /// Safe proxy factory address (default: based on --safe-version)
    #[arg(long)]
    pub factory: Option<Address>,

    /// Safe version to use
    #[arg(long, value_enum, default_value_t)]
    pub safe_version: SafeVersion,

    /// Skip confirmation prompt
    #[arg(long)]
    pub no_confirm: bool,

    #[command(flatten)]
    pub wallet: WalletArgs,
}

#[derive(Parser, Clone)]
pub struct WalletArgs {
    /// Raw private key
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,

    /// Path to keystore file
    #[arg(long)]
    pub keystore: Option<String>,

    /// Keystore password
    #[arg(long)]
    pub password: Option<String>,

    /// Prompt for private key interactively
    #[arg(short, long)]
    pub interactive: bool,
}

impl WalletArgs {
    /// Whether any wallet option was given.
    pub fn is_set(&self) -> bool {
        self.interactive || self.keystore.is_some() || self.private_key.is_some()
    }
}

/// The account that sends the outer transaction and pays for gas.
#[derive(Args, Clone)]
pub struct PayerArgs {
    /// Private key that sends the outer transaction and pays for gas, instead
    /// of the owner key
    #[arg(long, env = "SAFE_PAYER_PRIVATE_KEY")]
    pub payer_private_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_ids_parse_from_numbers_tags_and_hashes() {
        assert_eq!(parse_block_id("123").unwrap(), BlockId::number(123));
        assert_eq!(parse_block_id("latest").unwrap(), BlockId::latest());
        let hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
        assert!(matches!(parse_block_id(hash).unwrap(), BlockId::Hash(_)));
        assert!(parse_block_id("nope").is_err());
    }

    const SAFE: &str = "0x1111111111111111111111111111111111111111";

    fn parse_info(args: &[&str]) -> Result<InfoArgs, clap::Error> {
        let args = [
            &["safe", "info", "--rpc-url", "http://localhost:8545"],
            args,
        ]
        .concat();
        match Cli::try_parse_from(args)?.command {
            Commands::Info(info) => Ok(info),
            _ => unreachable!(),
        }
    }

    #[test]
    fn info_takes_the_safe_as_an_optional_positional() {
        let info = parse_info(&[SAFE]).unwrap();
        assert_eq!(info.safe, Some(SAFE.parse().unwrap()));

        let info = parse_info(&["--private-key", "0x01"]).unwrap();
        assert_eq!(info.safe, None);
        assert!(info.wallet.is_set());

        assert!(parse_info(&["--safe", SAFE]).is_err());
    }

    #[test]
    fn safe_versions_display_as_their_cli_values_default_first() {
        let versions = SafeVersion::value_variants();
        assert_eq!(versions[0].to_string(), SafeVersion::default().to_string());
        for version in versions {
            let name = version.to_possible_value().unwrap();
            assert_eq!(version.to_string(), name.get_name());
        }
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}

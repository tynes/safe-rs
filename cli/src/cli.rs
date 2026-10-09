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

    /// Swap the Safe's owner for the HD wallet's next unused key, with no other
    /// calls. Also moves an existing Safe onto the wallet (--from-*) and retires
    /// a key after a failed transaction
    Rotate(Box<RotateArgs>),

    /// Manage HD wallets: the encrypted phrase that one-time owner keys come from
    #[command(subcommand)]
    Wallet(WalletCommand),
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

    /// Use the Safe's owner key once: append a swap of the owner for the next
    /// unused key of --hd-wallet, then move the old key's ETH to the new one
    #[arg(long, conflicts_with_all = ["skip_simulation", "safe_tx_gas", "multi_send", "nonce"])]
    pub rotate: bool,

    #[command(flatten)]
    pub hd: HdArgs,

    #[command(flatten)]
    pub sweep: SweepArgs,

    #[command(flatten)]
    pub wallet: WalletArgs,

    #[command(flatten)]
    pub password: PasswordArgs,

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

    #[command(flatten)]
    pub password: PasswordArgs,
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

    /// Deploy the same Safe an HD wallet created on another chain, given as
    /// <CHAIN_ID>:<SAFE>. Reuses its first owner key and salt, so that key
    /// must be rotated right away
    #[arg(long, value_name = "CHAIN_ID:SAFE", requires = "hd_wallet", conflicts_with_all = ["owners", "salt_nonce"])]
    pub same_as: Option<String>,

    #[command(flatten)]
    pub hd: HdArgs,

    #[command(flatten)]
    pub sweep: SweepArgs,

    #[command(flatten)]
    pub wallet: WalletArgs,

    #[command(flatten)]
    pub password: PasswordArgs,

    #[command(flatten)]
    pub payer: PayerArgs,
}

#[derive(Parser, Clone)]
pub struct RotateArgs {
    #[command(flatten)]
    pub safe: SafeArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    #[command(flatten)]
    pub hd: HdArgs,

    #[command(flatten)]
    pub password: PasswordArgs,

    /// Private key of the Safe's current owner, to move the Safe onto the HD wallet
    #[arg(long, value_name = "KEY", conflicts_with_all = ["from_keystore", "from_interactive"])]
    pub from_private_key: Option<String>,

    /// Keystore of the Safe's current owner (its password is prompted for)
    #[arg(long, value_name = "PATH", conflicts_with = "from_interactive")]
    pub from_keystore: Option<PathBuf>,

    /// Prompt for the private key of the Safe's current owner
    #[arg(long)]
    pub from_interactive: bool,

    #[command(flatten)]
    pub sweep: SweepArgs,

    /// Move the whole ETH balance of the --from-* key to the new owner without
    /// asking. Needed with --no-confirm or --json, where no prompt shows the amount
    #[arg(long, conflicts_with = "no_sweep")]
    pub sweep_legacy: bool,

    #[command(flatten)]
    pub payer: PayerArgs,

    /// Only simulate, don't sign off or broadcast the transaction
    #[arg(long)]
    pub simulate_only: bool,

    /// Gas limit of the outer transaction (default: simulated gas + 20%)
    #[arg(long)]
    pub gas_limit: Option<u64>,

    /// maxFeePerGas of the outer transaction in wei (default: node estimate)
    #[arg(long)]
    pub max_fee_per_gas: Option<u128>,

    /// maxPriorityFeePerGas of the outer transaction in wei (default: node estimate)
    #[arg(long)]
    pub max_priority_fee_per_gas: Option<u128>,

    /// Seconds to wait for the receipt after broadcasting
    #[arg(long, default_value_t = 120)]
    pub timeout: u64,

    /// Print call traces of the simulated transaction
    #[arg(long)]
    pub trace: bool,

    #[command(flatten)]
    pub sim: SimArgs,

    /// MultiSendCallOnly address (default: canonical v1.4.1)
    #[arg(long)]
    pub multi_send_call_only: Option<Address>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub no_confirm: bool,
}

#[derive(Subcommand, Clone)]
pub enum WalletCommand {
    /// Create an HD wallet from a new 24-word phrase and encrypt it to disk
    New(WalletNewArgs),

    /// Encrypt an existing BIP-39 phrase to disk as an HD wallet
    Import(WalletImportArgs),

    /// List the HD wallets on disk
    List,

    /// Print the wallet's funding address, or the address of one owner key
    Address(WalletAddressArgs),

    /// Show which keys own which Safe, and where to send gas money
    Status(WalletStatusArgs),

    /// Rebuild the record of used keys for a Safe from the chain
    Sync(WalletSyncArgs),

    /// Move the ETH left on a Safe's retired owner keys to its current owner
    Sweep(WalletSweepArgs),
}

#[derive(Args, Clone)]
pub struct WalletNewArgs {
    /// Wallet name (stored as <name>.json under ~/.safe-rs/wallets)
    pub name: String,

    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Clone)]
pub struct WalletImportArgs {
    /// Wallet name (stored as <name>.json under ~/.safe-rs/wallets)
    pub name: String,

    /// File holding the phrase (default: prompt, without echo)
    #[arg(long, value_name = "PATH")]
    pub phrase_file: Option<PathBuf>,

    /// First index to use for owner keys, for a phrase whose lower indices
    /// were already used by another wallet
    #[arg(long, value_name = "INDEX")]
    pub start_index: Option<u32>,

    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Clone)]
pub struct WalletAddressArgs {
    #[command(flatten)]
    pub hd: HdArgs,

    /// Owner key index (default: the funding address, which needs no password)
    #[arg(long)]
    pub index: Option<u32>,

    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Clone)]
pub struct WalletStatusArgs {
    #[command(flatten)]
    pub hd: HdArgs,

    /// Only show this Safe
    #[arg(long)]
    pub safe: Option<Address>,
}

#[derive(Args, Clone)]
pub struct WalletSyncArgs {
    #[command(flatten)]
    pub hd: HdArgs,

    #[command(flatten)]
    pub safe: SafeArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// How many wallet indices to derive and compare
    #[arg(long, default_value_t = 1000)]
    pub scan_limit: u32,

    /// Also read the Safe's owner events from this block on, to restore its
    /// history and find keys that never paid for gas. Use the Safe's
    /// deployment block or earlier
    #[arg(long, value_name = "BLOCK")]
    pub from_block: Option<u64>,

    /// Blocks per eth_getLogs request
    #[arg(long, default_value_t = 10_000, requires = "from_block")]
    pub chunk: u64,

    /// MultiSendCallOnly address (default: canonical v1.4.1)
    #[arg(long)]
    pub multi_send_call_only: Option<Address>,

    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Args, Clone)]
pub struct WalletSweepArgs {
    #[command(flatten)]
    pub hd: HdArgs,

    #[command(flatten)]
    pub safe: SafeArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// Wei to leave on the retired owner (default: what the chain charges outside gas)
    #[arg(long, value_name = "WEI")]
    pub sweep_reserve: Option<U256>,

    /// Seconds to wait for the receipt after broadcasting
    #[arg(long, default_value_t = 120)]
    pub timeout: u64,

    #[command(flatten)]
    pub password: PasswordArgs,
}

#[derive(Parser, Clone)]
pub struct WalletArgs {
    /// Raw private key
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,

    /// Path to a keystore file (Web3 Secret Storage v3, as written by `cast wallet import`)
    #[arg(long)]
    pub keystore: Option<String>,

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

/// How the password of a keystore or HD wallet is supplied (default: a prompt).
#[derive(Args, Clone, Default)]
pub struct PasswordArgs {
    /// File holding the keystore or HD wallet password
    #[arg(long, env = "SAFE_PASSWORD_FILE", value_name = "PATH")]
    pub password_file: Option<PathBuf>,

    /// Keystore or HD wallet password. Visible in the process list and shell
    /// history: prefer --password-file or the prompt
    #[arg(long)]
    pub password: Option<String>,
}

/// The HD wallet one-time owner keys are derived from.
#[derive(Args, Clone, Default)]
pub struct HdArgs {
    /// HD wallet: a name under ~/.safe-rs/wallets, or the path of a mnemonic keystore
    #[arg(long, env = "SAFE_HD_WALLET", value_name = "NAME|PATH")]
    pub hd_wallet: Option<String>,
}

/// What happens to a retired owner key's ETH.
#[derive(Args, Clone, Default)]
pub struct SweepArgs {
    /// Leave the retired owner key's ETH where it is, instead of moving it to
    /// the next owner
    #[arg(long)]
    pub no_sweep: bool,

    /// Wei to leave on the retired owner key when sweeping (default: what the
    /// chain charges outside gas, which is nothing on most chains)
    #[arg(long, value_name = "WEI", conflicts_with = "no_sweep")]
    pub sweep_reserve: Option<U256>,
}

/// The account that sends the outer transaction and pays for gas.
#[derive(Args, Clone)]
pub struct PayerArgs {
    /// Private key that sends the outer transaction and pays for gas, instead
    /// of the owner key (with --hd-wallet on create: instead of the funding key)
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

    const TO: &str = "0x0000000000000000000000000000000000000042";

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        let mut all = vec!["safe"];
        all.extend_from_slice(args);
        Cli::try_parse_from(all)
    }

    fn send(extra: &[&str]) -> Result<Cli, clap::Error> {
        let mut args = vec![
            "send",
            TO,
            "--safe",
            SAFE,
            "--rpc-url",
            "http://localhost:8545",
        ];
        args.extend_from_slice(extra);
        parse(&args)
    }

    #[test]
    fn rotate_excludes_the_options_that_would_weaken_it() {
        assert!(send(&["--rotate", "--hd-wallet", "w"]).is_ok());
        // The batch target stays configurable; it must be the call-only one.
        assert!(send(&["--rotate", "--multi-send-call-only", TO]).is_ok());
        for conflicting in [
            &["--skip-simulation"][..],
            &["--safe-tx-gas", "100000"],
            &["--multi-send", TO],
            &["--nonce", "3"],
        ] {
            let mut args = vec!["--rotate"];
            args.extend_from_slice(conflicting);
            assert!(send(&args).is_err(), "{conflicting:?} must conflict");
        }
        assert!(send(&["--rotate", "--no-sweep"]).is_ok());
        assert!(send(&["--rotate", "--sweep-reserve", "1000"]).is_ok());
        assert!(
            send(&["--rotate", "--no-sweep", "--sweep-reserve", "1"]).is_err(),
            "a reserve without a sweep is a contradiction"
        );
    }

    fn rotate(extra: &[&str]) -> Result<Cli, clap::Error> {
        let mut args = vec![
            "rotate",
            "--safe",
            SAFE,
            "--rpc-url",
            "http://localhost:8545",
            "--hd-wallet",
            "w",
        ];
        args.extend_from_slice(extra);
        parse(&args)
    }

    #[test]
    fn rotate_takes_one_legacy_key_source_and_one_sweep_choice() {
        assert!(rotate(&[]).is_ok());
        assert!(rotate(&["--from-private-key", "0x01"]).is_ok());
        assert!(rotate(&["--from-interactive", "--sweep-legacy"]).is_ok());
        assert!(rotate(&["--from-private-key", "0x01", "--from-interactive"]).is_err());
        assert!(rotate(&["--from-private-key", "0x01", "--from-keystore", "k.json"]).is_err());
        assert!(rotate(&["--from-keystore", "k.json", "--from-interactive"]).is_err());
        assert!(rotate(&["--sweep-legacy", "--no-sweep"]).is_err());
    }

    #[test]
    fn wallet_and_create_options_parse() {
        assert!(parse(&["wallet", "new", "treasury"]).is_ok());
        assert!(parse(&["wallet", "import", "treasury", "--start-index", "5"]).is_ok());
        assert!(parse(&["wallet", "list"]).is_ok());
        assert!(parse(&["wallet", "status", "--hd-wallet", "w"]).is_ok());
        let sync = [
            "wallet",
            "sync",
            "--hd-wallet",
            "w",
            "--safe",
            SAFE,
            "--rpc-url",
            "http://localhost:8545",
        ];
        assert!(parse(&sync).is_ok());
        let mut chunk_only = sync.to_vec();
        chunk_only.extend(["--chunk", "500"]);
        assert!(parse(&chunk_only).is_err(), "--chunk needs --from-block");
        chunk_only.extend(["--from-block", "0"]);
        assert!(parse(&chunk_only).is_ok());

        let create = ["create", "--rpc-url", "http://localhost:8545"];
        let with = |extra: &[&str]| {
            let mut args = create.to_vec();
            args.extend_from_slice(extra);
            parse(&args)
        };
        let same_as = format!("10:{SAFE}");
        assert!(with(&["--hd-wallet", "w", "--same-as", &same_as]).is_ok());
        assert!(
            with(&["--same-as", &same_as]).is_err(),
            "--same-as needs --hd-wallet"
        );
        assert!(
            with(&[
                "--hd-wallet",
                "w",
                "--same-as",
                &same_as,
                "--salt-nonce",
                "7"
            ])
            .is_err(),
            "the salt comes from the original Safe"
        );
    }
}

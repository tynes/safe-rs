use std::fmt;
use std::path::PathBuf;

use alloy::eips::BlockId;
use alloy::primitives::{Address, U256};
use alloy_dyn_abi::DynSolType;
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

    /// Change the Safe's owners, threshold, modules, guards or fallback
    /// handler, all in one Safe transaction
    Config(Box<ConfigArgs>),

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
    /// Safe contract address (default: the signer's default Safe, the one
    /// `safe create` deploys for it without options; with an HD wallet, its
    /// sole recorded Safe on this chain)
    #[arg(long, env = "SAFE_ADDRESS")]
    pub safe: Option<Address>,
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

/// Parses an amount of wei as cast does: a decimal or 0x-hex number of wei, or
/// a number with a unit ("1ether", "0.1 ether", "10gwei", "1e18").
pub fn parse_ether_value(s: &str) -> Result<U256, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        return U256::from_str_radix(hex, 16).map_err(|e| e.to_string());
    }
    DynSolType::Uint(256)
        .coerce_str(s)
        .map_err(|e| e.to_string())?
        .as_uint()
        .map(|(value, _)| value)
        .ok_or_else(|| format!("invalid amount {s}"))
}

/// [`parse_ether_value`] for fee flags, which must fit in a u128.
pub fn parse_fee_value(s: &str) -> Result<u128, String> {
    u128::try_from(parse_ether_value(s)?).map_err(|_| format!("fee {s} does not fit in 128 bits"))
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

    /// ETH value to send: wei, or a number with a unit ("1ether", "10gwei")
    #[arg(long, default_value = "0", value_parser = parse_ether_value)]
    pub value: U256,

    /// Call specification for multicall mode (format: "0xAddr:sig(types):arg1,arg2")
    #[arg(long = "call", value_name = "CALL")]
    pub calls: Vec<String>,

    /// Path to bundle JSON file (reads calls and existing signatures; writes updated bundle when collecting offchain signatures)
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Merge offchain signatures from additional bundle file(s) into this run
    #[arg(long = "merge-bundle", value_name = "PATH")]
    pub merge_bundle: Vec<PathBuf>,

    /// Publish an on-chain approveHash(safeTxHash) transaction from the signer instead of executing or only saving offchain
    #[arg(long, conflicts_with_all = ["sign_only", "simulate_only"])]
    pub approve_hash: bool,

    /// Only sign and save the signature to --bundle (do not execute on-chain even if threshold is met)
    #[arg(long, conflicts_with_all = ["approve_hash", "simulate_only"])]
    pub sign_only: bool,
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

    /// maxFeePerGas of the outer transaction: wei, or a number with a unit
    /// ("30gwei") (default: node estimate)
    #[arg(long, value_parser = parse_fee_value)]
    pub max_fee_per_gas: Option<u128>,

    /// maxPriorityFeePerGas of the outer transaction: wei, or a number with a
    /// unit ("1gwei") (default: node estimate)
    #[arg(long, value_parser = parse_fee_value)]
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

    /// MultiSend address (default: canonical for the Safe's version)
    #[arg(long)]
    pub multi_send: Option<Address>,

    /// MultiSendCallOnly address (default: canonical for the Safe's version)
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

/// Parses an owner swap, `OLD:NEW`.
pub fn parse_owner_swap(s: &str) -> Result<(Address, Address), String> {
    let (old, new) = s
        .split_once(':')
        .ok_or_else(|| format!("expected OLD:NEW, got {s}"))?;
    let parse = |a: &str| {
        a.trim()
            .parse::<Address>()
            .map_err(|e| format!("invalid address {a}: {e}"))
    };
    Ok((parse(old)?, parse(new)?))
}

#[derive(Parser, Clone)]
pub struct ConfigArgs {
    #[command(flatten)]
    pub safe: SafeArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// Add an owner (repeatable). New owners go to the head of the owner list
    #[arg(long = "add-owner", value_name = "ADDR")]
    pub add_owners: Vec<Address>,

    /// Remove an owner (repeatable)
    #[arg(long = "remove-owner", value_name = "ADDR")]
    pub remove_owners: Vec<Address>,

    /// Replace owner OLD with NEW in its place in the owner list (repeatable)
    #[arg(long = "swap-owner", value_name = "OLD:NEW", value_parser = parse_owner_swap)]
    pub swap_owners: Vec<(Address, Address)>,

    /// Signature threshold after the change (default: unchanged; never lowered
    /// unless given)
    #[arg(long)]
    pub threshold: Option<U256>,

    /// Enable a module (repeatable)
    #[arg(long = "enable-module", value_name = "ADDR")]
    pub enable_modules: Vec<Address>,

    /// Disable a module (repeatable)
    #[arg(long = "disable-module", value_name = "ADDR")]
    pub disable_modules: Vec<Address>,

    /// Set the transaction guard; 0x0000000000000000000000000000000000000000
    /// removes it
    #[arg(long, value_name = "ADDR")]
    pub guard: Option<Address>,

    /// Set the fallback handler; the zero address removes it
    #[arg(long, value_name = "ADDR")]
    pub fallback_handler: Option<Address>,

    /// Set the module guard (Safe v1.5.0); the zero address removes it
    #[arg(long, value_name = "ADDR")]
    pub module_guard: Option<Address>,

    /// Path to bundle JSON file. Saves the planned transaction and signatures
    /// when the threshold is not met; co-signers pass it without change flags
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Merge offchain signatures from additional bundle file(s) into this run
    #[arg(long = "merge-bundle", value_name = "PATH")]
    pub merge_bundle: Vec<PathBuf>,

    /// Publish an on-chain approveHash(safeTxHash) transaction from the signer instead of executing or only saving offchain
    #[arg(long, conflicts_with_all = ["sign_only", "simulate_only"])]
    pub approve_hash: bool,

    /// Only sign and save the signature to --bundle (do not execute on-chain even if threshold is met)
    #[arg(long, conflicts_with_all = ["approve_hash", "simulate_only"])]
    pub sign_only: bool,

    /// Only simulate, don't sign or broadcast the outer transaction
    #[arg(long)]
    pub simulate_only: bool,

    /// Skip simulation, and with it the check of the resulting configuration
    /// (use with caution)
    #[arg(long)]
    pub skip_simulation: bool,

    /// Safe nonce to sign for; fails if the on-chain nonce differs
    #[arg(long)]
    pub nonce: Option<U256>,

    /// Gas limit of the outer transaction (default: simulated gas + 20%)
    #[arg(long)]
    pub gas_limit: Option<u64>,

    /// maxFeePerGas of the outer transaction: wei, or a number with a unit
    /// ("30gwei") (default: node estimate)
    #[arg(long, value_parser = parse_fee_value)]
    pub max_fee_per_gas: Option<u128>,

    /// maxPriorityFeePerGas of the outer transaction: wei, or a number with a
    /// unit ("1gwei") (default: node estimate)
    #[arg(long, value_parser = parse_fee_value)]
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

    /// MultiSendCallOnly address, used when there are several changes
    /// (default: canonical for the Safe's version)
    #[arg(long)]
    pub multi_send_call_only: Option<Address>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub no_confirm: bool,

    #[command(flatten)]
    pub hd: HdArgs,

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

    /// ETH value to send: wei, or a number with a unit ("1ether", "10gwei")
    #[arg(long, default_value = "0", value_parser = parse_ether_value)]
    pub value: U256,

    /// Print call traces
    #[arg(long)]
    pub trace: bool,

    #[command(flatten)]
    pub sim: SimArgs,

    #[command(flatten)]
    pub wallet: WalletArgs,

    #[command(flatten)]
    pub password: PasswordArgs,
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
    #[arg(long, value_name = "CHAIN_ID:SAFE", conflicts_with_all = ["owners", "salt_nonce", "safe_version", "singleton", "factory", "fallback_handler"])]
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
    /// Safe contract address (default: the wallet's sole recorded Safe on this
    /// chain, or the legacy signer's default Safe with --from-*)
    #[arg(value_name = "SAFE")]
    pub safe: Option<Address>,

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

    /// maxFeePerGas of the outer transaction: wei, or a number with a unit
    /// ("30gwei") (default: node estimate)
    #[arg(long, value_parser = parse_fee_value)]
    pub max_fee_per_gas: Option<u128>,

    /// maxPriorityFeePerGas of the outer transaction: wei, or a number with a
    /// unit ("1gwei") (default: node estimate)
    #[arg(long, value_parser = parse_fee_value)]
    pub max_priority_fee_per_gas: Option<u128>,

    /// Seconds to wait for the receipt after broadcasting
    #[arg(long, default_value_t = 120)]
    pub timeout: u64,

    /// Print call traces of the simulated transaction
    #[arg(long)]
    pub trace: bool,

    #[command(flatten)]
    pub sim: SimArgs,

    /// MultiSendCallOnly address (default: canonical for the Safe's version)
    #[arg(long)]
    pub multi_send_call_only: Option<Address>,

    /// Path to bundle JSON file (reads existing signatures/rotations; writes updated bundle when collecting offchain signatures)
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Merge offchain signatures from additional bundle file(s) into this run
    #[arg(long = "merge-bundle", value_name = "PATH")]
    pub merge_bundle: Vec<PathBuf>,

    /// Publish an on-chain approveHash(safeTxHash) transaction from the signer instead of executing or only saving offchain
    #[arg(long, conflicts_with_all = ["sign_only", "simulate_only"])]
    pub approve_hash: bool,

    /// Only sign and save the signature to --bundle (do not execute on-chain even if threshold is met)
    #[arg(long, conflicts_with_all = ["approve_hash", "simulate_only"])]
    pub sign_only: bool,

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

    /// How many wallet indices to derive and compare (default: 1000 for an HD
    /// wallet file, 52 for a Ledger, which answers one address at a time)
    #[arg(long)]
    pub scan_limit: Option<u32>,

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

    /// Wei to leave on the retired owner, or a number with a unit ("0.01ether")
    /// (default: what the chain charges outside gas)
    #[arg(long, value_name = "WEI", value_parser = parse_ether_value)]
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

    /// Take the owner keys from a connected Ledger (Ethereum app open) instead
    /// of an HD wallet file. Overrides SAFE_HD_WALLET
    #[arg(long)]
    pub ledger: bool,
}

impl HdArgs {
    /// Whether an HD wallet or a Ledger was chosen.
    pub fn is_set(&self) -> bool {
        self.ledger || self.hd_wallet.is_some()
    }
}

/// What happens to a retired owner key's ETH.
#[derive(Args, Clone, Default)]
pub struct SweepArgs {
    /// Leave the retired owner key's ETH where it is, instead of moving it to
    /// the next owner
    #[arg(long)]
    pub no_sweep: bool,

    /// Wei to leave on the retired owner key when sweeping, or a number with a
    /// unit ("0.01ether") (default: what the chain charges outside gas, which is
    /// nothing on most chains)
    #[arg(long, value_name = "WEI", conflicts_with = "no_sweep", value_parser = parse_ether_value)]
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

    #[test]
    fn ether_values_parse_like_cast() {
        let ether = U256::from(10).pow(U256::from(18));
        let ok = |s: &str| parse_ether_value(s).unwrap();
        assert_eq!(ok("1000000000000000000"), ether);
        assert_eq!(ok("1ether"), ether);
        assert_eq!(ok("1 ether"), ether);
        assert_eq!(ok("0.1ether"), ether / U256::from(10));
        assert_eq!(ok("10gwei"), U256::from(10_000_000_000_u64));
        assert_eq!(ok("1e18"), ether);
        assert_eq!(ok("0x10"), U256::from(16));
        assert_eq!(ok("0"), U256::ZERO);
        for bad in ["1.5", "-1", "1 parsec", "0xzz", ""] {
            assert!(parse_ether_value(bad).is_err(), "{bad} must not parse");
        }
        assert_eq!(parse_fee_value("30gwei").unwrap(), 30_000_000_000);
        assert!(parse_fee_value("1e40").is_err());
    }

    #[test]
    fn value_flags_take_units() {
        let Commands::Send(args) = send(&["--value", "1.5ether", "--max-fee-per-gas", "2gwei"])
            .unwrap()
            .command
        else {
            unreachable!()
        };
        assert_eq!(args.value, U256::from(1_500_000_000_000_000_000_u128));
        assert_eq!(args.max_fee_per_gas, Some(2_000_000_000));
        assert!(send(&["--rotate", "--sweep-reserve", "0.01ether"]).is_ok());
    }

    #[test]
    fn send_and_call_take_the_safe_as_optional() {
        let rpc = ["--rpc-url", "http://localhost:8545"];
        let mut args = vec!["send", TO, "--private-key", "0x01"];
        args.extend(rpc);
        let Commands::Send(send) = parse(&args).unwrap().command else {
            unreachable!()
        };
        assert_eq!(send.safe.safe, None);
        let mut args = vec!["call", TO, "owner()", "--private-key", "0x01"];
        args.extend(rpc);
        let Commands::Call(call) = parse(&args).unwrap().command else {
            unreachable!()
        };
        assert_eq!(call.safe.safe, None);
        assert!(call.wallet.is_set());
    }

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
    fn config_parses_changes() {
        let cli = parse(&[
            "config",
            "--safe",
            SAFE,
            "--rpc-url",
            "http://localhost:8545",
            "--add-owner",
            TO,
            "--add-owner",
            SAFE,
            "--swap-owner",
            &format!("{TO}:{SAFE}"),
            "--threshold",
            "2",
            "--guard",
            "0x0000000000000000000000000000000000000000",
        ])
        .unwrap();
        let Commands::Config(args) = cli.command else {
            panic!("expected config");
        };
        let to: Address = TO.parse().unwrap();
        let safe: Address = SAFE.parse().unwrap();
        assert_eq!(args.add_owners, [to, safe]);
        assert_eq!(args.swap_owners, [(to, safe)]);
        assert_eq!(args.threshold, Some(U256::from(2)));
        assert_eq!(args.guard, Some(Address::ZERO));
        assert_eq!(args.fallback_handler, None);
    }

    #[test]
    fn owner_swaps_need_two_addresses() {
        assert!(parse_owner_swap(TO).is_err());
        assert!(parse_owner_swap(&format!("{TO}:nope")).is_err());
        assert!(parse_owner_swap(&format!("{TO}:{TO}")).is_ok());
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
    fn rotate_takes_the_safe_as_an_optional_positional() {
        let base = [
            "rotate",
            "--rpc-url",
            "http://localhost:8545",
            "--hd-wallet",
            "w",
        ];
        let Commands::Rotate(args) = parse(&base).unwrap().command else {
            unreachable!()
        };
        assert_eq!(args.safe, None);
        let Commands::Rotate(args) = rotate(&[]).unwrap().command else {
            unreachable!()
        };
        assert_eq!(args.safe, Some(SAFE.parse().unwrap()));
        let mut flagged = base.to_vec();
        flagged.extend(["--safe", SAFE]);
        assert!(parse(&flagged).is_err());
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
        assert!(with(&["--ledger", "--same-as", &same_as]).is_ok());
        // Without a wallet it parses, and `create` refuses it.
        assert!(with(&["--same-as", &same_as]).is_ok());
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
        assert!(
            with(&[
                "--hd-wallet",
                "w",
                "--same-as",
                &same_as,
                "--safe-version",
                "1.4.1"
            ])
            .is_err(),
            "so do the version and contracts"
        );
        assert!(with(&["--hd-wallet", "w", "--safe-version", "1.4.1"]).is_ok());
    }
}

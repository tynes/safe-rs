use std::fmt;
use std::path::PathBuf;

use alloy::eips::BlockId;
use alloy::primitives::{Address, B256, U256};
use alloy_dyn_abi::DynSolType;
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use safe_rs::{ChainAddresses, SpecId};
use url::Url;

pub use crate::commands::create::CreateArgs;
use crate::error::OptionsError;
pub use crate::wallet::WalletCommand;

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

    /// Show how many owners have approved a Safe transaction: on-chain
    /// approveHash approvals, plus offchain signatures saved in --bundle
    Approvals(ApprovalsArgs),

    /// Change the Safe's owners, threshold, modules, guards or fallback
    /// handler, all in one Safe transaction
    Config(Box<ConfigArgs>),

    /// Deploy a new Safe deterministically (same address across chains)
    Create(Box<CreateArgs>),

    /// Manage HD wallets: the encrypted phrase that one-time owner keys come from
    Wallet(WalletCliArgs),
}

/// `safe wallet`: the subcommands, and the RPC and Safe that `sync` and
/// `sweep` read. A CLI that embeds [`WalletCommand`] resolves those itself
/// into a [`WalletContext`](crate::wallet::WalletContext).
#[derive(Args, Clone)]
pub struct WalletCliArgs {
    /// RPC endpoint URL (sync and sweep)
    #[arg(long, env = "ETH_RPC_URL", global = true)]
    pub rpc_url: Option<Url>,

    /// Safe contract address (sync and sweep: default, the wallet's sole
    /// recorded Safe on this chain; status: only show this Safe)
    #[arg(long, global = true)]
    pub safe: Option<Address>,

    #[command(subcommand)]
    pub command: WalletCommand,
}

#[derive(Args, Clone, Debug)]
pub struct RpcArgs {
    /// RPC endpoint URL
    #[arg(long, env = "ETH_RPC_URL")]
    pub rpc_url: Url,
}

#[derive(Args, Clone, Debug, Default)]
pub struct SafeArgs {
    /// Safe contract address (default: the signer's default Safe, the one
    /// `safe create` deploys for it without options; with an HD wallet, its
    /// sole recorded Safe on this chain)
    #[arg(long, env = "SAFE_ADDRESS")]
    pub safe: Option<Address>,
}

/// Local fork simulation settings.
#[derive(Args, Clone, Debug)]
pub struct SimArgs {
    /// Block to fork from: a number, hash or tag (default: latest). Execution is
    /// simulated in the block after it.
    #[arg(long, value_parser = parse_block_id)]
    pub block: Option<BlockId>,

    /// EVM specification used for simulation (default: the fork active at the
    /// simulated block on mainnet, Sepolia, Holesky and Hoodi; osaka elsewhere)
    #[arg(long, value_enum)]
    pub spec: Option<EvmSpec>,

    /// Seconds between blocks, used for the simulated block's timestamp
    #[arg(long, default_value_t = DEFAULT_BLOCK_TIME)]
    pub block_time: u64,
}

impl Default for SimArgs {
    fn default() -> Self {
        Self {
            block: None,
            spec: None,
            block_time: DEFAULT_BLOCK_TIME,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum EvmSpec {
    Cancun,
    Prague,
    Osaka,
    Amsterdam,
}

/// Safe versions `safe create` can deploy, newest first.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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
            EvmSpec::Amsterdam => SpecId::AMSTERDAM,
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

    #[command(flatten)]
    pub eoa: EoaArgs,

    #[command(flatten)]
    pub opts: SendOpts,

    #[command(flatten)]
    pub signer: SignerArgs,
}

/// `--send-eoa`: whether calls go from the signer's own account or through a
/// Safe. A host that sends calls flattens it to offer the same choice.
#[derive(Args, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EoaArgs {
    /// Send each call from the signer's own account, one transaction per
    /// call, instead of through a Safe. Refuses --safe (and SAFE_ADDRESS) and
    /// the options only a Safe has, such as --bundle, --nonce and --rotate
    #[arg(long)]
    pub send_eoa: bool,
}

/// Seconds to wait for a receipt after broadcasting (`--timeout`).
pub const DEFAULT_TIMEOUT: u64 = 120;

/// Seconds between blocks in simulation (`--block-time`).
pub const DEFAULT_BLOCK_TIME: u64 = 12;

/// How `safe send` sends: simulation, gas and fees, nonce, bundle, raw-out,
/// timeout, confirmation, payer and owner rotation.
///
/// Leaves out what the transaction is sent with and to (`--rpc-url`, the
/// signer and `--safe`), which [`SendContext`](crate::SendContext) carries:
/// a CLI that embeds these flags resolves those itself. Flatten it into a
/// command with `#[command(flatten)]`, or build it in code from
/// [`Default`], which matches the flag defaults.
#[derive(Args, Clone, Debug, Default)]
#[command(
    group(ArgGroup::new("send_approve_or_simulate").args(["approve_hash", "simulate_only"])),
    group(ArgGroup::new("send_sign_or_simulate").args(["sign_only", "simulate_only"])),
    group(ArgGroup::new("send_raw_or_simulate").args(["raw_out", "simulate_only"])),
    group(ArgGroup::new("send_no_submit_or_simulate").args(["no_submit", "simulate_only"])),
)]
pub struct SendOpts {
    #[command(flatten)]
    pub collect: CollectArgs,

    /// Use MultiSendCallOnly (safer, no delegatecall)
    #[arg(long)]
    pub call_only: bool,

    #[command(flatten)]
    pub simulate: SimulateArgs,

    /// Skip simulation and execute directly (use with caution)
    #[arg(long, conflicts_with = "simulate_only")]
    pub skip_simulation: bool,

    /// Explicit safeTxGas. The default, 0, makes a failing inner call revert the
    /// whole transaction instead of consuming the Safe nonce
    #[arg(long)]
    pub safe_tx_gas: Option<U256>,

    /// Safe nonce to sign for; fails if the on-chain nonce differs
    #[arg(long)]
    pub nonce: Option<U256>,

    #[command(flatten)]
    pub fees: FeeArgs,

    #[command(flatten)]
    pub raw: RawTxArgs,

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
    /// unused key of the HD wallet (--mnemonic) or Ledger (--ledger), then
    /// move the old key's ETH to the new one. With no calls, only rotates
    #[arg(long, conflicts_with_all = ["skip_simulation", "safe_tx_gas", "multi_send", "nonce"])]
    pub rotate: bool,

    /// The HD wallet or Ledger the rotating owner keys come from. Not flags
    /// of its own: `--mnemonic` / `--ledger` (and the password) fill it under
    /// `--rotate`, see [`SignerArgs::take_rotation_keys`]
    #[arg(skip)]
    pub hd: HdArgs,

    #[command(flatten)]
    pub sweep: SweepArgs,

    #[command(flatten)]
    pub gas_payer: GasPayerArgs,
}

/// How a Safe transaction collects its signatures: `--bundle`,
/// `--merge-bundle`, `--approve-hash` and `--sign-only`.
///
/// `--approve-hash` and `--sign-only` conflict with `--simulate-only` of
/// [`SimulateArgs`]; a command that flattens both declares that itself, as
/// [`SendOpts`] does, so this group also flattens on its own.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct CollectArgs {
    /// Path to bundle JSON file (reads calls and existing signatures; writes updated bundle when collecting offchain signatures)
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Merge offchain signatures from additional bundle file(s) into this run
    #[arg(long = "merge-bundle", value_name = "PATH")]
    pub merge_bundle: Vec<PathBuf>,

    /// Publish an on-chain approveHash(safeTxHash) transaction from the signer instead of executing or only saving offchain
    #[arg(long, conflicts_with = "sign_only")]
    pub approve_hash: bool,

    /// Only sign and save the signature to --bundle (do not execute on-chain even if threshold is met)
    #[arg(long)]
    pub sign_only: bool,
}

/// Simulation of the outer transaction: `--simulate-only`, `--trace` and the
/// [`SimArgs`] (`--block`, `--spec`, `--block-time`).
#[derive(Args, Clone, Debug, Default)]
pub struct SimulateArgs {
    /// Only simulate, don't sign or broadcast the outer transaction
    #[arg(long)]
    pub simulate_only: bool,

    /// Print call traces of the simulated transaction
    #[arg(long)]
    pub trace: bool,

    #[command(flatten)]
    pub sim: SimArgs,
}

/// The signed transaction itself: `--raw-out` and `--no-submit`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub struct RawTxArgs {
    /// Write the signed transaction as JSON to PATH ("-" for stdout) before it
    /// is broadcast
    #[arg(long, value_name = "PATH")]
    pub raw_out: Option<String>,

    /// Sign the transaction but do not broadcast it (writes it to --raw-out,
    /// stdout by default)
    #[arg(long)]
    pub no_submit: bool,
}

impl SendOpts {
    /// The flag conflicts clap enforces, checked again for options built in
    /// code, which never go through clap.
    pub fn validate(&self) -> Result<(), OptionsError> {
        let conflicts = [
            (
                self.collect.approve_hash && self.collect.sign_only,
                "--approve-hash",
                "--sign-only",
            ),
            (
                self.collect.approve_hash && self.simulate.simulate_only,
                "--approve-hash",
                "--simulate-only",
            ),
            (
                self.collect.sign_only && self.simulate.simulate_only,
                "--sign-only",
                "--simulate-only",
            ),
            (
                self.skip_simulation && self.simulate.simulate_only,
                "--skip-simulation",
                "--simulate-only",
            ),
            (
                self.raw.raw_out.is_some() && self.simulate.simulate_only,
                "--raw-out",
                "--simulate-only",
            ),
            (
                self.raw.no_submit && self.simulate.simulate_only,
                "--no-submit",
                "--simulate-only",
            ),
        ];
        let rotate_conflicts = [
            (
                self.rotate && self.skip_simulation,
                "--rotate",
                "--skip-simulation",
            ),
            (
                self.rotate && self.safe_tx_gas.is_some(),
                "--rotate",
                "--safe-tx-gas",
            ),
            (
                self.rotate && self.multi_send.is_some(),
                "--rotate",
                "--multi-send",
            ),
            (self.rotate && self.nonce.is_some(), "--rotate", "--nonce"),
            (
                self.sweep.no_sweep && self.sweep.sweep_reserve.is_some(),
                "--no-sweep",
                "--sweep-reserve",
            ),
        ];
        match conflicts
            .iter()
            .chain(&rotate_conflicts)
            .find(|(conflict, ..)| *conflict)
        {
            Some(&(_, flag, with)) => Err(OptionsError::Conflict { flag, with }),
            None => Ok(()),
        }
    }

    /// Checks the options of a send through a Safe before any key or the
    /// chain is touched: the conflicts of [`validate`](Self::validate), then
    /// the rotation rules.
    ///
    /// `has_signer` is whether the caller brings the owner key (a host's
    /// signer, or any key option of [`SignerArgs`]: see
    /// [`SignerArgs::is_set`]). With `--rotate` the key comes from the HD
    /// wallet or Ledger instead.
    pub fn validate_safe(&self, has_signer: bool) -> Result<(), OptionsError> {
        self.validate()?;
        if self.rotate {
            return if has_signer {
                Err(OptionsError::RotateWithSigner)
            } else {
                Ok(())
            };
        }
        if self.sweep.no_sweep || self.sweep.sweep_reserve.is_some() {
            return Err(OptionsError::SweepWithoutRotate);
        }
        if self.hd.is_set() && !has_signer {
            return Err(OptionsError::HdWithoutRotate);
        }
        Ok(())
    }

    /// Checks the options of a send of `calls` calls from an EOA before any
    /// key or the chain is touched: the conflicts of
    /// [`validate`](Self::validate), then the options only a Safe has.
    pub fn validate_eoa(&self, calls: usize) -> Result<(), OptionsError> {
        self.validate()?;
        if let Some(flag) = self.safe_only_flag() {
            return Err(OptionsError::SafeOnly { flag });
        }
        if self.fees.gas_limit.is_some() && calls > 1 {
            return Err(OptionsError::GasLimitForBatch { calls });
        }
        Ok(())
    }

    /// The first option given that only a send through a Safe uses.
    fn safe_only_flag(&self) -> Option<&'static str> {
        let safe_only = [
            (self.collect.bundle.is_some(), "--bundle"),
            (!self.collect.merge_bundle.is_empty(), "--merge-bundle"),
            (self.collect.approve_hash, "--approve-hash"),
            (self.collect.sign_only, "--sign-only"),
            (self.call_only, "--call-only"),
            (self.safe_tx_gas.is_some(), "--safe-tx-gas"),
            (self.nonce.is_some(), "--nonce"),
            (self.raw.raw_out.is_some(), "--raw-out"),
            (self.raw.no_submit, "--no-submit"),
            (self.multi_send.is_some(), "--multi-send"),
            (
                self.multi_send_call_only.is_some(),
                "--multi-send-call-only",
            ),
            (self.gas_payer.is_set(), "--gas-payer-*"),
        ];
        let rotation = [
            (self.rotate, "--rotate"),
            (self.hd.mnemonic.is_some(), "--mnemonic"),
            (self.hd.ledger, "--ledger"),
            (self.sweep.no_sweep, "--no-sweep"),
            (self.sweep.sweep_reserve.is_some(), "--sweep-reserve"),
        ];
        safe_only
            .into_iter()
            .chain(rotation)
            .find_map(|(set, flag)| set.then_some(flag))
    }

    /// Whether the send rotates the owner key (`--rotate`).
    pub fn rotates(&self) -> bool {
        self.rotate
    }
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
#[command(
    mut_arg("bundle", |a| a.help(
        "Path to bundle JSON file. Saves the planned transaction and signatures \
         when the threshold is not met; co-signers pass it without change flags",
    )),
    group(ArgGroup::new("config_approve_or_simulate").args(["approve_hash", "simulate_only"])),
    group(ArgGroup::new("config_sign_or_simulate").args(["sign_only", "simulate_only"])),
    group(ArgGroup::new("config_raw_or_simulate").args(["raw_out", "simulate_only"])),
    group(ArgGroup::new("config_no_submit_or_simulate").args(["no_submit", "simulate_only"])),
)]
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

    /// Install a new guard or module guard even if it rejects a trivial
    /// follow-up transaction in simulation, or without simulating at all
    /// (a guard that rejects every transaction locks the Safe for good)
    #[arg(long)]
    pub allow_unchecked_guard: bool,

    #[command(flatten)]
    pub collect: CollectArgs,

    #[command(flatten)]
    pub simulate: SimulateArgs,

    /// Skip simulation, and with it the check of the resulting configuration
    /// (use with caution)
    #[arg(long, conflicts_with = "simulate_only")]
    pub skip_simulation: bool,

    /// Safe nonce to sign for; fails if the on-chain nonce differs
    #[arg(long)]
    pub nonce: Option<U256>,

    #[command(flatten)]
    pub fees: FeeArgs,

    #[command(flatten)]
    pub raw: RawTxArgs,

    /// MultiSendCallOnly address, used when there are several changes
    /// (default: canonical for the Safe's version)
    #[arg(long)]
    pub multi_send_call_only: Option<Address>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub no_confirm: bool,

    #[command(flatten)]
    pub signer: SignerArgs,

    #[command(flatten)]
    pub gas_payer: GasPayerArgs,
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
    pub signer: SignerArgs,
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
    pub signer: SignerArgs,
}

/// Reads `approvedHashes(owner, safeTxHash)` for each current owner, so no
/// logs are scanned. Safe 1.3+ never clears these approvals, so with a bare
/// hash an executed transaction still shows its approvals; pass --bundle to
/// also check whether its nonce is used.
#[derive(Parser, Clone)]
pub struct ApprovalsArgs {
    /// SafeTxHash of the transaction (default: the one prepared in --bundle)
    #[arg(value_name = "SAFE_TX_HASH", required_unless_present = "bundle")]
    pub safe_tx_hash: Option<B256>,

    /// Bundle file holding the prepared transaction; its offchain signatures
    /// are counted too
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<PathBuf>,

    #[command(flatten)]
    pub safe: SafeArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// Block to read at: a number, hash or tag (default: latest)
    #[arg(long, value_parser = parse_block_id)]
    pub block: Option<BlockId>,

    #[command(flatten)]
    pub signer: SignerArgs,
}

/// The fee and receipt flags of a transaction: `--gas-limit`,
/// `--max-fee-per-gas`, `--max-priority-fee-per-gas` and `--timeout`.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct FeeArgs {
    /// Gas limit of the outer transaction (default: simulated or estimated gas + 20%)
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
    #[arg(long, default_value_t = DEFAULT_TIMEOUT)]
    pub timeout: u64,
}

impl Default for FeeArgs {
    fn default() -> Self {
        Self {
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// The Safe `safe create` deploys: owners, threshold, salt and contracts.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct SafeSetupArgs {
    /// Additional owner address (repeatable, the first owner is always included)
    #[arg(long = "owner", value_name = "ADDR")]
    pub owners: Vec<Address>,

    /// Signature threshold (default: 1)
    #[arg(long, default_value = "1")]
    pub threshold: u64,

    /// Salt nonce for CREATE2 (default: 0)
    #[arg(long, default_value = "0")]
    pub salt_nonce: U256,

    /// Custom fallback handler address
    #[arg(long)]
    pub fallback_handler: Option<Address>,

    /// Safe version to use
    #[arg(long, value_enum, default_value_t)]
    pub safe_version: SafeVersion,

    /// Safe singleton address (default: based on --safe-version)
    #[arg(long)]
    pub singleton: Option<Address>,

    /// Safe proxy factory address (default: based on --safe-version)
    #[arg(long)]
    pub factory: Option<Address>,
}

impl Default for SafeSetupArgs {
    fn default() -> Self {
        Self {
            owners: Vec::new(),
            threshold: 1,
            salt_nonce: U256::ZERO,
            fallback_handler: None,
            safe_version: SafeVersion::default(),
            singleton: None,
            factory: None,
        }
    }
}

/// A Safe setup with every default filled in: what the address is computed
/// from and the deployment sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSetup {
    /// The first owner, then the `--owner`s in order, without duplicates
    pub owners: Vec<Address>,
    pub threshold: u64,
    pub salt_nonce: U256,
    pub singleton: Address,
    pub factory: Address,
    pub fallback_handler: Address,
}

impl SafeSetupArgs {
    /// `first` followed by the `--owner`s, without duplicates: the order the
    /// address is computed with.
    pub fn owners(&self, first: Address) -> Vec<Address> {
        owners_with(first, &self.owners)
    }

    /// Refuses a zero-address owner and a threshold outside 1..=owners.
    /// Needs the first owner, so it runs once the key is known.
    pub fn validate(&self, first: Address) -> Result<(), String> {
        check_setup(&self.owners(first), self.threshold)
    }

    /// The setup with the version's contracts filled in, after
    /// [`validate`](Self::validate).
    pub fn resolve(&self, first: Address) -> ResolvedSetup {
        let defaults = safe_rs::ChainAddresses::from(self.safe_version);
        ResolvedSetup {
            owners: self.owners(first),
            threshold: self.threshold,
            salt_nonce: self.salt_nonce,
            singleton: self.singleton.unwrap_or(defaults.safe_singleton),
            factory: self.factory.unwrap_or(defaults.proxy_factory),
            fallback_handler: self.fallback_handler.unwrap_or(defaults.fallback_handler),
        }
    }
}

/// `first` followed by `rest`, without duplicates.
pub(crate) fn owners_with(first: Address, rest: &[Address]) -> Vec<Address> {
    let mut owners = vec![first];
    for &owner in rest {
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    owners
}

/// Refuses a zero-address owner and a threshold outside 1..=owners.
pub(crate) fn check_setup(owners: &[Address], threshold: u64) -> Result<(), String> {
    if owners.contains(&Address::ZERO) {
        return Err("Zero address cannot be an owner".to_string());
    }
    if threshold == 0 || usize::try_from(threshold).map_or(true, |t| t > owners.len()) {
        return Err(format!(
            "Invalid threshold: {threshold} (must be 1-{})",
            owners.len()
        ));
    }
    Ok(())
}

/// The key that signs: `cast`'s wallet options, one to one. The flags, short
/// flags, aliases, value names, defaults and environment variables are those
/// of `foundry_wallets::WalletOpts`, which `cast send` takes. The one addition
/// is the `PRIVATE_KEY` environment variable on `--private-key`.
///
/// Two flags read more than `cast` does: `--mnemonic` also opens a `safe`
/// HD wallet (a name under `~/.safe-rs/wallets` or the path of a mnemonic
/// keystore), and `--password` / `--password-file` also unlock it.
///
/// Under `--rotate` (and on `safe wallet`), `--mnemonic` or `--ledger` gives
/// the rotating owner keys instead of one signer: see
/// [`take_rotation_keys`](Self::take_rotation_keys).
#[derive(Args, Clone, Default)]
#[command(next_help_heading = "Wallet options")]
pub struct SignerArgs {
    /// The sender account: checked against the address of the key the other
    /// options name
    #[arg(long, short, value_name = "ADDRESS", env = "ETH_FROM")]
    pub from: Option<Address>,

    /// Open an interactive prompt to enter your private key
    #[arg(long, short)]
    pub interactive: bool,

    /// Use the provided private key
    #[arg(
        long,
        value_name = "RAW_PRIVATE_KEY",
        env = "PRIVATE_KEY",
        hide_env_values = true
    )]
    pub private_key: Option<String>,

    /// Use the mnemonic phrase or mnemonic file at the specified path. Also a
    /// `safe` HD wallet: a name under ~/.safe-rs/wallets, or the path of a
    /// mnemonic keystore (unlocked with --password or --password-file)
    #[arg(long, alias = "mnemonic-path")]
    pub mnemonic: Option<String>,

    /// Use a BIP39 passphrase for the mnemonic
    #[arg(long, value_name = "PASSPHRASE")]
    pub mnemonic_passphrase: Option<String>,

    /// The wallet derivation path. Works with both --mnemonic-path and hardware
    /// wallets
    #[arg(
        long = "mnemonic-derivation-path",
        alias = "hd-path",
        value_name = "PATH"
    )]
    pub hd_path: Option<String>,

    /// Use the private key from the given mnemonic index. Used with
    /// --mnemonic-path
    #[arg(
        long,
        conflicts_with = "hd_path",
        default_value_t = 0,
        value_name = "INDEX"
    )]
    pub mnemonic_index: u32,

    /// Use the keystore file at the given path
    #[arg(long = "keystore", value_name = "PATH", env = "ETH_KEYSTORE")]
    pub keystore_path: Option<String>,

    /// Use a keystore from the default keystores folder (~/.foundry/keystores)
    /// by its filename
    #[arg(
        long = "account",
        value_name = "ACCOUNT_NAME",
        env = "ETH_KEYSTORE_ACCOUNT",
        conflicts_with = "keystore_path"
    )]
    pub keystore_account_name: Option<String>,

    #[command(flatten)]
    pub password: PasswordArgs,

    /// Use a Ledger hardware wallet
    #[arg(long, short)]
    pub ledger: bool,

    /// Use a Trezor hardware wallet
    #[arg(long, short)]
    pub trezor: bool,

    /// Use AWS Key Management Service. Ensure the AWS_KMS_KEY_ID environment
    /// variable is set
    #[arg(long, hide = !cfg!(feature = "aws-kms"))]
    pub aws: bool,

    /// Use Google Cloud Key Management Service. Ensure the following
    /// environment variables are set: GCP_PROJECT_ID, GCP_LOCATION,
    /// GCP_KEY_RING, GCP_KEY_NAME, GCP_KEY_VERSION
    #[arg(long, hide = !cfg!(feature = "gcp-kms"))]
    pub gcp: bool,

    /// Use Turnkey. Ensure the following environment variables are set:
    /// TURNKEY_API_PRIVATE_KEY, TURNKEY_ORGANIZATION_ID, TURNKEY_ADDRESS
    #[arg(long, hide = !cfg!(feature = "turnkey"))]
    pub turnkey: bool,
}

/// The old name of [`SignerArgs`].
#[deprecated(since = "0.14.0", note = "renamed to SignerArgs")]
pub type WalletArgs = SignerArgs;

impl SignerArgs {
    /// Whether any option names a key. `--from` alone does not.
    pub fn is_set(&self) -> bool {
        self.interactive
            || self.private_key.is_some()
            || self.mnemonic.is_some()
            || self.keystore_path.is_some()
            || self.keystore_account_name.is_some()
            || self.ledger
            || self.trezor
            || self.aws
            || self.gcp
            || self.turnkey
    }

    /// Moves `--mnemonic` or `--ledger`, with the password, into the source
    /// of the rotating owner keys, for `--rotate`: the wallet then gives each
    /// owner key in turn, and these flags name no signer.
    ///
    /// Refuses `--mnemonic-index`, `--mnemonic-derivation-path` and
    /// `--mnemonic-passphrase` there, since the wallet's state picks the key.
    pub fn take_rotation_keys(&mut self) -> Result<HdArgs, OptionsError> {
        if !self.ledger && self.mnemonic.is_none() {
            return Ok(HdArgs::default());
        }
        let refused = [
            (self.mnemonic_index != 0, "--mnemonic-index"),
            (self.hd_path.is_some(), "--mnemonic-derivation-path"),
            (self.mnemonic_passphrase.is_some(), "--mnemonic-passphrase"),
        ];
        if let Some((_, flag)) = refused.iter().find(|(set, _)| *set) {
            return Err(OptionsError::Conflict {
                flag,
                with: "--rotate",
            });
        }
        let hd = HdArgs {
            mnemonic: self.mnemonic.take(),
            ledger: std::mem::take(&mut self.ledger),
            password: std::mem::take(&mut self.password),
        };
        Ok(hd)
    }
}

/// The account that sends the outer transaction and pays for gas, instead of
/// the owner key: the [`SignerArgs`] flags with a `--gas-payer-` prefix, and
/// their environment variables with a `GAS_PAYER_` prefix. No short flags:
/// those belong to the signer.
#[derive(Args, Clone, Default)]
#[command(next_help_heading = "Gas payer options")]
pub struct GasPayerArgs {
    /// The gas payer's account: checked against the address of the key the
    /// other --gas-payer-* options name
    #[arg(long, value_name = "ADDRESS", env = "GAS_PAYER_ETH_FROM")]
    pub gas_payer_from: Option<Address>,

    /// Open an interactive prompt to enter the gas payer's private key
    #[arg(long)]
    pub gas_payer_interactive: bool,

    /// The gas payer's private key
    #[arg(
        long,
        value_name = "RAW_PRIVATE_KEY",
        env = "GAS_PAYER_PRIVATE_KEY",
        hide_env_values = true
    )]
    pub gas_payer_private_key: Option<String>,

    /// The gas payer's mnemonic phrase, mnemonic file or `safe` HD wallet
    #[arg(long, alias = "gas-payer-mnemonic-path")]
    pub gas_payer_mnemonic: Option<String>,

    /// BIP39 passphrase for --gas-payer-mnemonic
    #[arg(long, value_name = "PASSPHRASE")]
    pub gas_payer_mnemonic_passphrase: Option<String>,

    /// The gas payer's derivation path (mnemonic or hardware wallet)
    #[arg(
        long = "gas-payer-mnemonic-derivation-path",
        alias = "gas-payer-hd-path",
        value_name = "PATH"
    )]
    pub gas_payer_hd_path: Option<String>,

    /// The gas payer's mnemonic index
    #[arg(
        long,
        conflicts_with = "gas_payer_hd_path",
        default_value_t = 0,
        value_name = "INDEX"
    )]
    pub gas_payer_mnemonic_index: u32,

    /// The gas payer's keystore file
    #[arg(
        long = "gas-payer-keystore",
        value_name = "PATH",
        env = "GAS_PAYER_ETH_KEYSTORE"
    )]
    pub gas_payer_keystore_path: Option<String>,

    /// The gas payer's keystore in ~/.foundry/keystores, by its filename
    #[arg(
        long = "gas-payer-account",
        value_name = "ACCOUNT_NAME",
        env = "GAS_PAYER_ETH_KEYSTORE_ACCOUNT",
        conflicts_with = "gas_payer_keystore_path"
    )]
    pub gas_payer_keystore_account_name: Option<String>,

    /// The gas payer's keystore or HD wallet password
    #[arg(
        id = "gas_payer_keystore_password",
        long = "gas-payer-password",
        value_name = "PASSWORD"
    )]
    pub gas_payer_password: Option<String>,

    /// File holding the gas payer's keystore or HD wallet password
    #[arg(
        id = "gas_payer_keystore_password_file",
        long = "gas-payer-password-file",
        value_name = "PASSWORD_FILE",
        env = "GAS_PAYER_ETH_PASSWORD"
    )]
    pub gas_payer_password_file: Option<PathBuf>,

    /// The gas payer is on a Ledger
    #[arg(long)]
    pub gas_payer_ledger: bool,

    /// The gas payer is on a Trezor
    #[arg(long)]
    pub gas_payer_trezor: bool,

    /// The gas payer is in AWS KMS (AWS_KMS_KEY_ID)
    #[arg(long, hide = !cfg!(feature = "aws-kms"))]
    pub gas_payer_aws: bool,

    /// The gas payer is in Google Cloud KMS (GCP_* variables)
    #[arg(long, hide = !cfg!(feature = "gcp-kms"))]
    pub gas_payer_gcp: bool,

    /// The gas payer is a Turnkey key (TURNKEY_* variables)
    #[arg(long, hide = !cfg!(feature = "turnkey"))]
    pub gas_payer_turnkey: bool,
}

impl GasPayerArgs {
    /// Whether any option names a gas payer.
    pub fn is_set(&self) -> bool {
        self.as_signer().is_set()
    }

    /// The same options without the prefix, as [`SignerArgs`].
    pub fn as_signer(&self) -> SignerArgs {
        SignerArgs {
            from: self.gas_payer_from,
            interactive: self.gas_payer_interactive,
            private_key: self.gas_payer_private_key.clone(),
            mnemonic: self.gas_payer_mnemonic.clone(),
            mnemonic_passphrase: self.gas_payer_mnemonic_passphrase.clone(),
            hd_path: self.gas_payer_hd_path.clone(),
            mnemonic_index: self.gas_payer_mnemonic_index,
            keystore_path: self.gas_payer_keystore_path.clone(),
            keystore_account_name: self.gas_payer_keystore_account_name.clone(),
            password: PasswordArgs {
                password: self.gas_payer_password.clone(),
                password_file: self.gas_payer_password_file.clone(),
            },
            ledger: self.gas_payer_ledger,
            trezor: self.gas_payer_trezor,
            aws: self.gas_payer_aws,
            gcp: self.gas_payer_gcp,
            turnkey: self.gas_payer_turnkey,
        }
    }

    /// The first option given, by its flag, for messages.
    pub fn first_flag(&self) -> Option<&'static str> {
        let flags = [
            (self.gas_payer_interactive, "--gas-payer-interactive"),
            (
                self.gas_payer_private_key.is_some(),
                "--gas-payer-private-key",
            ),
            (self.gas_payer_mnemonic.is_some(), "--gas-payer-mnemonic"),
            (
                self.gas_payer_keystore_path.is_some(),
                "--gas-payer-keystore",
            ),
            (
                self.gas_payer_keystore_account_name.is_some(),
                "--gas-payer-account",
            ),
            (self.gas_payer_ledger, "--gas-payer-ledger"),
            (self.gas_payer_trezor, "--gas-payer-trezor"),
            (self.gas_payer_aws, "--gas-payer-aws"),
            (self.gas_payer_gcp, "--gas-payer-gcp"),
            (self.gas_payer_turnkey, "--gas-payer-turnkey"),
        ];
        flags
            .into_iter()
            .find_map(|(set, flag)| set.then_some(flag))
    }
}

/// The password of a keystore or `safe` HD wallet: `--password-file`
/// (`ETH_PASSWORD`), `--password`, or else a prompt.
#[derive(Args, Clone, Default)]
pub struct PasswordArgs {
    /// The keystore (or HD wallet) password. Visible in the process list and
    /// shell history: prefer --password-file or the prompt
    #[arg(id = "keystore_password", long = "password", value_name = "PASSWORD")]
    pub password: Option<String>,

    /// The keystore (or HD wallet) password file path
    #[arg(
        id = "keystore_password_file",
        long = "password-file",
        value_name = "PASSWORD_FILE",
        env = "ETH_PASSWORD"
    )]
    pub password_file: Option<PathBuf>,
}

/// The HD wallet (or Ledger) the rotating owner keys come from, spelled like
/// the signer flags: `--mnemonic <NAME|PATH>` or `--ledger`, with the
/// wallet's password. `safe wallet` takes these flags; a command that also
/// signs fills them from its [`SignerArgs`] with
/// [`take_rotation_keys`](SignerArgs::take_rotation_keys).
#[derive(Args, Clone, Default)]
pub struct HdArgs {
    /// The HD wallet: a name under ~/.safe-rs/wallets, or the path of a
    /// mnemonic keystore
    #[arg(long, alias = "mnemonic-path", value_name = "NAME|PATH")]
    pub mnemonic: Option<String>,

    /// Take the owner keys from a connected Ledger (Ethereum app open)
    /// instead of an HD wallet file
    #[arg(long, short)]
    pub ledger: bool,

    #[command(flatten)]
    pub password: PasswordArgs,
}

impl HdArgs {
    /// Whether an HD wallet or a Ledger was chosen.
    pub fn is_set(&self) -> bool {
        self.ledger || self.mnemonic.is_some()
    }
}

/// What happens to a retired owner key's ETH.
#[derive(Args, Clone, Debug, Default)]
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

/// Shows whether a secret was given, never its value.
fn redacted<T>(secret: Option<&T>) -> &'static str {
    if secret.is_some() {
        "Some(<redacted>)"
    } else {
        "None"
    }
}

impl fmt::Debug for SignerArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerArgs")
            .field("from", &self.from)
            .field("interactive", &self.interactive)
            .field(
                "private_key",
                &format_args!("{}", redacted(self.private_key.as_ref())),
            )
            .field(
                "mnemonic",
                &format_args!("{}", redacted(self.mnemonic.as_ref())),
            )
            .field(
                "mnemonic_passphrase",
                &format_args!("{}", redacted(self.mnemonic_passphrase.as_ref())),
            )
            .field("hd_path", &self.hd_path)
            .field("mnemonic_index", &self.mnemonic_index)
            .field("keystore_path", &self.keystore_path)
            .field("keystore_account_name", &self.keystore_account_name)
            .field("password", &self.password)
            .field("ledger", &self.ledger)
            .field("trezor", &self.trezor)
            .field("aws", &self.aws)
            .field("gcp", &self.gcp)
            .field("turnkey", &self.turnkey)
            .finish()
    }
}

impl fmt::Debug for HdArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A wallet name or path, but possibly a phrase: never shown.
        f.debug_struct("HdArgs")
            .field(
                "mnemonic",
                &format_args!("{}", redacted(self.mnemonic.as_ref())),
            )
            .field("ledger", &self.ledger)
            .field("password", &self.password)
            .finish()
    }
}

impl fmt::Debug for GasPayerArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GasPayerArgs")
            .field(&self.as_signer())
            .finish()
    }
}

impl fmt::Debug for PasswordArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordArgs")
            .field("password_file", &self.password_file)
            .field(
                "password",
                &format_args!("{}", redacted(self.password.as_ref())),
            )
            .finish()
    }
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
        assert_eq!(args.opts.fees.max_fee_per_gas, Some(2_000_000_000));
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
        assert!(call.signer.is_set());
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

    fn parse_approvals(args: &[&str]) -> Result<ApprovalsArgs, clap::Error> {
        let args = [
            &["safe", "approvals", "--rpc-url", "http://localhost:8545"],
            args,
        ]
        .concat();
        match Cli::try_parse_from(args)?.command {
            Commands::Approvals(approvals) => Ok(approvals),
            _ => unreachable!(),
        }
    }

    #[test]
    fn approvals_needs_a_hash_or_a_bundle() {
        const HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let approvals = parse_approvals(&[HASH, "--safe", SAFE]).unwrap();
        assert_eq!(approvals.safe_tx_hash, Some(HASH.parse().unwrap()));
        assert_eq!(approvals.safe.safe, Some(SAFE.parse().unwrap()));

        let approvals = parse_approvals(&["--bundle", "tx.json"]).unwrap();
        assert_eq!(approvals.safe_tx_hash, None);

        assert!(parse_approvals(&["--safe", SAFE]).is_err());
    }

    #[test]
    fn info_takes_the_safe_as_an_optional_positional() {
        let info = parse_info(&[SAFE]).unwrap();
        assert_eq!(info.safe, Some(SAFE.parse().unwrap()));

        let info = parse_info(&["--private-key", "0x01"]).unwrap();
        assert_eq!(info.safe, None);
        assert!(info.signer.is_set());

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
        assert!(send(&["--rotate", "--mnemonic", "w"]).is_ok());
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

    #[test]
    fn wallet_and_create_options_parse() {
        assert!(parse(&["wallet", "new", "treasury"]).is_ok());
        assert!(parse(&["wallet", "import", "treasury", "--start-index", "5"]).is_ok());
        assert!(parse(&["wallet", "list"]).is_ok());
        assert!(parse(&["wallet", "status", "--mnemonic", "w"]).is_ok());
        let sync = [
            "wallet",
            "sync",
            "--mnemonic",
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
        assert!(with(&["--rotate", "--mnemonic", "w", "--same-as", &same_as]).is_ok());
        assert!(with(&["--rotate", "--ledger", "--same-as", &same_as]).is_ok());
        // Without a wallet it parses, and `create` refuses it.
        assert!(with(&["--same-as", &same_as]).is_ok());
        assert!(
            with(&[
                "--mnemonic",
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
                "--mnemonic",
                "w",
                "--same-as",
                &same_as,
                "--safe-version",
                "1.4.1"
            ])
            .is_err(),
            "so do the version and contracts"
        );
        assert!(with(&["--mnemonic", "w", "--safe-version", "1.4.1"]).is_ok());
    }

    #[test]
    fn one_ledger_flag_signs_or_gives_the_rotating_keys() {
        let signer = |cli: Cli| match cli.command {
            Commands::Send(args) => args.signer,
            _ => panic!("expected send"),
        };
        let ledger = signer(send(&["--ledger"]).unwrap());
        assert!(ledger.ledger && ledger.mnemonic_index == 0);
        let indexed = signer(send(&["-l", "--mnemonic-index", "2"]).unwrap());
        assert!(indexed.ledger && indexed.mnemonic_index == 2);

        let mut rotating = ledger.clone();
        let hd = rotating.take_rotation_keys().unwrap();
        assert!(hd.ledger && !rotating.ledger && !rotating.is_set());

        let mut rotating = indexed.clone();
        assert_eq!(
            rotating.take_rotation_keys().unwrap_err(),
            OptionsError::Conflict {
                flag: "--mnemonic-index",
                with: "--rotate"
            }
        );

        let mut phrase = signer(send(&["--mnemonic", "w", "--password-file", "/pw"]).unwrap());
        let hd = phrase.take_rotation_keys().unwrap();
        assert_eq!(hd.mnemonic.as_deref(), Some("w"));
        assert!(hd.password.password_file.is_some());
        assert!(!phrase.is_set() && phrase.password.password_file.is_none());

        assert!(parse(&["wallet", "status", "--ledger"]).is_ok());
        assert!(parse(&["wallet", "status", "--mnemonic", "w"]).is_ok());
    }

    /// The gas payer takes every wallet option, prefixed.
    #[test]
    fn the_gas_payer_takes_the_wallet_options_prefixed() {
        let payer = |cli: Cli| match cli.command {
            Commands::Send(args) => args.opts.gas_payer,
            _ => panic!("expected send"),
        };
        let given = payer(send(&["--gas-payer-private-key", "0x01"]).unwrap());
        assert_eq!(given.as_signer().private_key.as_deref(), Some("0x01"));
        assert_eq!(given.first_flag(), Some("--gas-payer-private-key"));
        let ledger =
            payer(send(&["--gas-payer-ledger", "--gas-payer-mnemonic-index", "3"]).unwrap());
        assert!(ledger.as_signer().ledger);
        assert_eq!(ledger.as_signer().mnemonic_index, 3);
        assert!(payer(send(&["--gas-payer-account", "a"]).unwrap()).is_set());
        assert!(!payer(send(&[]).unwrap()).is_set());
        assert!(send(&["--gas-payer-keystore", "k", "--gas-payer-account", "a"]).is_err());
    }

    #[test]
    fn send_eoa_is_a_send_flag() {
        let send_eoa = |cli: Cli| match cli.command {
            Commands::Send(args) => args.eoa.send_eoa,
            _ => panic!("expected send"),
        };
        assert!(send_eoa(
            parse(&["send", TO, "--send-eoa", "--rpc-url", "http://x"]).unwrap()
        ));
        assert!(!send_eoa(send(&[]).unwrap()));
    }

    /// Each shared group flattens on its own into a host's command: none
    /// names an argument from another group.
    #[test]
    fn each_flag_group_flattens_alone() {
        fn check<T: Args>(name: &'static str) {
            T::augment_args(clap::Command::new(name)).debug_assert();
        }
        check::<CollectArgs>("collect");
        check::<SimulateArgs>("simulate");
        check::<FeeArgs>("fees");
        check::<RawTxArgs>("raw");
        check::<SendOpts>("send");
        check::<SafeSetupArgs>("setup");
    }

    #[test]
    fn the_groups_keep_their_conflicts_with_simulate_only() {
        for flag in [
            &["--approve-hash"][..],
            &["--sign-only"],
            &["--no-submit"],
            &["--raw-out", "-"],
        ] {
            let args = [flag, &["--simulate-only"][..]].concat();
            let error = send(&args).err().expect("a conflict");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{flag:?}"
            );
        }
        assert!(send(&["--approve-hash", "--sign-only"]).is_err());
    }

    #[test]
    fn an_eoa_send_refuses_what_only_a_safe_does() {
        let opts = SendOpts::default();
        assert_eq!(opts.validate_eoa(3), Ok(()));
        let with_nonce = SendOpts {
            nonce: Some(U256::from(1)),
            ..SendOpts::default()
        };
        assert_eq!(
            with_nonce.validate_eoa(1),
            Err(OptionsError::SafeOnly { flag: "--nonce" })
        );
        assert_eq!(with_nonce.validate_safe(true), Ok(()));
        let gas = SendOpts {
            fees: FeeArgs {
                gas_limit: Some(21_000),
                ..FeeArgs::default()
            },
            ..SendOpts::default()
        };
        assert_eq!(gas.validate_eoa(1), Ok(()));
        assert_eq!(
            gas.validate_eoa(2),
            Err(OptionsError::GasLimitForBatch { calls: 2 })
        );
        // The flag conflicts come first, for either kind of send.
        let conflicting = SendOpts {
            simulate: SimulateArgs {
                simulate_only: true,
                ..SimulateArgs::default()
            },
            skip_simulation: true,
            collect: CollectArgs {
                bundle: Some("tx.json".into()),
                ..CollectArgs::default()
            },
            ..SendOpts::default()
        };
        let conflict = Err(OptionsError::Conflict {
            flag: "--skip-simulation",
            with: "--simulate-only",
        });
        assert_eq!(conflicting.validate_eoa(1), conflict);
        assert_eq!(conflicting.validate_safe(true), conflict);
    }

    #[test]
    fn a_safe_send_applies_the_rotation_rules() {
        let rotate = SendOpts {
            rotate: true,
            ..SendOpts::default()
        };
        assert!(rotate.rotates());
        assert_eq!(rotate.validate_safe(false), Ok(()));
        assert_eq!(
            rotate.validate_safe(true),
            Err(OptionsError::RotateWithSigner)
        );
        assert_eq!(
            rotate.validate_eoa(1),
            Err(OptionsError::SafeOnly { flag: "--rotate" })
        );

        let mut ledger = SendOpts::default();
        ledger.hd.ledger = true;
        assert!(!ledger.rotates());
        assert_eq!(
            ledger.validate_safe(false),
            Err(OptionsError::HdWithoutRotate)
        );

        let mut no_sweep = SendOpts::default();
        no_sweep.sweep.no_sweep = true;
        assert_eq!(
            no_sweep.validate_safe(true),
            Err(OptionsError::SweepWithoutRotate)
        );
    }
}

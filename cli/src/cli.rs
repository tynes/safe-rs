use clap::{Parser, Subcommand};

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
    Send(SendArgs),

    /// Simulate a call without executing (dry-run)
    Call(CallArgs),

    /// Display Safe information (nonce, threshold, owners)
    Info(InfoArgs),

    /// Deploy a new Safe deterministically (same address across chains)
    Create(CreateArgs),
}

#[derive(Parser, Clone)]
pub struct SendArgs {
    /// Target address (for single call mode)
    #[arg(value_name = "TO")]
    pub to: Option<String>,

    /// Function signature (e.g., "transfer(address,uint256)")
    #[arg(value_name = "SIG")]
    pub sig: Option<String>,

    /// Function arguments
    #[arg(value_name = "ARGS")]
    pub args: Vec<String>,

    /// Safe contract address
    #[arg(long, env = "SAFE_ADDRESS")]
    pub safe: String,

    /// RPC endpoint URL
    #[arg(long, env = "ETH_RPC_URL")]
    pub rpc_url: String,

    /// ETH value to send (in wei)
    #[arg(long, default_value = "0")]
    pub value: String,

    /// Call specification for multicall mode (format: "0xAddr:sig(types):arg1,arg2")
    #[arg(long = "call", value_name = "CALL")]
    pub calls: Vec<String>,

    /// Path to Safe TX Bundler JSON file
    #[arg(long)]
    pub bundle: Option<String>,

    /// Use MultiSendCallOnly (safer, no delegatecall)
    #[arg(long)]
    pub call_only: bool,

    /// Only simulate, don't execute
    #[arg(long)]
    pub simulate_only: bool,

    /// Skip simulation and execute directly (use with caution)
    #[arg(long)]
    pub skip_simulation: bool,

    /// Override Safe transaction gas limit (auto-estimated if not set)
    #[arg(long)]
    pub safe_tx_gas: Option<String>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub no_confirm: bool,

    #[command(flatten)]
    pub wallet: WalletArgs,
}

#[derive(Parser, Clone)]
pub struct CallArgs {
    /// Target address
    #[arg(value_name = "TO")]
    pub to: String,

    /// Function signature (e.g., "balanceOf(address)")
    #[arg(value_name = "SIG")]
    pub sig: String,

    /// Function arguments
    #[arg(value_name = "ARGS")]
    pub args: Vec<String>,

    /// Safe contract address
    #[arg(long, env = "SAFE_ADDRESS")]
    pub safe: String,

    /// RPC endpoint URL
    #[arg(long, env = "ETH_RPC_URL")]
    pub rpc_url: String,

    /// ETH value to send (in wei)
    #[arg(long, default_value = "0")]
    pub value: String,
}

#[derive(Parser, Clone)]
pub struct InfoArgs {
    /// Safe contract address
    #[arg(long, env = "SAFE_ADDRESS")]
    pub safe: String,

    /// RPC endpoint URL
    #[arg(long, env = "ETH_RPC_URL")]
    pub rpc_url: String,
}

#[derive(Parser, Clone)]
pub struct CreateArgs {
    /// RPC endpoint URL
    #[arg(long, env = "ETH_RPC_URL")]
    pub rpc_url: String,

    /// Salt nonce for CREATE2 (default: 0)
    #[arg(long, default_value = "0")]
    pub salt_nonce: String,

    /// Additional owner address (repeatable, signer is always included)
    #[arg(long = "owner", value_name = "ADDR")]
    pub owners: Vec<String>,

    /// Signature threshold (default: 1)
    #[arg(long, default_value = "1")]
    pub threshold: u64,

    /// Only compute and display the address, don't deploy
    #[arg(long)]
    pub compute_only: bool,

    /// Custom fallback handler address
    #[arg(long)]
    pub fallback_handler: Option<String>,

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

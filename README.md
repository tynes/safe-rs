# safe-rs

A Rust library and CLI for interacting with [Safe](https://safe.global) smart accounts.
Built for single-owner (1/1) Safes with a focus on simplicity, safety, and developer experience.

## Philosophy

**Opinionated by design.** safe-rs optimizes for an opinionated usecase: single-owner Safes where you want to execute transactions with confidence. Rather than supporting every Safe configuration, it provides a streamlined experience with compile-time guarantees and optional forking simulation.

**Minimal surface area.** One way to do things, done well. No configuration sprawl, no optional safety features that can be accidentally disabled.

## Features

- **Type-state builder pattern** — Compile-time enforcement that simulation precedes execution
- **Fork simulation** — Test transactions against live blockchain state using revm
- **Automatic multicall batching** — Single calls execute directly; multiple calls batch via MultiSend
- **Type-safe contract calls** — First-class support for alloy's `sol!` macro
- **Multi-chain support** — Pre-configured for Ethereum, Arbitrum, Optimism, Base, Polygon, and more
- **Deterministic deployment** — Deploy new Safes with predictable addresses via CREATE2
- **Gas estimation** — Automatic safeTxGas calculation with safety buffer
- **Revert decoding** — Human-readable error messages from failed simulations
- **EOA fallback mode** — Same builder API for executing as individual transactions from an EOA

## Installation

### CLI

```bash
cargo install safe-rs
```

### Library

```toml
[dependencies]
safe-rs = "0.1"
```

## Quick Start

### CLI

Execute an ERC20 transfer through your Safe:

```bash
safe send 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
    'transfer(address,uint256)' 0xRecipient 1000000 \
    --safe 0xYourSafe \
    --rpc-url $ETH_RPC_URL \
    --private-key $PRIVATE_KEY
```

Simulate without executing:

```bash
safe call 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
    'transfer(address,uint256)' 0xRecipient 1000000 \
    --safe 0xYourSafe \
    --rpc-url $ETH_RPC_URL
```

### Library

```rust
use safe_rs::{Safe, contracts::IERC20};
use alloy::primitives::{address, U256};

let safe = Safe::connect(provider, signer, safe_address).await?;
safe.verify_single_owner().await?;

let result = safe
    .multicall()
    .add_typed(token, IERC20::transferCall {
        to: recipient,
        amount: U256::from(1_000_000),
    })
    .simulate().await?
    .execute().await?;

println!("Transaction: {:?}", result.transaction_hash);
```

## CLI Reference

### `safe send`

Execute transactions through a Safe. Always simulates first, then prompts for confirmation.

**Single call:**
```bash
safe send <to> <signature> [args...] --safe <address> --rpc-url <url>
```

**Multiple calls:**
```bash
safe send \
    --call 0xToken:transfer(address,uint256):0xRecipient,1000 \
    --call 0xToken:approve(address,uint256):0xSpender,5000 \
    --safe 0xYourSafe \
    --rpc-url $ETH_RPC_URL
```

**From bundle file:**
```bash
safe send --bundle transactions.json --safe 0xYourSafe --rpc-url $ETH_RPC_URL
```

**Options:**
| Flag | Description |
|------|-------------|
| `--simulate-only` | Simulate without executing |
| `--call-only` | Use MultiSendCallOnly (no delegatecall) |
| `--no-confirm` | Skip confirmation prompt |
| `--json` | Output as JSON |
| `-i, --interactive` | Prompt for private key |

### `safe call`

Simulate a transaction without executing. Useful for testing and gas estimation.

```bash
safe call <to> <signature> [args...] --safe <address> --rpc-url <url>
```

### `safe info`

Query Safe state.

```bash
safe info --safe 0xYourSafe --rpc-url $ETH_RPC_URL
```

Output:
```
Safe: 0xYourSafe
Nonce: 42
Threshold: 1
Owners:
  - 0xOwner1
```

### `safe create`

Deploy a new Safe with deterministic addressing.

```bash
safe create \
    --owner 0xAdditionalOwner \
    --threshold 2 \
    --salt-nonce 12345 \
    --rpc-url $ETH_RPC_URL \
    --private-key $PRIVATE_KEY
```

**Options:**
| Flag | Description |
|------|-------------|
| `--owner <address>` | Additional owner (repeatable) |
| `--threshold <n>` | Required signatures (default: 1) |
| `--salt-nonce <n>` | Salt for deterministic address |
| `--compute-only` | Show address without deploying |

### Wallet Options

All commands that require signing support:

| Flag | Description |
|------|-------------|
| `--private-key <key>` | Private key (hex) |
| `-i, --interactive` | Prompt for private key securely |
| `PRIVATE_KEY` env var | Environment variable |

## Library API

### Connecting to a Safe

```rust
use safe_rs::Safe;

// Auto-detect chain configuration
let safe = Safe::connect(provider, signer, safe_address).await?;

// Verify single-owner requirement
safe.verify_single_owner().await?;
```

### Building Transactions

The `MulticallBuilder` uses a type-state pattern with two states:
- `NotSimulated` — Can add calls, cannot execute
- `Simulated` — Can execute, cannot add more calls

```rust
// Raw call
let builder = safe.multicall()
    .add(Call {
        to: address,
        value: U256::ZERO,
        data: calldata.into(),
        operation: Operation::Call,
    });

// Typed call (recommended)
let builder = safe.multicall()
    .add_typed(token, IERC20::transferCall { to, amount });

// Multiple calls batch automatically
let builder = safe.multicall()
    .add_typed(token1, transfer1)
    .add_typed(token2, transfer2)
    .call_only();  // Use MultiSendCallOnly for safety
```

### Simulation

Simulation runs the transaction against a fork of the current blockchain state:

```rust
let simulated = builder.simulate().await?;

println!("Success: {}", simulated.success());
println!("Gas used: {}", simulated.gas_used());
println!("Logs: {:?}", simulated.logs());

// If simulation failed
if !simulated.success() {
    println!("Revert reason: {:?}", simulated.revert_reason());
}
```

### Execution

After simulation, you can execute:

```rust
let result = simulated.execute().await?;
println!("Transaction hash: {:?}", result.transaction_hash);
```

### Simulation-Only Mode

For read-only operations or testing, you don't need to be an owner:

```rust
use alloy::signers::local::PrivateKeySigner;

// Use any signer for simulation
let dummy = PrivateKeySigner::random();
let safe = Safe::new(provider, dummy, safe_address, config);

let result = safe.multicall()
    .add_typed(token, call)
    .simulate().await?;

// Inspect results without executing
println!("Would use {} gas", result.gas_used());
```

### Querying Safe State

```rust
let nonce = safe.nonce().await?;
let threshold = safe.threshold().await?;
let owners = safe.owners().await?;
```

### EOA Fallback Mode

The `Eoa` client provides the same builder API as Safe multicall, but executes each call as a separate transaction. This is useful when you don't have a Safe but want the same batching workflow:

```rust
use safe_rs::Eoa;

let eoa = Eoa::connect(provider, signer).await?;

let result = eoa.batch()
    .add_typed(token, IERC20::transferCall { to: alice, amount: U256::from(100) })
    .add_typed(token, IERC20::transferCall { to: bob, amount: U256::from(200) })
    .simulate().await?
    .execute().await?;

println!("Executed {} txs, {} succeeded", result.results.len(), result.success_count);

for tx in &result.results {
    println!("Tx {}: {:?}", tx.index, tx.tx_hash);
}
```

**Key differences from Safe mode:**

| Aspect | Safe Mode | EOA Mode |
|--------|-----------|----------|
| Execution | Single atomic tx via MultiSend | Multiple independent txs |
| Failure | All-or-nothing | Can partially succeed |
| Result | Single `TxHash` | `Vec<TxHash>` |
| DelegateCall | Supported | Not supported |

**Partial failure handling:**

By default, EOA batch execution stops on the first failure. Use `continue_on_failure()` to execute all transactions regardless:

```rust
let result = eoa.batch()
    .add_typed(token, transfer1)
    .add_typed(token, transfer2)
    .continue_on_failure()  // Don't stop on first failure
    .simulate().await?
    .execute().await?;

if let Some(idx) = result.first_failure {
    println!("First failure at index {}", idx);
}
```

## Bundle Format

The `--bundle` option accepts JSON files compatible with the Safe Transaction Bundler format:

```json
[
  {
    "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "value": "0",
    "data": "0xa9059cbb000000000000000000000000...",
    "operation": 0
  },
  {
    "to": "0x6B175474E89094C44Da98b954EescdAD80089fD12",
    "data": "0x095ea7b3...",
    "operation": 0
  }
]
```

Fields:
- `to` — Target address (required)
- `value` — Wei to send (optional, default: "0")
- `data` — Calldata hex (optional, default: "0x")
- `operation` — 0 for Call, 1 for DelegateCall (optional, default: 0)

## Supported Chains

safe-rs includes pre-configured addresses for Safe v1.4.1 contracts:

| Chain | Chain ID |
|-------|----------|
| Ethereum | 1 |
| Sepolia | 11155111 |
| Arbitrum | 42161 |
| Optimism | 10 |
| Base | 8453 |
| Polygon | 137 |
| BSC | 56 |
| Avalanche | 43114 |
| Gnosis | 100 |

All chains use the same contract addresses (deployed via CREATE2):

| Contract | Address |
|----------|---------|
| Safe Singleton | `0x41675C099F32341bf84BFc5382aF534df5C7461a` |
| MultiSend | `0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526` |
| MultiSendCallOnly | `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` |
| Proxy Factory | `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` |
| Fallback Handler | `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99` |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ETH_RPC_URL` | RPC endpoint URL |
| `SAFE_ADDRESS` | Default Safe address |
| `PRIVATE_KEY` | Signer private key |

## Examples

See the [`examples/`](./examples) directory:

- `simple_transfer.rs` — Single ERC20 transfer
- `multicall_erc20.rs` — Batch multiple operations
- `simulation_only.rs` — Simulation without execution

Run examples:
```bash
cargo run --example simple_transfer
```

## Why safe-rs?

**vs Safe Transaction Service API:** safe-rs executes transactions directly on-chain without relying on Safe's infrastructure. No API keys, no rate limits, no external dependencies.

**vs ethers/alloy directly:** safe-rs handles the complexity of Safe transaction encoding, EIP-712 signing, gas estimation, and multicall batching. You focus on what you want to do, not how Safe works internally.

**vs multi-owner Safes:** If you need multiple signers, use the Safe web interface or Transaction Service. safe-rs is intentionally limited to 1/1 Safes for simplicity and reliability.

## License

MIT

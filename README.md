# safe-rs

A Rust library and CLI for interacting with [Safe](https://safe.global) smart accounts.
Built for single-owner (1/1) Safes with a focus on simplicity, safety, and developer experience.

## Philosophy

**Opinionated by design.** safe-rs optimizes for an opinionated usecase: single-owner Safes where you want to execute transactions with confidence. Rather than supporting every Safe configuration, it provides a streamlined experience with compile-time guarantees and optional forking simulation.

**Minimal surface area.** One way to do things, done well. No configuration sprawl, no optional safety features that can be accidentally disabled.

## Features

- **Fluent builder pattern** — Simple API with optional simulation before execution
- **Fork simulation** — Test transactions against live blockchain state using revm
- **Automatic multicall batching** — Single calls execute directly; multiple calls batch via MultiSend
- **Type-safe contract calls** — First-class support for alloy's `sol!` macro
- **Multi-chain support** — Pre-configured for Ethereum, Arbitrum, Optimism, Base, Polygon, and more
- **Deterministic deployment** — Deploy new Safes with predictable addresses via CREATE2
- **Fail-closed execution** — `safeTxGas` defaults to 0, so a failing inner call reverts the whole transaction instead of consuming the Safe nonce; `execute()` signs exactly the Safe transaction that `simulate()` ran
- **Revert decoding** — Human-readable error messages from failed simulations
- **EOA fallback mode** — Same builder API for executing as individual transactions from an EOA

## Installation

### CLI

The `safe-rs-cli` crate installs the `safe` binary:

```bash
cargo install safe-rs-cli --locked
```

Or from a local clone:

```bash
cargo install --path cli --locked
```

### Library

```toml
[dependencies]
safe-rs = "0.12"
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
    .batch()
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

Execute transactions through a Safe. `send` freezes the Safe transaction (nonce, `safeTxGas = 0`), signs it, and simulates the exact outer `execTransaction` it will broadcast in the next block with all validity checks (nonce, fees, balance). It then prompts for confirmation, signs the outer transaction locally, broadcasts the raw bytes and waits for the Safe's `ExecutionSuccess` event. A failed simulation stops before any prompt and exits non-zero.

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

**Sign now, broadcast later:**
```bash
# Write the signed transaction to stdout without broadcasting it
safe send --bundle transactions.json --call-only --no-submit --safe 0xYourSafe > tx.json

# Or keep a copy of the exact bytes while submitting
safe send --bundle transactions.json --call-only --raw-out tx.json --safe 0xYourSafe
```

**Options:**
| Flag | Description |
|------|-------------|
| `--simulate-only` | Simulate without signing or broadcasting |
| `--skip-simulation` | Skip simulation (outer gas from `eth_estimateGas`) |
| `--call-only` | Use MultiSendCallOnly (no delegatecall) |
| `--nonce <n>` | Safe nonce to sign for; fails if the on-chain nonce differs |
| `--safe-tx-gas <n>` | Explicit `safeTxGas` (default 0; non-zero lets a failed inner call consume the nonce) |
| `--gas-limit <n>` | Outer gas limit (default: simulated gas + 20%) |
| `--max-fee-per-gas <wei>` / `--max-priority-fee-per-gas <wei>` | Override the node's fee estimate |
| `--raw-out <path\|->` | Write the signed transaction as JSON before broadcasting (`-` = stdout; progress then goes to stderr) |
| `--no-submit` | Sign but don't broadcast (implies `--raw-out -` unless set) |
| `--timeout <secs>` | How long to wait for the receipt (default 120) |
| `--trace` | Print call traces of the simulation |
| `--block <n\|hash\|tag>` | Simulate on top of this block (default: latest) |
| `--spec <cancun\|prague\|osaka>` | EVM spec for simulation (default: osaka) |
| `--multi-send <addr>` / `--multi-send-call-only <addr>` | Non-canonical MultiSend deployments |
| `--no-confirm` | Skip confirmation prompt |
| `--json` | Output as JSON |
| `-i, --interactive` | Prompt for private key |

The `--raw-out` document contains `chain_id`, `safe`, `safe_nonce`, `safe_tx_hash`, the Safe transaction fields (`safe_tx`), the owner `signer` and `signature`, the outer transaction fields (`outer`), the EIP-2718 `raw` bytes and their `tx_hash`. `raw` can be rebroadcast as is with `cast publish`.

A broadcast the node rejects, a broadcast with an unclear result, a receipt that doesn't arrive in time, and a Safe transaction without `ExecutionSuccess` all exit non-zero with the transaction hash.

### `safe call`

Simulate a call made by the Safe without executing it. It runs in the block after `--block` (default: latest), with that block's timestamp and base fee. It is useful for testing and gas estimation.

```bash
safe call <to> <signature> [args...] --safe <address> --rpc-url <url> [--block <n>] [--trace]
```

### `safe info`

Query Safe state. Every value is read at the same block (`--block`, default: latest).

```bash
safe info --safe 0xYourSafe --rpc-url $ETH_RPC_URL [--block <n|hash|tag>]
```

Output:
```
Safe: 0xYourSafe
Block: 21000000 (0x...)
Version: 1.4.1
Singleton: 0x41675C099F32341bf84BFc5382aF534df5C7461a
Nonce: 42
Threshold: 1
Owners:
  1: 0xOwner1
Modules: none
Guard: none
Fallback Handler: 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99
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
| `--fallback-handler <address>` | Custom fallback handler |
| `--singleton <address>` / `--factory <address>` | Non-canonical Safe deployment |

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

The `MulticallBuilder` provides a fluent API for constructing transactions:

```rust
// Raw call
let builder = safe.batch()
    .add(Call {
        to: address,
        value: U256::ZERO,
        data: calldata.into(),
        operation: Operation::Call,
    });

// Typed call (recommended)
let builder = safe.batch()
    .add_typed(token, IERC20::transferCall { to, amount });

// Multiple calls batch automatically
let builder = safe.batch()
    .add_typed(token1, transfer1)
    .add_typed(token2, transfer2)
    .call_only();  // Use MultiSendCallOnly for safety
```

### Simulation

Simulation runs the transaction against a fork of the current blockchain state:

```rust
let builder = builder.simulate().await?;

// Access simulation result
if let Some(result) = builder.simulation_result() {
    println!("Success: {}", result.success);
    println!("Gas used: {}", result.gas_used);
    println!("Logs: {:?}", result.logs);

    // If simulation failed
    if let Some(reason) = &result.revert_reason {
        println!("Revert reason: {}", reason);
    }
}
```

### Execution

After simulation, you can execute:

```rust
let result = simulated.execute().await?;
println!("Transaction hash: {:?}", result.tx_hash);
```

`execute()` signs exactly the Safe transaction that `simulate()` ran. It fails with `Error::NonceMismatch` if the Safe nonce moved in the meantime. `safeTxGas` is 0 unless set with `with_safe_tx_gas()`, so a failing inner call reverts (`GS013`) instead of being mined as `ExecutionFailure`.

### Frozen Transactions

To review, simulate, sign and broadcast the same transaction as separate steps, freeze it with `prepare()`:

```rust
use safe_rs::{broadcast_raw, sign_outer_tx, OuterTxParams};

let prepared = safe.batch().call_only().add_typed(token, call).prepare().await?;
let signed = prepared.sign(&owner).await?;
let fees = provider.estimate_eip1559_fees().await?;
let params = OuterTxParams::exec_transaction(&signed, owner.address(), eoa_nonce, gas_limit, fees);
let outer = sign_outer_tx(&owner, params).await?;
// persist outer.raw / outer.tx_hash, then:
let outcome = broadcast_raw(&provider, &outer.raw, outer.tx_hash).await;
```

`ForkSession` simulates `SimTx::from_outer(&outer.params, TxChecks::STRICT)` in the next block before you broadcast. `read_safe_state` returns a block-pinned snapshot of owners, threshold, nonce, modules, guard and fallback handler.

### Simulation-Only Mode

For read-only operations or testing, you don't need to be an owner:

```rust
use alloy::signers::local::PrivateKeySigner;

// Use any signer for simulation
let dummy = PrivateKeySigner::random();
let safe = Safe::new(provider, dummy, safe_address, config);

let builder = safe.batch()
    .add_typed(token, call)
    .simulate().await?;

// Inspect results without executing
if let Some(result) = builder.simulation_result() {
    println!("Would use {} gas", result.gas_used);
}
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

EOA simulation runs the calls in order on one fork, so each call sees the effects of the calls before it (for example an `approve` followed by a `transferFrom`).

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
- `operation` — 0 for Call, 1 for DelegateCall (optional, default: 0). With `--call-only`, a DelegateCall entry is rejected.
- `value` accepts decimal or `0x`-prefixed hex

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

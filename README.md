# safe-rs

A Rust library and CLI for interacting with [Safe](https://safe.global) smart accounts.
Built for single-signer (threshold 1) Safes with a focus on simplicity, safety, and developer experience.

## Philosophy

**Opinionated by design.** safe-rs optimizes for an opinionated usecase: single-signer Safes where you want to execute transactions with confidence. Rather than supporting every Safe configuration, it provides a streamlined experience with compile-time guarantees and optional forking simulation.

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
- **One-time owner keys** — `send --rotate` swaps the Safe's owner for a fresh key in the same transaction, with the keys derived from one encrypted phrase ([details](#one-time-owner-keys))

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

Use the owner key once, and hand the Safe to the next key in the same transaction:

```bash
safe wallet new treasury                      # encrypts a new 24-word phrase to disk
# send ETH for gas to the funding address it prints, then:
safe create --hd-wallet treasury --rpc-url $ETH_RPC_URL
safe send 0xRecipient --value 1000000000000000000 \
    --safe 0xYourSafe \
    --rpc-url $ETH_RPC_URL \
    --rotate --hd-wallet treasury
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
| `--multi-send <addr>` / `--multi-send-call-only <addr>` | MultiSend contracts to batch through (default: the canonical ones for the Safe's version) |
| `--no-confirm` | Skip confirmation prompt |
| `--json` | Output as JSON |
| `-i, --interactive` | Prompt for private key |
| `--payer-private-key <key>` | A different key sends the outer transaction and pays for gas |
| `--rotate` | Swap the owner for the next unused key of `--hd-wallet` in the same transaction (see [One-time owner keys](#one-time-owner-keys)) |
| `--hd-wallet <name\|path>` | The HD wallet the owner keys come from (with `--rotate`) |
| `--ledger` | Take the owner keys from a connected Ledger instead (with `--rotate`; see [On a Ledger](#on-a-ledger)) |
| `--no-sweep` | With `--rotate`: leave the old owner's ETH where it is |
| `--sweep-reserve <wei>` | With `--rotate`: wei to leave on the old owner when sweeping |

`--rotate` cannot be combined with `--skip-simulation`, `--safe-tx-gas`, `--nonce` or `--multi-send`: the rotation has to succeed or fail together with the calls, and its result is checked in simulation.

Two or more calls go through a MultiSend contract: by default the canonical one for the Safe's version (v1.5.0 for a v1.5.0 Safe, v1.4.1 for any other), with or without `--rotate`. Pass another with `--multi-send` or `--multi-send-call-only`. A Safe sent a batch through an address without code reports success while none of the calls ran, so if the contract has no code on the chain (at `--block`, when simulating from one) the command stops before signing anything and names the address. That holds with `--rotate` too, where the calls and the owner swap are the batch.

The `--raw-out` document contains `chain_id`, `safe`, `safe_nonce`, `safe_tx_hash`, the Safe transaction fields (`safe_tx`), the owner `signer` and `signature`, the outer transaction fields (`outer`), the EIP-2718 `raw` bytes and their `tx_hash`. `raw` can be rebroadcast as is with `cast publish`. With `--rotate` it also has a `rotation` object naming the old and new owner, the payer and the planned sweep.

A broadcast the node rejects, a broadcast with an unclear result, a receipt that doesn't arrive in time, and a Safe transaction without `ExecutionSuccess` all exit non-zero with the transaction hash.

### `safe call`

Simulate a call made by the Safe without executing it. It runs in the block after `--block` (default: latest), with that block's timestamp and base fee. It is useful for testing and gas estimation.

```bash
safe call <to> <signature> [args...] --safe <address> --rpc-url <url> [--block <n>] [--trace]
```

### `safe info`

Query Safe state. Every value is read at the same block (`--block`, default: latest).

```bash
safe info [safe] --rpc-url <url> [--block <n|hash|tag>]
```

Without an address, `info` shows the signer's default Safe: the one `safe create` deploys for that key when run without options (salt nonce 0, the signer as the only owner). That address depends on the Safe version, so `info` looks for a v1.5.0 Safe first and then for a v1.4.1 one.

```bash
# The default Safe of the signer
safe info --rpc-url $ETH_RPC_URL --private-key $PRIVATE_KEY

# Any Safe, no key needed
safe info 0xYourSafe --rpc-url $ETH_RPC_URL
```

A Safe created with other options (`--owner`, `--threshold`, `--salt-nonce`, `--fallback-handler`, `--singleton`, `--factory`) has a different address, which must be passed explicitly.

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
    --safe-version 1.5.0 \
    --rpc-url $ETH_RPC_URL \
    --private-key $PRIVATE_KEY
```

**Options:**
| Flag | Description |
|------|-------------|
| `--owner <address>` | Additional owner (repeatable) |
| `--threshold <n>` | Required signatures (default: 1) |
| `--salt-nonce <n>` | Salt for deterministic address |
| `--safe-version <version>` | Safe version: `1.5.0` (default) or `1.4.1` |
| `--compute-only` | Show address without deploying |
| `--fallback-handler <address>` | Custom fallback handler |
| `--singleton <address>` / `--factory <address>` | Non-canonical Safe deployment |

With `--hd-wallet <name>` (or `--ledger`) the Safe is a 1/1 owned by a wallet key that has never signed anything: the wallet's funding key sends the deployment, then its remaining ETH moves to the owner (`--no-sweep` to skip). `--safe-version` applies as usual. `--same-as <chain_id>:<safe>` deploys the same Safe on another chain, with the version and contracts it was first created with.

### `safe rotate`

Swap the Safe's owner for the HD wallet's next unused key, with no other calls. See [One-time owner keys](#one-time-owner-keys).

```bash
# Retire the current owner of the wallet's sole Safe on this chain
safe rotate --rpc-url $ETH_RPC_URL --hd-wallet treasury

# Move an existing Safe from an ordinary key onto the wallet
safe rotate 0xYourSafe --rpc-url $ETH_RPC_URL --hd-wallet treasury --from-interactive
```

The Safe address is optional: `safe rotate [SAFE]`. Without an address, the command selects the HD wallet's sole recorded Safe on the connected chain. If none are recorded, supply an address or recover the state with `safe wallet sync`; if several are recorded, the command lists them and asks for an explicit address.

With `--from-*` and no address, it instead discovers that legacy signer's default Safe, just like `info` (v1.5.0 first, then v1.4.1). Safes created with other options need an explicit address. `rotate` does not accept `--safe` or read `SAFE_ADDRESS`.

**Options:**
| Flag | Description |
|------|-------------|
| `--from-private-key <key>` / `--from-keystore <path>` / `--from-interactive` | The Safe's current owner, when it is not a wallet key |
| `--sweep-legacy` | Move the `--from-*` key's whole ETH balance to the new owner without a prompt (required with `--no-confirm` or `--json`) |
| `--no-sweep` / `--sweep-reserve <wei>` | As for `send --rotate` |
| `--payer-private-key <key>` | A different key pays for gas |
| `--simulate-only`, `--gas-limit`, `--max-fee-per-gas`, `--max-priority-fee-per-gas`, `--timeout`, `--trace`, `--spec`, `--multi-send-call-only`, `--no-confirm` | As for `send` |

### `safe wallet`

Manage HD wallets: the encrypted phrase that one-time owner keys are derived from, and the record of which keys are used.

```bash
safe wallet new <name>                        # new 24-word phrase, shown once
safe wallet import <name> [--phrase-file F] [--start-index N]
safe wallet list
safe wallet address --hd-wallet <name> [--index N]
safe wallet status  --hd-wallet <name> [--safe 0xYourSafe]
safe wallet sync    --hd-wallet <name> --safe 0xYourSafe --rpc-url $ETH_RPC_URL [--from-block N]
safe wallet sweep   --hd-wallet <name> --safe 0xYourSafe --rpc-url $ETH_RPC_URL
```

`address`, `status`, `sync` and `sweep` take `--ledger` in place of `--hd-wallet <name>`; `new` and `import` are for phrases only.

| Command | What it does |
|---------|--------------|
| `new` | Creates a phrase, prints it once, and writes the keystore |
| `import` | Encrypts an existing BIP-39 phrase. `--start-index` skips keys another wallet already used |
| `address` | Prints the funding address (no password needed), or owner key `--index N` |
| `status` | Shows, per Safe, the current owner key (the address to send gas money to), whether it is exposed, and any pending transaction or owed sweep |
| `sync` | Rebuilds the record of used keys for a Safe from the chain |
| `sweep` | Moves ETH left on a Safe's retired owner keys to its current owner |

### Wallet Options

Commands that sign with a single key, and `safe info` when it derives the Safe address from the signer, support:

| Flag | Description |
|------|-------------|
| `--private-key <key>` | Private key (hex) |
| `--keystore <path>` | Keystore file (Web3 Secret Storage v3, as written by `cast wallet import`) |
| `-i, --interactive` | Prompt for private key securely |
| `PRIVATE_KEY` env var | Environment variable |

A keystore or HD wallet password is read from `--password-file <path>`, then `--password <text>` (visible in the process list; avoid it), then a prompt.

## One-time owner keys

A Safe's address is safe to publish, and so is an owner's *address*. An owner's *public key* is not published until that owner signs something: a signature reveals it. If ECDSA weakens, whether through quantum computers or better mathematics, a published public key is what an attacker works from.

So the rule is: an owner key signs once. Every transaction ends by swapping the signing owner for a key that has never signed, and the old key is no longer an owner by the time its signature is on chain.

```
Safe transaction = your calls + swapOwner(prev, current owner, next owner)
```

This assumes ECDSA is weakened, not broken instantly: while a transaction waits in a public mempool its signature is visible and the key is still the owner. A private RPC shortens that.

### How it works

- **One phrase, many keys.** `safe wallet new` creates a BIP-39 phrase. Keys come from the standard path `m/44'/60'/0'/0/i`: index 0 is the *funding key*, indices 1 and up are owner keys, each used for one transaction.
- **The swap is part of the transaction.** `send --rotate` appends `swapOwner` to your calls and sends them through `MultiSendCallOnly` with `safeTxGas = 0`, so the calls and the rotation succeed or fail together. The simulation checks that the Safe's owner list afterwards is exactly the planned one.
- **Gas money follows the owner.** The owner key pays for its one transaction. Right after the rotation, its remaining ETH is sent to the new owner, so the ETH always sits on a key whose public key is unpublished and the next owner is ready to send. Turn this off with `--no-sweep`, or use `--payer-private-key` so owner keys never hold ETH at all.
- **Used keys are remembered.** `~/.safe-rs/state/` records, per chain and Safe, the current owner key, the next one, and every retired one. No key index is handed out twice.
- **Upcoming keys are at hand.** The state also records the addresses of the next keys: 20 ahead when a Safe is set up (created, adopted or synced) and at least 5 ahead after every send. They are a cache: before a key signs, its address is derived (or asked of the device) again and must match, so the wrong phrase or device fails before it signs.

### Getting started

```bash
# 1. A wallet. The phrase is shown once: write it down.
safe wallet new treasury

# 2. Send ETH for gas to the funding address it prints, then create a Safe.
#    The funding key deploys; the Safe's owner is a key that has never signed.
safe create --hd-wallet treasury --rpc-url $ETH_RPC_URL

# 3. Use it. Each send rotates the owner and moves the gas money along.
safe send 0xToken 'transfer(address,uint256)' 0xRecipient 1000000 \
    --safe 0xYourSafe --rpc-url $ETH_RPC_URL --rotate --hd-wallet treasury

# Where things stand, and which address to top up with gas money:
safe wallet status --hd-wallet treasury
```

To move an existing Safe onto a wallet, sign one rotation with its current key:

```bash
safe rotate 0xYourSafe --rpc-url $ETH_RPC_URL --hd-wallet treasury --from-interactive
```

The prompt shows how much ETH the old key holds; all of it moves to the new owner unless you pass `--no-sweep`.

### On a Ledger

Pass `--ledger` instead of `--hd-wallet <name>` to keep the keys on a Ledger. It uses the same path, `m/44'/60'/0'/0/i`, so a Ledger seeded with a phrase has the same keys, and the same state, as that phrase.

```bash
safe wallet address --ledger                  # the funding address (key 0)
safe create --ledger --rpc-url $ETH_RPC_URL   # records the next 20 keys from the device
safe send 0xRecipient --value 1000000000000000000 \
    --safe 0xYourSafe --rpc-url $ETH_RPC_URL --rotate --ledger
```

- **The device is asked for each address once.** Setting up a Safe reads 20 keys ahead and records them; each send tops the record up so at least 5 unused keys stay ahead, and asks the device again only for the keys that sign. Searching for a Safe's owner (when adopting one, or `wallet sync`) looks at 52 keys rather than 1000; pass `--scan-limit` to `wallet sync` to look further.
- **Each send asks for three confirmations** when the owner pays for gas: the Safe transaction, the transaction that submits it, and the transfer that moves the old key's ETH. With `--payer-private-key` it is one. The CLI prints the EIP-712 domain hash to compare before the first prompt.
- **What the device must allow:** the Ethereum app 1.6.0 or later (Safe transactions are signed as EIP-712 typed data and shown as a domain hash and a message hash), and blind signing turned on in its settings, because `execTransaction` calldata cannot be decoded on the device.
- No password is asked for, and `--ledger` takes precedence over `SAFE_HD_WALLET`.

Ledger support is a default feature of the CLI (`cargo install safe-rs-cli --no-default-features` leaves it out). On Linux it uses the system libusb if pkg-config finds it, and builds libusb from source otherwise.

### When something goes wrong

| Situation | What happened | What to do |
|-----------|---------------|------------|
| Simulation fails | Nothing left your machine; the key is unused | Fix the calls and send again |
| The transaction reverts on chain | The owner was **not** rotated, but its signature is public. The signed calls stay executable by anyone until the Safe nonce is used | `safe rotate` right away: it rotates at the same Safe nonce, which voids the old signature |
| No receipt in time, or the broadcast is unclear | Unknown yet. The key is recorded as used | Run any rotating command: it reads the owner list first and picks up from there |
| The rotation landed but the sweep did not | The old key still holds the gas ETH. The sweep stays on record until it is done, however many rotations follow | The next rotating command sweeps first, or run `safe wallet sweep` |
| The state directory is lost | The phrase still derives every key | `safe wallet sync` for every Safe and chain the phrase was used with |

`safe wallet sync` finds the current owner by deriving keys and comparing them with the Safe's owner list, and treats every wallet address that has sent a transaction on that chain as used. With `--from-block` (the Safe's deployment block or earlier) it also reads the Safe's owner events, which restores the history and finds keys that never paid for gas. It then leaves a margin of unused indices.

### Limits

- **Threshold 1 only.** In a 1-of-N Safe only the signing owner rotates. N-of-M signature collection is not supported.
- **Safe v1.4.1 and v1.5.0.** Other versions are refused.
- **Sync every Safe.** After losing state, a key retired on a Safe or chain you did not sync could be handed out again. A phrase imported from another wallet may have keys that already signed: use `--start-index`, or better, a phrase from `safe wallet new`.
- **Never export the account's extended public key (xpub).** The derivation is not hardened: with the xpub, one recovered key yields all the others. safe-rs never writes it anywhere.
- **The same Safe on several chains** starts with the same owner key on each. Rotating on one chain publishes the key that still owns the others: `safe wallet status` flags them, and each needs a `safe rotate`. An address where the Safe is *not* deployed can be claimed by whoever holds that first key, forever, because anyone may deploy it.
- **The sweep is a second transaction.** For about one block the gas ETH sits on the retired key. On Optimism and Base it leaves a little ETH behind to cover the L1 data fee.
- **Fund index 0 only right before `safe create`.** Its public key is published by the deployment; top up the current owner (`safe wallet status`) instead.

### Files on disk

Under `~/.safe-rs` (or `$SAFE_RS_HOME`), all readable by you only:

| File | Contents |
|------|----------|
| `wallets/<name>.json` | The phrase, encrypted with your password |
| `state/<funding address>.json` | Addresses and key indices: which key owns which Safe, and the addresses of the next keys. No secrets |

The keystore is Web3 Secret Storage v3, the format geth and Foundry use, with the `x-ethers` field ethers.js defines for a phrase. Foundry and geth open it as an ordinary keystore for the funding key (`cast wallet address --keystore ~/.safe-rs/wallets/<name>.json`); ethers.js and safe-rs also recover the phrase.

It is password → scrypt (N = 2^18) → AES-128-CTR for the funding key and AES-256-CTR for the phrase, with a keccak256 MAC. All of it is symmetric cryptography, which quantum computers do not break the way they break signatures (NIST puts AES-128 in its lowest post-quantum category, AES-256 in its highest). What protects the file in practice is the password: choose a long one.

## Library API

### Connecting to a Safe

```rust
use safe_rs::Safe;

// Auto-detect chain configuration
let safe = Safe::connect(provider, signer, safe_address).await?;

// Verify single-owner requirement
safe.verify_single_owner().await?;
```

`Safe::connect` reads the chain ID and the Safe's version, and batches through the canonical MultiSend contracts for that version (v1.4.1's if the version cannot be read). `Safe::new` takes a `ChainConfig` and uses its addresses as given, as does `RotationConfig`; `ChainConfig::new` is v1.4.1. `detect_addresses` does the lookup `Safe::connect` does, for a configuration you build yourself.

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

Two or more calls are sent through the MultiSend contract in the Safe's `ChainConfig`. `prepare()`, `simulate()` and `execute()` fail with `Error::MultiSendNotDeployed` before signing if that address has no code: the Safe's DELEGATECALL to it would report success without running any of the calls.

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

### One-Time Owner Keys

With the `hd-wallet` feature, `RotatingSafe` sends every transaction as your calls plus an owner swap, and keeps the record of used keys in a state file:

```toml
[dependencies]
safe-rs = { version = "0.12", features = ["hd-wallet"] }
```

```rust
use safe_rs::rotation::{RotatingSafe, RotationStatus};
use safe_rs::{Call, HdWallet};

let wallet = HdWallet::from_keystore_json(&keystore_json, password)?;
// Reads the owner list and locks the state file until `safe` is dropped.
let mut safe = RotatingSafe::open(provider, safe_address, wallet, state_path).await?;

let outcome = safe.execute(&[Call::new(recipient, amount, Bytes::new())]).await?;
assert_eq!(outcome.status, RotationStatus::Rotated);
println!("new owner: {:?}", safe.binding()?.current);
```

`execute` is `prepare` (reserve the next key, sign, simulate, check the resulting owner list) followed by `submit` (record the signed transaction, broadcast, read the owner list at the receipt's block, sweep). Call them separately to inspect a transaction before it leaves the process; `rotate()` sends a swap with no other calls, and `sync()` rebuilds the state from the chain. `RotationConfig` sets a separate payer, the sweep, and a legacy owner key for moving an existing Safe onto the wallet.

Owner keys come from a `KeySource`: `HdWallet` (the default type parameter of `RotatingSafe`) or, with the `ledger` feature, `LedgerKeys`. A `KeySource` only derives addresses and signs; a `Keyring` pairs one with its state file, records the addresses it is told about, looks ahead, and checks a key's address again before it signs:

```rust
use safe_rs::rotation::{KeySource, RotatingSafe, RotationConfig, StateFile};
use safe_rs::LedgerKeys;

let keys = LedgerKeys::connect().await?;
let store = StateFile::open(state_path, keys.address(0).await?)?;
// A Ledger is searched for 52 keys rather than 1000: it answers one at a time.
let mut safe =
    RotatingSafe::open_with(provider, safe_address, keys, store, RotationConfig::default()).await?;
safe.rotate().await?; // confirm on the device
```

Calls sent with the swap are batched through `RotationConfig::addresses.multi_send_call_only`. `prepare` fails with `Error::MultiSendNotDeployed` before signing if that address has no code; a rotation with no other calls is a direct call to the Safe and needs no batch contract.

Without the feature, `safe_rs::rotation` still has the parts that need no key material: `plan_rotation` builds the Safe transaction for any `(old owner, new owner)` pair, `check_post_state` verifies it against a simulation, and `RotationState` tracks used keys.

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

## Supported Chains and Versions

safe-rs supports Safe v1.5.0 (default) and v1.4.1. Specify the version with `safe create --safe-version 1.5.0` or `--safe-version 1.4.1`. The CLI defaults to v1.5.0.

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

All chains use the same contract addresses (deployed via CREATE2). A Safe's batches go through the MultiSend contracts of its own version:

**Safe v1.5.0:**

| Contract | Address |
|----------|---------|
| Safe Singleton | `0xFf51A5898e281Db6DfC7855790607438dF2ca44b` |
| MultiSend | `0x218543288004CD07832472D464648173c77D7eB7` |
| MultiSendCallOnly | `0xA83c336B20401Af773B6219BA5027174338D1836` |
| Proxy Factory | `0x14F2982D601c9458F93bd70B218933A6f8165e7b` |
| Fallback Handler | `0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4` |

**Safe v1.4.1:**

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
| `SAFE_ADDRESS` | Safe address for `send` and `call` |
| `PRIVATE_KEY` | Signer private key |
| `SAFE_PAYER_PRIVATE_KEY` | Key that pays for gas instead of the owner key |
| `SAFE_HD_WALLET` | Default `--hd-wallet` (`--ledger` overrides it) |
| `SAFE_PASSWORD_FILE` | Default `--password-file` |
| `SAFE_RS_HOME` | Where HD wallets and their state are stored (default `~/.safe-rs`) |

## Examples

See the [`examples/`](./examples) directory:

- `simple_transfer.rs` — Single ERC20 transfer
- `multicall_erc20.rs` — Batch multiple operations
- `simulation_only.rs` — Simulation without execution
- `rotating_transfer.rs` — Send ETH and rotate the owner key (`--features hd-wallet`)

Run examples:
```bash
cargo run --example simple_transfer
```

## Why safe-rs?

**vs Safe Transaction Service API:** safe-rs executes transactions directly on-chain without relying on Safe's infrastructure. No API keys, no rate limits, no external dependencies.

**vs ethers/alloy directly:** safe-rs handles the complexity of Safe transaction encoding, EIP-712 signing, gas estimation, and multicall batching. You focus on what you want to do, not how Safe works internally.

**vs multi-owner Safes:** If you need multiple signers, use the Safe web interface or Transaction Service. safe-rs is intentionally limited to threshold-1 Safes for simplicity and reliability.

## License

MIT

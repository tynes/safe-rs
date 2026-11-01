# safe-rs

A Rust library and CLI for interacting with [Safe](https://safe.global) smart accounts.
Built for owners who sign and execute their own Safe transactions, alone or with co-owners, with a focus on simplicity, safety, and developer experience.

## Philosophy

**Opinionated by design.** safe-rs optimizes for an opinionated usecase: owners who want to execute Safe transactions with confidence. A threshold-1 Safe signs and executes in one command; a Safe that needs more signatures collects them in a bundle file or on chain, with no Safe infrastructure in between. Rather than supporting every Safe configuration, it provides a streamlined experience with compile-time guarantees and optional forking simulation.

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
- **Multi-owner Safes** — For a threshold above 1, owners sign into a bundle file or approve the hash on chain (`approveHash`), and whoever completes the threshold executes ([details](#multi-owner-safes))
- **One-time owner keys** — `send --rotate` swaps the Safe's owner for a fresh key in the same transaction, with the keys derived from one encrypted phrase ([details](#one-time-owner-keys))

## Installation

safe-rs ships as two crates, so a library user never compiles the CLI's dependencies and a CLI user never needs a Rust project.

### CLI

The `safe-rs-cli` crate installs the `safe` binary:

```bash
cargo install safe-rs-cli --locked
```

Ledger support and one-time owner keys are on by default. Leave out the Ledger, and with it the libusb build, but keep `--rotate`, `safe rotate` and `safe wallet`, with:

```bash
cargo install safe-rs-cli --locked --no-default-features --features hd-wallet
```

Or build only the plain commands (`send`, `call`, `info`, `approvals`, `config` and `create` with `--private-key`, `--keystore` or `--interactive`), without the HD wallet code and its BIP-32/39 dependencies:

```bash
cargo install safe-rs-cli --locked --no-default-features
```

| CLI feature | Default | Adds |
|-------------|---------|------|
| `hd-wallet` | yes | `--rotate`, `--hd-wallet`, `safe rotate`, `safe wallet` and `safe create --rotate` |
| `ledger` | yes | `--ledger`: sign with a Ledger key, or with `--rotate` take the owner keys from one (implies `hd-wallet`) |

Or from a local clone:

```bash
cargo install --path cli --locked
```

### Library

```toml
[dependencies]
safe-rs = "0.13"
```

| Feature | Default | Adds |
|---------|---------|------|
| `simulation` | yes | Fork simulation with revm: `simulate()` on the builders, `ForkSession`, `simulate_exec*` |
| `keystore` | no | Decrypting password-encrypted (V3) keystores: `keystore::decrypt_keystore` |
| `hd-wallet` | no | Encrypted mnemonic keystores, HD keys and `RotatingSafe` (implies `simulation` and `keystore`) |
| `ledger` | no | Owner keys on a Ledger (implies `hd-wallet`) |

To build, sign and execute Safe transactions without compiling revm, turn off the default features. The builders still execute, with gas estimated over RPC, so a reverting call fails before anything is broadcast:

```toml
[dependencies]
safe-rs = { version = "0.13", default-features = false }
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
safe create --rotate --hd-wallet treasury --rpc-url $ETH_RPC_URL
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

**Choosing the Safe:** `--safe` (or `SAFE_ADDRESS`) is optional. Without it, `send` and `call` use the signer's default Safe, the same 1:1 Safe that `safe info` finds: the one `safe create` deploys for that key without options. The CLI checks that a Safe is deployed at that deterministic address, v1.5.0 first and then v1.4.1, and fails if neither has code. When `send` continues a bundle that already holds a prepared transaction, the bundle's Safe is used, so co-signers need no `--safe`. With `--rotate`, and in `wallet sync` and `wallet sweep`, the default is the HD wallet's only recorded Safe on the connected chain.

**Amounts:** `--value`, `--sweep-reserve`, `--max-fee-per-gas` and `--max-priority-fee-per-gas` accept amounts in the same forms as cast. A plain number is wei, in decimal or `0x` hex. A number with a unit is converted, such as `1ether`, `0.5 ether`, `10gwei` or `1e18`.

```bash
safe send 0xRecipient --value 0.5ether --rpc-url $ETH_RPC_URL --private-key $PRIVATE_KEY
```

**From your own account:** `--send-eoa` sends the calls from the signer's own address instead of a Safe, one transaction per call. They are simulated together in order first, and nothing is sent unless all of them pass; after one confirmation they are broadcast one at a time, each after the one before it is mined. Simulation, the fee flags, `--timeout`, `--trace`, `--block`, `--spec` and `--no-confirm` work as for a Safe, and `--gas-limit` works with a single call. `--safe` (or `SAFE_ADDRESS`) and the options only a Safe has, such as `--bundle`, `--nonce`, `--no-submit`, `--rotate` and `--payer-private-key`, are refused. A send of several calls is not atomic: if one fails after others were mined, the error lists the ones on chain.

```bash
safe send 0xRecipient --value 0.5ether --send-eoa --rpc-url $ETH_RPC_URL --private-key $PRIVATE_KEY
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
| `--send-eoa` | Send each call from the signer's own account instead of a Safe (see above) |
| `--simulate-only` | Simulate without signing or broadcasting |
| `--skip-simulation` | Skip simulation (outer gas from `eth_estimateGas`) |
| `--call-only` | Use MultiSendCallOnly (no delegatecall) |
| `--nonce <n>` | Safe nonce to sign for; fails if the on-chain nonce differs |
| `--safe-tx-gas <n>` | Explicit `safeTxGas` (default 0; non-zero lets a failed inner call consume the nonce) |
| `--gas-limit <n>` | Outer gas limit (default: simulated gas + 20%) |
| `--max-fee-per-gas <wei>` / `--max-priority-fee-per-gas <wei>` | Override the node's fee estimate (units accepted, such as `30gwei`) |
| `--raw-out <path\|->` | Write the signed transaction as JSON before broadcasting (`-` = stdout; progress then goes to stderr) |
| `--no-submit` | Sign but don't broadcast (implies `--raw-out -` unless set) |
| `--timeout <secs>` | How long to wait for the receipt (default 120) |
| `--trace` | Print call traces of the simulation |
| `--block <n\|hash\|tag>` | Simulate on top of this block (default: latest) |
| `--spec <cancun\|prague\|osaka\|amsterdam>` | EVM spec for simulation (default: the fork active at the simulated block on mainnet, Sepolia, Holesky and Hoodi; osaka elsewhere) |
| `--multi-send <addr>` / `--multi-send-call-only <addr>` | MultiSend contracts to batch through (default: the canonical ones for the Safe's version) |
| `--no-confirm` | Skip confirmation prompt |
| `--json` | Output as JSON |
| `-i, --interactive` | Prompt for private key |
| `--payer-private-key <key>` | A different key sends the outer transaction and pays for gas |
| `--bundle <path>` | Read the calls, and any signatures collected so far, from a [bundle file](#bundle-format); below the threshold, save this owner's signature to it (see [Multi-owner Safes](#multi-owner-safes)) |
| `--merge-bundle <path>` | Add the signatures from another bundle of the same Safe transaction (repeatable) |
| `--sign-only` | Sign into `--bundle` and stop, even when the threshold is met |
| `--approve-hash` | Approve the Safe transaction hash on chain (`approveHash`) instead of executing |
| `--rotate` | Swap the owner for the next unused key of `--hd-wallet` in the same transaction (see [One-time owner keys](#one-time-owner-keys)) |
| `--hd-wallet <name\|path>` | The HD wallet the owner keys come from (with `--rotate`) |
| `--ledger` | With `--rotate`: take the owner keys from a connected Ledger instead (see [On a Ledger](#on-a-ledger)). Without it, `--ledger [index]` signs with that Ledger key (see [Wallet Options](#wallet-options)) |
| `--no-sweep` | With `--rotate`: leave the old owner's ETH where it is |
| `--sweep-reserve <wei>` | With `--rotate`: wei to leave on the old owner when sweeping |

`--rotate` cannot be combined with `--skip-simulation`, `--safe-tx-gas`, `--nonce` or `--multi-send`: the rotation has to succeed or fail together with the calls, and its result is checked in simulation.

Two or more calls go through a MultiSend contract: by default the canonical one for the Safe's version (v1.5.0 for a v1.5.0 Safe, v1.4.1 for any other), with or without `--rotate`. Pass another with `--multi-send` or `--multi-send-call-only`. A Safe sent a batch through an address without code reports success while none of the calls ran, so if the contract has no code on the chain (at `--block`, when simulating from one) the command stops before signing anything and names the address. That holds with `--rotate` too, where the calls and the owner swap are the batch.

The `--raw-out` document contains `chain_id`, `safe`, `safe_nonce`, `safe_tx_hash`, the Safe transaction fields (`safe_tx`), the owner `signer` and `signature` (with several owners, `signature` packs all of them sorted by owner address, and `signer` is the first), the outer transaction fields (`outer`), the EIP-2718 `raw` bytes and their `tx_hash`. `raw` can be rebroadcast as is with `cast publish`. With `--rotate` it also has a `rotation` object naming the old and new owner, the payer and the planned sweep.

A broadcast the node rejects, a broadcast with an unclear result, a receipt that doesn't arrive in time, and a Safe transaction without `ExecutionSuccess` all exit non-zero with the transaction hash.

### Multi-owner Safes

When the Safe's threshold is above 1, `send` signs with your key and counts it with the signatures already collected: the ones in `--bundle` and `--merge-bundle`, and the approvals owners have made on chain with `approveHash`. Below the threshold it saves your signature to `--bundle` and stops, with nothing broadcast (without `--bundle` or `--approve-hash`, it stops with an error). Once the threshold is met it executes. The simulation runs first either way, with the missing owners' approvals filled in on the fork, so the calls are checked before everyone has signed.

```bash
# Owner 1 prepares the transaction and signs it into tx.json (1/2)
safe send 0xRecipient --value 1000000000000000000 \
    --safe 0xYourSafe --rpc-url $ETH_RPC_URL --private-key $OWNER1_KEY \
    --bundle tx.json

# Owner 2 adds a signature (2/2) and executes
safe send --bundle tx.json --safe 0xYourSafe --rpc-url $ETH_RPC_URL --private-key $OWNER2_KEY
```

The first run writes the Safe transaction to the file, and every later run signs that transaction. Owners can also sign the same calls independently, each into a file of their own, with `--sign-only` so that nobody executes. Then anyone, an owner or a key that only pays for gas, merges the files and executes:

```bash
safe send --bundle owner1.json --merge-bundle owner2.json \
    --safe 0xYourSafe --rpc-url $ETH_RPC_URL --payer-private-key $PAYER_KEY
```

Files merge only if they hold the same Safe transaction: the same calls, options and Safe nonce.

To approve on chain instead, `--approve-hash` sends `approveHash(safeTxHash)` from your owner key, which pays its gas. Later runs find on-chain approvals by themselves: another owner who sends the same calls at the same Safe nonce counts yours and can execute. With `--bundle` the transaction is written to the file as well, so the others don't have to repeat the calls.

`safe rotate` and `send --rotate` take the same flags; see [Limits](#limits) for what rotates.

### `safe call`

Simulate a call made by the Safe without executing it. It runs in the block after `--block` (default: latest), with that block's timestamp and base fee. It is useful for testing and gas estimation.

```bash
safe call <to> <signature> [args...] --safe <address> --rpc-url <url> [--block <n>] [--trace]
```

Without `--safe`, pass `--private-key`, `--keystore` or `--interactive` to call from the signer's default Safe, as `send` does.

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
Implementation (singleton): 0x41675C099F32341bf84BFc5382aF534df5C7461a
Balance: 1.250000000000000000 ETH
Nonce: 42
Threshold: 1
Owners:
  1: 0xOwner1
Modules: none
Guard: none
Fallback Handler: 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99
```

A v1.5.0 Safe also shows its `Module Guard` (`module_guard` in `--json`). `--json` gives the balance in wei.

### `safe approvals`

Show how far a Safe transaction is from execution, without scanning logs: for each current owner it reads `approvedHashes(owner, safeTxHash)` at one block (`--block`, default: latest).

```bash
safe approvals <safeTxHash> --safe <address> --rpc-url <url> [--block <n|hash|tag>]

# Take the hash and Safe from a bundle, and count its offchain signatures too
safe approvals --bundle tx.json --rpc-url $ETH_RPC_URL
```

Without `--safe` or `--bundle`, pass a key to use the signer's default Safe, as `send` does.

Output:
```
Safe: 0xYourSafe
Block: 21000000 (0x...)
SafeTxHash: 0x...
Safe nonce: 7
Approvals: 1 / 2 threshold
Approved on-chain:
  0xOwner1
Pending:
  0xOwner2
Status: one approval short (a pending owner can execute it directly)
```

Only current owners count, as in `execTransaction`. Safe 1.3 and later never clear `approvedHashes`, so a transaction that has already executed still shows its approvals. With `--bundle` the command also compares the transaction's nonce with the Safe's and reports when the nonce is used (`nonce_used` in `--json`).

### `safe config`

Change the Safe's own configuration: owners, threshold, modules, transaction guard, module guard and fallback handler. Every change given in one run goes into a single Safe transaction, so co-owners sign once.

```bash
# Add an owner and require two signatures
safe config --add-owner 0xNewOwner --threshold 2 --safe 0xYourSafe

# Replace an owner in place, and install a guard
safe config --swap-owner 0xOldOwner:0xNewOwner --guard 0xGuard

# Remove a module and the guard (the zero address clears a setting)
safe config --disable-module 0xModule --guard 0x0000000000000000000000000000000000000000
```

| Option | Description |
|--------|-------------|
| `--add-owner <addr>` | Add an owner (repeatable). New owners go to the head of the owner list |
| `--remove-owner <addr>` | Remove an owner (repeatable) |
| `--swap-owner <old>:<new>` | Replace an owner in its place in the list (repeatable) |
| `--threshold <n>` | Threshold after the change (default: unchanged) |
| `--enable-module <addr>` | Enable a module (repeatable) |
| `--disable-module <addr>` | Disable a module (repeatable) |
| `--guard <addr>` | Set the transaction guard; the zero address removes it |
| `--fallback-handler <addr>` | Set the fallback handler; the zero address removes it |
| `--module-guard <addr>` | Set the module guard (Safe v1.5.0 only); the zero address removes it |
| `--allow-unchecked-guard` | Install a new guard or module guard even if the follow-up check below fails, or with `--skip-simulation` |

The `prevOwner` and `prevModule` arguments of the Safe's linked lists are worked out for you, including when one change moves the entry another depends on. The calls always run in this order: owner swaps, additions, removals, `changeThreshold`, module enables, disables, fallback handler, module guard, and the transaction guard last.

The threshold is never lowered unless you pass `--threshold`. A change that would leave fewer owners than the current threshold is refused and asks for one. Also refused, before anything is signed: an address named in two changes, adding an existing owner, removing or swapping out a non-owner, enabling an enabled module or disabling one that isn't enabled, a module guard on a Safe before v1.5.0, and a request that changes nothing.

After simulating, `config` reads the Safe back from the simulated state and checks that every owner (in list order), the threshold, the modules, the guards and the fallback handler match the plan. Several changes go through MultiSendCallOnly (`--multi-send-call-only` to override), never through a DELEGATECALL MultiSend.

The transaction that installs a guard is not checked by that guard, so its simulation says nothing about whether the guard lets anything through afterwards. A guard whose `checkTransaction` or `checkAfterExecution` always reverts would block every later Safe transaction, including the one that removes it, and lock the Safe for good. So when `--guard` sets a non-zero guard, `config` also simulates a trivial follow-up on the simulated post-state: a zero-value call from the Safe to itself at the next nonce, approved by the owners and threshold after the change. If the guard rejects it, `config` refuses to sign and says why. `--skip-simulation` with a new guard is refused too. `--allow-unchecked-guard` overrides both.

`--module-guard` (v1.5.0) gets the same check through `execTransactionFromModule`, sent by the first module enabled after the change. A module guard that rejects every module transaction cannot lock the owners out, because `execTransaction` does not go through it, but it does stop every module until the owners replace it. When no module is enabled after the change there is no module to send the follow-up from, so the module guard is not checked.

The follow-up proves that the guard lets a self-call through at the next nonce in the simulated block. It does not prove the guard will allow other calls, or the same call later. A guard that depends on time, targets or calldata can still lock the Safe in ways one follow-up cannot catch.

The signing, bundle, simulation and gas options are those of `safe send` (`--bundle`, `--merge-bundle`, `--approve-hash`, `--sign-only`, `--simulate-only`, `--no-submit`, `--raw-out`, `--nonce`, fees and so on). `--safe-tx-gas` and `--rotate` are not offered: config changes are always fail-closed, and a config change cannot also rotate the signer. `--hd-wallet` is refused for the same reason as in `send` without `--rotate`; `--ledger [index]` signs with that Ledger key, like `--private-key`.

On a multi-owner Safe, the first owner plans the change into a bundle. Co-owners then sign what is in the bundle instead of planning again, because `prevOwner` depends on the chain state the plan was made against:

```bash
# Owner 1 plans and signs (1/2)
safe config --add-owner 0xNewOwner --threshold 3 --bundle config.json --safe 0xYourSafe --private-key $OWNER1_KEY

# Owner 2 signs the planned change and executes (2/2)
safe config --bundle config.json --private-key $OWNER2_KEY
```

`safe send --bundle config.json` works for co-owners too. A co-owner signing from the bundle gets the simulation and the Safe's own checks, but not the read-back of the planned configuration or the guard follow-up check: only the run that planned the change knows what to expect.

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

With `--rotate --hd-wallet <name>` (or `--rotate --ledger`) the Safe's first owner is a wallet key that has never signed anything: the wallet's funding key sends the deployment, then its remaining ETH moves to the owner (`--no-sweep` to skip). `--owner` and `--threshold` add co-owners, and `--safe-version` applies as usual. `--same-as <chain_id>:<safe>` deploys the same Safe on another chain, with the version, contracts, owners and threshold it was first created with.

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
| `--bundle`, `--merge-bundle`, `--sign-only`, `--approve-hash` | Collect the co-owners' signatures, as for `send` (see [Multi-owner Safes](#multi-owner-safes)) |
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

Commands that sign with a single key, and `safe info` and `safe call` when they derive the Safe address from the signer, support:

| Flag | Description |
|------|-------------|
| `--private-key <key>` | Private key (hex) |
| `--keystore <path>` | Keystore file (Web3 Secret Storage v3, as written by `cast wallet import`) |
| `-i, --interactive` | Prompt for private key securely |
| `--hd-key <wallet>[:<index>]` | The key at `m/44'/60'/0'/0/<index>` (default 0) of an HD wallet: a name under `~/.safe-rs/wallets` or a keystore path |
| `--ledger [index]` | The key at `m/44'/60'/0'/0/<index>` (default 0) of a connected Ledger (Ethereum app open). With `--rotate` (`send`, `create`) the Ledger gives the rotating owner keys instead |
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
safe create --rotate --hd-wallet treasury --rpc-url $ETH_RPC_URL

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

Pass `--ledger` instead of `--hd-wallet <name>` to keep the rotating keys on a Ledger (with `--rotate` on `send` and `create`, and on `safe rotate` and `safe wallet`; elsewhere `--ledger [index]` just signs with that key). It uses the same path, `m/44'/60'/0'/0/i`, so a Ledger seeded with a phrase has the same keys, and the same state, as that phrase.

```bash
safe wallet address --ledger                  # the funding address (key 0)
safe create --rotate --ledger --rpc-url $ETH_RPC_URL   # records the next 20 keys from the device
safe send 0xRecipient --value 1000000000000000000 \
    --safe 0xYourSafe --rpc-url $ETH_RPC_URL --rotate --ledger
```

- **The device is asked for each address once.** Setting up a Safe reads 20 keys ahead and records them; each send tops the record up so at least 5 unused keys stay ahead, and asks the device again only for the keys that sign. Searching for a Safe's owner (when adopting one, or `wallet sync`) looks at 52 keys rather than 1000; pass `--scan-limit` to `wallet sync` to look further.
- **Each send asks for three confirmations** when the owner pays for gas: the Safe transaction, the transaction that submits it, and the transfer that moves the old key's ETH. With `--payer-private-key` it is one. The CLI prints the EIP-712 domain hash to compare before the first prompt.
- **What the device must allow:** the Ethereum app 1.6.0 or later (Safe transactions are signed as EIP-712 typed data and shown as a domain hash and a message hash), and blind signing turned on in its settings, because `execTransaction` calldata cannot be decoded on the device.
- No password is asked for, and `--ledger` takes precedence over `SAFE_HD_WALLET`.

Ledger support is a default feature of the CLI (`cargo install safe-rs-cli --locked --no-default-features --features hd-wallet` leaves it out). On Linux it uses the system libusb if pkg-config finds it, and builds libusb from source otherwise.

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

- **Only the wallet's key rotates.** In a Safe with co-owners, the wallet's owner key is swapped and the co-owners keep theirs. They sign the bundle with `safe send --bundle <file> --sign-only` (no `--rotate`) and the wallet's next run executes it, or they approve on chain. Either way their public keys are published.
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
| `config.toml` | Defaults for flags, optional (below) |

`config.toml` holds defaults that `safe` and any CLI embedding it read. A flag or its environment variable always wins, and `keystore` / `hd_key` are used only when no other signer is given. Unknown keys are an error. Private keys and passwords never go here.

```toml
rpc_url = "https://polygon.drpc.org"   # --rpc-url, ETH_RPC_URL
safe = "0x…"                           # --safe, SAFE_ADDRESS
hd_wallet = "treasury"                 # --hd-wallet, SAFE_HD_WALLET
password_file = "/home/me/.safe-rs/pw" # --password-file, SAFE_PASSWORD_FILE
keystore = "/home/me/.foundry/keystores/me"   # --keystore
hd_key = "treasury:3"                  # --hd-key
```

A CLI that embeds the commands applies it to its own command tree before parsing: `ConfigFile::load()?.apply(command)`.

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

`verify_single_owner` checks that the signer is an owner and the threshold is 1, which `execute()` needs. `verify_owner` checks only ownership and returns the owners and threshold (see [Multi-Owner Signatures](#multi-owner-signatures)).

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

Simulation runs the transaction against a fork of the current blockchain state. It needs the `simulation` feature, which is on by default:

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

`ForkSession` simulates `SimTx::from_outer(&outer.params, TxChecks::STRICT)` in the next block before you broadcast. `read_safe_state` returns a block-pinned snapshot of owners, threshold, nonce, modules, guard, fallback handler and (on v1.5.0) module guard. `plan_config` turns a `ConfigChanges` into the self-calls that make them and the configuration expected afterwards, which `check_config_post_state` compares against a simulated post-state.

### Multi-Owner Signatures

`execute()` signs with the one key the `Safe` was connected with, so it needs a threshold-1 Safe. `simulate()` works at any threshold: it fills in the missing owners' approvals on the fork. For a higher threshold, collect the signatures on a frozen transaction:

```rust
use safe_rs::{read_approved_owners, OuterTxParams, SignedSafeTx};

let (owners, threshold) = safe.verify_owner().await?;
let prepared = safe.batch().add_typed(token, call).prepare().await?;

// Each owner signs the same transaction; a signature must recover to its owner
let mut signed = SignedSafeTx::empty(prepared.clone());
for owner in &owner_signers {
    let sig = prepared.sign(owner).await?;
    signed.insert_signature(owner.address(), sig.signature().unwrap().clone())?;
}
// Owners that called approveHash(safe_tx_hash) on chain count without a signature
for owner in read_approved_owners(&provider, safe_address, &owners, prepared.safe_tx_hash, block).await? {
    signed.add_prevalidated(owner);
}

let params = OuterTxParams::exec_transaction(&signed, payer.address(), eoa_nonce, gas_limit, fees);
// then sign_outer_tx and broadcast_raw, as above
```

`recover_signer` checks a signature that arrives from elsewhere. `OuterTxParams::approve_hash` builds an owner's on-chain approval. With the `simulation` feature, `simulate_exec_with_threshold` simulates the transaction before every owner has signed, and `simulate_approve_hash` simulates the approval. `RotatingSafe::prepare` takes the co-owners' signatures in `ExecOptions::co_signatures` and reports `signatures_collected` and `threshold` on the result. Below the threshold, `arm`, `submit` and `execute` return `Error::InsufficientSignatures` before anything is broadcast, so the owner key is not exposed; an `approve_hash` transaction is not held to the threshold.

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
safe-rs = { version = "0.13", features = ["hd-wallet"] }
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

## Reusing the send flags in your own CLI

An app-specific CLI can build its own calls with safe-rs and send them the way `safe send` does. It gets the same options and behavior: simulation, gas and fees, `--nonce`, `--bundle` signature collection, `--sign-only`, `--raw-out`, `--timeout`, confirmation, `--payer-private-key` and `--rotate`. The `safe-rs-cli` crate is also a library:

- Flatten its `SendOpts` into your clap command.
- Resolve the RPC URL, the signer and the Safe yourself, into a `SendContext`. `SendOpts` leaves out `--rpc-url`, `--safe` and the wallet flags, so your CLI's own flags and environment variables for those keep their meaning.
- Call `send`. It returns how the send ended.

```toml
[dependencies]
# Without default features to skip the HD wallet code and the libusb build;
# add `features = ["hd-wallet"]` for --rotate, or `["ledger"]` for --ledger too.
safe-rs-cli = { version = "0.13", default-features = false }
clap = { version = "4", features = ["derive", "env"] }
```

```rust
use clap::Parser;
use safe_rs_cli::args::SendOpts;
use safe_rs_cli::safe_rs::{Address, Call, U256};
use safe_rs_cli::log::{ConsoleLogger, Level};
use safe_rs_cli::{PrivateKeySigner, SendContext, SendError, SendOutcome, Url};

#[derive(Parser)]
struct Deposit {
    #[arg(long, env = "MYAPP_RPC_URL")]
    rpc_url: Url,

    #[arg(long, env = "MYAPP_PRIVATE_KEY")]
    private_key: PrivateKeySigner,

    #[arg(long)]
    amount: U256,

    #[command(flatten)]
    send: SendOpts,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let deposit = Deposit::parse();
    let calls: Vec<Call> = build_deposit_calls(deposit.amount);
    let ctx = SendContext::new(deposit.rpc_url, MY_APP_SAFE)
        .with_signer(deposit.private_key)
        .with_logger(ConsoleLogger::new(Level::Info));
    match safe_rs_cli::send(ctx, calls, deposit.send).await {
        Ok(SendOutcome::Executed { tx_hash, .. }) => println!("Deposited in {tx_hash}"),
        Ok(SendOutcome::Aborted { .. }) => println!("Cancelled"),
        Ok(other) => println!("{other:?}"),
        Err(e) if e.may_be_pending() => eprintln!("Not confirmed, check before retrying: {e}"),
        Err(SendError::SimulationFailed { reason }) => eprintln!("Deposit would revert: {reason}"),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
```

**What `send` returns.** A `SendOutcome`:

| Outcome | When |
|---|---|
| `Executed` | The Safe transaction was mined and succeeded. Carries `tx_hash`, `safe_tx_hash`, `gas_used` and `block` |
| `Simulated` | `--simulate-only` |
| `Signed` | The signatures were saved to `--bundle`: `--sign-only`, or below the threshold |
| `HashApproved` | `--approve-hash` |
| `NotSubmitted` | `--no-submit`. Carries the raw signed transaction |
| `Aborted` | The user declined the confirmation prompt |
| `EoaExecuted` | Every call of an EOA send was mined and succeeded. Carries each transaction's `tx_hash`, `gas_used` and `block` |
| `EoaSimulated` | `--simulate-only` for an EOA send |
| `EoaAborted` | The user declined the confirmation prompt of an EOA send |

The enum derives `Serialize` (tagged by `outcome`), so it can go into your own JSON output.

**How `send` fails.** With a `SendError`, a `thiserror` enum you can match on. It converts into an `eyre::Report` (or `anyhow::Error`) with `?`, as in the example above. The variants a host is most likely to handle:

| Error | When |
|---|---|
| `Options` | The options conflict, such as `--rotate` with `--nonce`. Carries an `OptionsError`. Nothing was signed or sent |
| `NoSigner`, `NoCalls` | Nothing to sign with, or nothing to send |
| `SimulationFailed` | The calls revert in simulation. Nothing was signed or sent |
| `BelowThreshold` | Fewer signatures than the threshold, and no `--bundle` to save them to |
| `Broadcast(BroadcastError::Rejected)` | The node refused the signed transaction. Carries the node's reason and its `RejectClass` |
| `Broadcast(BroadcastError::Ambiguous \| ReceiptTimeout)`, `RotationUnconfirmed` | The transaction may still be mined. `SendError::may_be_pending()` is true for these |
| `ApproveHashReverted`, `SafeTxFailed`, `NotRotated` | The transaction was mined and did not succeed |
| `EoaTxReverted` | A transaction of an EOA send was mined and reverted |
| `EoaBatchFailed` | An EOA send stopped part way. Carries the hashes already mined, the index of the call that failed and its error |
| `Safe` | An error from safe-rs, such as `NotOwner` or `NonceMismatch` |
| `Rpc` | An RPC request failed |

Everything else, such as a bundle file that does not parse, is `Other`. The enum is `#[non_exhaustive]`.

**What `send` prints.** Nothing: the library never writes to stdout or stderr, so your CLI owns both.
- Progress and warnings go to the context's `Logger` (`with_logger`). The default, `NoopLogger`, drops them. `ConsoleLogger::new(Level::Info)` writes them to stderr, `log::from_fn(|level, args| ...)` hands them to your own code, and `TracingLogger` (the `tracing` feature) forwards them to `tracing`.
- The confirmation and any password go to the context's `Prompt` (`with_prompt`). The default, `TerminalPrompt`, asks on the terminal and shows the summary first. `NoPrompt` declines every confirmation and refuses every secret, for servers and tests. Set `no_confirm` to send without asking.
- The result is the returned `SendOutcome`, for your CLI to print as it likes.

**Sending from an EOA.** `SendContext::eoa(rpc_url).with_signer(key)` sends the calls from the key's own account instead of a Safe, so an app can offer both with one code path. Each call becomes its own transaction. They are simulated together in order first, and nothing is sent unless all of them pass. After one confirmation they are broadcast one at a time, each after the one before it is mined. Simulation, `--trace`, `--block`, `--spec`, the fee flags, `--timeout` and `--no-confirm` work as for a Safe. `--gas-limit` works when there is a single call. Options only a Safe has, such as `--bundle`, `--nonce`, `--no-submit`, `--rotate` and `--payer-private-key`, fail with `OptionsError::SafeOnly`. An EOA send is not atomic: if one transaction fails after others were mined, `SendError::EoaBatchFailed` lists the ones on chain.

**Building `SendOpts` in code.** `SendOpts::default()` matches the flag defaults. Its flags come in groups that `safe config` and `safe rotate` share, and that you can also flatten one by one: `CollectArgs` (`--bundle`, `--merge-bundle`, `--approve-hash`, `--sign-only`), `SimulateArgs` (`--simulate-only`, `--trace` and the `SimArgs`), `FeeArgs` (`--gas-limit`, the fee flags, `--timeout`) and `RawTxArgs` (`--raw-out`, `--no-submit`). So `--sign-only` is `opts.collect.sign_only` and `--gas-limit` is `opts.fees.gas_limit`. `send` checks options built in code for the same conflicts clap enforces on the flags, such as `--rotate` with `--nonce`.

**Other notes:**
- Use `safe_rs_cli::safe_rs` to build the calls, and `safe_rs_cli::PrivateKeySigner` and `safe_rs_cli::Url` for the context. They come from the same versions the CLI uses.
- Always name the Safe for a Safe send. Without `--safe`, `safe send` falls back to the signer's default Safe, which is wrong for a Safe from another factory, so `SendContext` requires one.
- With `--rotate`, the owner key comes from `--hd-wallet` or `--ledger`, so the context carries no signer.
- The `safe` CLI's own `--rpc-url`, `--safe` and signer flags are in `safe_rs_cli::args` as `RpcArgs`, `SafeArgs` and `SignerArgs` (`WalletArgs` is a deprecated alias), for a CLI that wants those too. `safe_rs_cli::Commands` with `safe_rs_cli::run(command, RunConfig::terminal(json))` embeds the whole `safe` command tree as a subcommand; `RunConfig` picks its logger and prompt.
- `SendOpts` takes these flag names, so your command can't define them too:
  - `--bundle`, `--merge-bundle`, `--approve-hash`, `--sign-only`, `--call-only`
  - `--simulate-only`, `--skip-simulation`, `--trace`, `--block`, `--spec`, `--block-time`
  - `--safe-tx-gas`, `--nonce`, `--gas-limit`, `--max-fee-per-gas`, `--max-priority-fee-per-gas`
  - `--raw-out`, `--no-submit`, `--timeout`, `--no-confirm`
  - `--multi-send`, `--multi-send-call-only`
  - `--rotate`, `--hd-wallet`, `--no-sweep`, `--sweep-reserve`
- `SignerArgs` takes `--private-key`, `--keystore`, `--hd-key`, `--ledger` and `--interactive`. With `--rotate`, the `safe` commands move `--ledger` into `SendOpts::hd` / `CreateOpts::hd` as the source of the rotating keys; set `hd.ledger` yourself when you build the options in code.
  - `--password`, `--password-file`, `--payer-private-key`
- `SendOpts` also reads three environment variables: `SAFE_HD_WALLET`, `SAFE_PASSWORD_FILE` and `SAFE_PAYER_PRIVATE_KEY`.
- To catch a flag-name clash, parse a sample command line in a test. `Command::debug_assert()` alone misses a clash between a global flag and one of these, and clap panics at parse time instead.

**Checking Safe transactions with a host policy.** A host sets a `policy::SafePolicy` with `SendContext::with_policy` or `RunConfig::with_policy`. Before a Safe transaction leaves the machine, whether by broadcast, `--approve-hash`, a bundle, `--sign-only` or `--no-submit`, the CLI calls the policy's `check` and then its `check_async`. `--simulate-only` runs them too. If either returns `false`, the CLI stops with `SendError::PolicyRefused`. Both checks default to `true`, so implement only the ones you need.

Each check gets a `policy::SafeTxCheck` with everything that was planned:
- `plan`: `Plan::Send(&SendOpts)` for `send` and `safe config`, or `Plan::Rotation(&RotationPlan)` for `safe rotate` and `send --rotate`
- `calls`: the calls asked for
- `prepared`: the Safe transaction
- `before`: the Safe's `SafeState`
- `after`: its owners, threshold and implementation after the simulated transaction, or the owners a rotation must leave. This is `None` with `--skip-simulation`.

The CLI decides nothing itself, and without a policy none of this runs.

## Reusing `safe create` and `safe wallet` in your own CLI

The same pattern covers deploying Safes and managing HD wallets:

- `safe_rs_cli::create::CreateOpts` holds the `safe create` flags without `--rpc-url` or the signer: the setup (`SafeSetupArgs`: `--owner`, `--threshold`, `--salt-nonce`, `--safe-version`, `--singleton`, `--factory`, `--fallback-handler`), `--compute-only`, `--no-confirm`, the fee flags, and with `hd-wallet` `--rotate`, `--hd-wallet`, `--same-as` and the sweep flags (`hd.ledger` takes the keys from a Ledger). Build a `CreateContext::new(rpc_url).with_signer(key)` (no signer with `--rotate`) and call `create::create(ctx, opts)`. It returns a `CreateOutcome` (`Computed`, `AlreadyDeployed`, `Deployed` or `Aborted`, each with the Safe's address) or a `CreateError`. `CreateError::may_be_pending()` is true when the deployment may still be mined, and `CreateError::safe()` gives the address it was deploying to.
- `safe_rs_cli::wallet` (the `hd-wallet` feature) has `WalletCommand`, the `safe wallet` subcommands, to mount with `#[command(subcommand)]`, and one function per subcommand: `new_wallet`, `import_wallet`, `list_wallets`, `wallet_address`, `wallet_status`, `sync_wallet` and `sweep_wallet`. Each takes a `WalletContext` (`with_rpc_url`, `with_safe`, `with_home`, logger and prompt) and returns a typed outcome or a `WalletError`, such as `NotFound`, `WrongPassword`, `Locked`, or `Sweep` with what was moved and what is still owed. `wallet::run` runs a parsed `WalletCommand` and prints like `safe wallet`.

Neither defines `--rpc-url`, `--private-key` or `--safe`, so your CLI's own global flags for those keep working. `cli/tests/embed_create.rs` is a host shaped this way.

## Bundle Format

The `--bundle` option reads a JSON object. To send a list of calls, `calls` is all it needs:

```json
{
  "calls": [
    {
      "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "value": "0",
      "data": "0xa9059cbb000000000000000000000000...",
      "operation": 0
    },
    {
      "to": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
      "data": "0x095ea7b3...",
      "operation": 0
    }
  ]
}
```

Fields of a call:
- `to` — Target address (required)
- `value` — Wei to send (optional, default: "0")
- `data` — Calldata hex (optional, default: "0x")
- `operation` — 0 for Call, 1 for DelegateCall (optional, default: 0). With `--call-only`, a DelegateCall entry is rejected.
- `value` accepts decimal or `0x`-prefixed hex

When owners collect signatures ([Multi-owner Safes](#multi-owner-safes)), the CLI adds:
- `tx` — The Safe transaction being signed: chain ID, Safe, nonce, `safe_tx_hash` and the `execTransaction` fields. Once it is set, every run signs this transaction, and calls given on the command line must match `calls`.
- `signatures` — Owner address → 65-byte signature of `safe_tx_hash`
- `rotations` — The owner swaps `--rotate` added to the calls (`old_owner`, `new_owner`, `new_owner_index`)

Reading the file recomputes `safe_tx_hash` from the `tx` fields and checks that every signature recovers to its owner. The bare JSON array that versions before 0.13 read is rejected: wrap it as `{"calls": [...]}`.

## Supported Chains and Versions

safe-rs supports Safe v1.5.0 (default) and v1.4.1. Specify the version with `safe create --safe-version 1.5.0` or `--safe-version 1.4.1`. The CLI defaults to v1.5.0. v1.5.0 adds a module guard, which `safe config --module-guard` sets and `safe info` shows.

Existing v1.3.0 Safes also work with `Safe::connect`, `simulate()` and `execute()`, including ones with their own implementation contract, such as Polymarket's on Polygon. They batch through the v1.4.1 MultiSend contracts. v1.3.0 does not index `txHash` in `ExecutionSuccess` and `ExecutionFailure`, and safe-rs reads both layouts. safe-rs does not create v1.3.0 Safes, and one-time owner keys (`--rotate`) need v1.4.1 or v1.5.0.

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
| `SAFE_ADDRESS` | Safe address for `send`, `call`, `wallet sync` and `wallet sweep` (default: the signer's default Safe) |
| `PRIVATE_KEY` | Signer private key (also picks the default Safe when no Safe is given) |
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

**vs the Safe web interface:** A multi-owner Safe collects its signatures without the Transaction Service: owners pass a bundle file around however they like, or approve on chain with `approveHash`.

## License

MIT

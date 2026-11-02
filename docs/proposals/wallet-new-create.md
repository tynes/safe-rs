# Proposal: `safe wallet new --create`, and making a wallet and a Safe work together

Status: steps 1–3 built (uncommitted) · 2026-11-02

Built with these defaults for the open questions: no time limit on the wait in
a terminal, a plain y/N backup question, both a minimum and a recommended
amount (a 300k-gas buffer for the first send), and the flag named `--create`.
Open question 1 (`create --wallet` implying `--rotate`) is not done.

## The two nouns

- **A wallet** is a set of keys that come from one secret: a 24-word phrase on
  disk, or one path on a Ledger. Key 0 is the *funding key*. The later keys are
  used one at a time as owners. A wallet also keeps a record of which keys it
  has used. A wallet has no chain and no Safe.
- **A Safe** is an account on a chain. When a wallet manages it, one of the
  wallet's keys owns it, and that key changes with every rotating send.

`safe wallet new` makes the first. `safe create` makes the second. The output of
each command should only talk about its own noun. The one exception is the
"next step" line, which links the two.

Following this rule, `wallet new` no longer prints "Owner keys count up from":
which key owns a Safe is decided by `safe create` and the wallet's record, not
by the wallet. This change is done (`cli/src/wallet.rs`), together with the
same wording in the `--path` help.

## What is awkward today

```
safe wallet new treasury                                  # 1. phrase, funding address
# 2. send ETH to the funding address, somehow, from somewhere
safe create --rotate --mnemonic treasury --rpc-url $RPC   # 3. deploy
```

1. **The gap between the two steps is funding, and nothing helps with it.**
   `wallet new` says nothing about how much ETH to send. `safe create` with an
   unfunded funding key fails at gas estimation ("... may need ETH") instead of
   saying "send 0.0004 ETH to 0xFUND".
2. **The next step is not printed.** The Ledger output says "Use it with
   --wallet test (or --mnemonic test)", which doesn't say what to *do*. The
   phrase output says nothing.
3. **`--rotate` on `create` is a misleading name.** Nothing rotates when a Safe
   is created. Here it means "the owner comes from this wallet".
4. **Footgun:** `safe create --wallet treasury` *without* `--rotate` makes key
   0 (the funding key) the Safe's owner, which is exactly what the wallet
   exists to prevent. See open question 1.

## Proposed UX

### `safe wallet new <name> --create --rpc-url <RPC>`

One command from nothing to a deployed Safe:

```
$ safe wallet new treasury --create --rpc-url $BASE_RPC
Password: ********
Confirm password: ********

Wallet "treasury" saved to ~/.safe-rs/wallets/treasury.json
  Funding address: 0xFUND

Recovery phrase (shown once; it is the only backup of every key):

  word1 word2 ... word24

Write it down and keep it offline. Anyone who has it controls every Safe
this wallet owns.

Have you written down the recovery phrase? [y/N] y

Safe to create on chain 8453
  Safe address: 0xSAFE
  Owner:        key 1 of "treasury" (0xOWNER)
  Threshold:    1
  Paid by:      the funding address 0xFUND
Create this Safe? [Y/n] y

Send at least 0.00042 ETH to 0xFUND on chain 8453.
  Recommended: 0.002 ETH. Whatever is left after the deployment moves to the
  Safe's owner key and pays for its next transactions.
Waiting for funds... (Ctrl-C is safe: no key has been used yet. To finish
later: safe create --rotate --wallet treasury --rpc-url <RPC>)
  Received 0.002 ETH.

Sent 0xTX, waiting for receipt...
Safe 0xSAFE created. 0.0016 ETH moved to its owner key 0xOWNER.

Next: safe send <to> ... --rotate --wallet treasury --rpc-url <RPC>
```

The same works for a Ledger wallet (`--ledger [--path P] --create`). There is
no phrase, so the backup question is skipped. The device signs the deployment
with the funding key.

With a `--gas-payer-*` key, the funding wait is skipped and the Safe is
deployed right away. The funding address can be filled later, before the
first send.

### Order of steps, and what it guarantees

1. **Check everything that can fail cheaply before writing anything:** the
   name is free, `--rpc-url` is given and answers (`eth_chainId`), the setup
   flags are consistent (threshold against the number of owners), and the
   gas payer resolves. A typo in the RPC then leaves no orphan wallet behind.
2. Write the wallet file and show the phrase, then ask for the backup
   confirmation.
3. Compute the Safe (owner = the next unused key, normally key 1) and the cost
   of the deployment. Confirm once.
4. Wait for the funding address to hold the minimum.
5. Only then reserve the owner key, deploy, and sweep the funding key's ETH
   to the owner (what `rotating::create` already does).

Because the key is reserved after the wait, stopping at any point before step 5
leaves key 1 unused. `safe create --rotate --wallet treasury` then gives the
**same Safe address**, so funds already sent are not stranded. If something
fails after step 2, the wallet stays (its phrase was shown, and it may already
be funded), and the error ends with the resume command. Rerunning
`wallet new treasury --create` would fail with "already exists", so the resume
command is always `safe create`.

While the command waits, the wallet's state file stays locked (as it already
is through `rotating::create`). Other commands on the same wallet fail fast
with "locked" until the wait ends.

### How much to ask for

- **Minimum:** the deployment's gas estimate (with the usual margin) × max fee
  per gas. Estimating from an empty account works because no gas price is set
  on the estimate.
- **Recommended:** minimum + a buffer for the first rotating send. The sweep
  moves everything left to the owner key, so any extra ETH is not lost; it
  pays for later transactions.
- Show both. Wait for the minimum, not the recommended amount.

### `safe wallet new <name>` without `--create`

The output stays about the wallet, and ends with the exact next step:

```
Wallet "treasury" saved to ~/.safe-rs/wallets/treasury.json
  Funding address: 0xFUND

Recovery phrase (shown once; ...)

Next: send ETH for gas to 0xFUND, then create a Safe:
  safe create --rotate --wallet treasury --rpc-url <RPC>
```

The Ledger output is the same, plus the `Path:` line, and loses "Use it with
--wallet test (or --mnemonic test)".

### `safe create --rotate --wallet <name>` gets the same funding help

`wallet new --create` is `wallet new` followed by this, so `create` gains
the funding step on its own:

- If the payer (funding key or gas payer) can't cover the minimum, return a
  typed `CreateError::NeedsFunding { address, chain_id, minimum, balance }`.
  Its message names the address and amount, instead of a gas-estimation
  failure.
- `--wait-for-funds [<SECS>]` polls the balance between the confirmation and
  the key reservation (step 4 above) instead of failing. `wallet new --create`
  turns this on by default when it runs in a terminal.

## Flags

`wallet new` gains:

| Flag | Meaning |
|---|---|
| `--create` | Also create a Safe owned by the new wallet. Needs `--rpc-url` (or `ETH_RPC_URL`, or `rpc_url` in `config.toml`) |
| `--owner`, `--threshold`, `--salt-nonce`, `--safe-version`, `--fallback-handler`, `--singleton`, `--factory` | The Safe's setup, as for `safe create` (`SafeSetupArgs`) |
| Fee flags, `--timeout` | As for `safe create` (`FeeArgs`) |
| `--gas-payer-*` | Pay for the deployment from another key; skips the funding wait (`GasPayerArgs`) |
| `--no-sweep`, `--sweep-reserve` | As for `safe create --rotate` (`SweepArgs`) |
| `--no-confirm` | Skip both questions (backup and deploy) |
| `--wait-for-funds [<SECS>]` | As for `create`. Default with `--create`: wait without a limit when interactive |

These go under a help heading "Create a Safe (with --create)". Each one is
refused without `--create`. `--same-as` and `--compute-only` are left out:
a new wallet has no Safe to copy, and `--compute-only` belongs to `safe
create`.

`WalletCliArgs` already has a global `--rpc-url` (today used by `sync` and
`sweep`), so `--create` needs no new RPC flag.

## Structure (follows `cli-composable-commands.md`)

- **One code path.** `--create` builds a `CreateOpts { rotate: true,
  owner_keys: <the new wallet>, setup, fees, gas_payer, sweep, no_confirm, .. }`
  and calls the same `create_with` / `rotating::create`. There is no second
  deploy implementation.
- **The funding wait lives in `CreateOpts`** (`wait_for_funds:
  Option<Duration>`), checked inside `rotating::create` after the confirmation
  and before `take_unused`. The plain (non-rotating) create can use it too,
  but doesn't have to.
- **No combined library function.** A host does what the CLI does: calls
  `new_wallet` / `new_ledger_wallet`, shows the phrase its own way, then calls
  `create`. The library still never prints. The combining code is a few lines
  in `wallet::run`.
- **JSON.** `wallet new --create --json` emits one document: the existing
  `WalletCreated` keys (phrase included, as today) plus a `safe` field holding
  the `CreateOutcome`, or an `error` field if the create failed. The phrase
  must be emitted even when the create fails.
- **Non-interactive.** `--json` implies `--no-confirm`, and doesn't wait for
  funds unless `--wait-for-funds` is given. A brand-new wallet is always
  empty, so `--create --json` without `--wait-for-funds` or a gas payer
  returns `NeedsFunding` right away, with the wallet already written. The
  error says so, so a script can fund the address and run `safe create`.

## Steps

1. **Output polish** (small, can land on its own): add the "Next:" line to
   both `wallet new` outputs, and drop "Use it with --wallet ...".
2. **Funding in `safe create --rotate`:** cost estimate, `NeedsFunding`,
   `--wait-for-funds`, with the wait placed before the key reservation.
   Tests: unit test for the cost math. An anvil test with an empty funding key
   gets `NeedsFunding`, and the key is still unused. A test that funds the key
   during the wait sees the deployment go through.
3. **`wallet new --create`:** the flags, the early checks, backup question,
   JSON shape. Tests: `WalletCliArgs::command().debug_assert()` (catches
   clashes such as `-l` / `--password` against the gas-payer flags), each
   create flag is refused without `--create`, a bad RPC leaves no wallet file,
   and an anvil end-to-end run with a gas payer and with `--wait-for-funds`.
4. **README:** "Getting started" becomes one command, with the two-command
   form kept for when the wallet already exists.
5. **Open question 1**, if accepted.

## Open questions

1. **Should `safe create --wallet <name>` imply `--rotate` when the name is a
   safe-rs wallet?** Today it makes the funding key the owner. Options:
   (a) imply `--rotate` and say so in the output, (b) refuse without `--rotate`
   and explain, (c) keep today's behaviour. (a) is the nicest and matches what
   the wallet is for, but it changes what an existing command does. Raw
   phrases, keystores and a bare `--ledger` would keep today's meaning.
2. **Default wait in a terminal:** no limit (Ctrl-C to stop), or a long
   timeout such as 30 minutes?
3. **Backup question:** a plain y/N, or ask for two random words of the
   phrase? The second is safer, and a bit annoying.
4. **Recommended amount:** a fixed gas buffer for one rotating send
   (estimated per chain from the current fee), or no recommended figure at all?
5. **Name of the flag:** `wallet new --create`, or `--safe`? `--create`
   matches the command it stands for; `--safe` reads better ("a new wallet
   with a Safe"), but `--safe <ADDRESS>` is already a global flag on `safe
   wallet`, so `--create` avoids the clash.

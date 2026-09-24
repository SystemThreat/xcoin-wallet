# xcoin-wallet

A minimal, auditable **post-quantum** command-line wallet for xCoin (XCF).

Every Xcoin address is an **ML-DSA-65** (FIPS 204, quantum-resistant) key. Addresses
look like `xpa1r…` (`txa1r…` on testnet A). There is no non-quantum spend path — coins
can only be moved with a real ML-DSA-65 signature.

> **What works today: everything.** Identity and forum sign-in (`identity`,
> `signmessage` — the `xid1…` key at index 101 that minedifferent.com verifies),
> wallet creation, encryption, backup, card wallets — and, since 2026-09-24, the
> **full witness v3 payment path**: `address` derives the live chains' `xpa1r…`/
> `txa1r…` form and `send` signs the v3 tagged sighash offline. The keytool
> replays the node's own golden vectors (`./xcoin-wallet _v3vectors`) and the
> path is proven on-chain: testnet A accepted and mined its first keytool-signed
> v3 spends (txids `88665c29…`, `f035c14d…`, `cd5b6f71…`) the day it landed.
> With `--explorer https://superknet.com` the wallet needs **no node at all**:
> balances and fees come from the explorer's public API, transactions are built
> and signed on this Mac, and the explorer relays the one signed transaction.

The wallet is fully **deterministic and self-custody**: one 256-bit seed is your entire
wallet. The same seed always regenerates the same keys and addresses, so the seed alone
is a complete backup — and anyone who has it controls the coins.

Two pieces:

| Piece | File | Role |
|---|---|---|
| Native keytool | `xcoin-wallet.cpp` → `./xcoin-wallet` | Offline key/address derivation, built from the node's own PQClean sources |
| Wallet CLI | `wallet_cli.py` via `./xcoin-wallet-cli` | Full wallet: balance, UTXOs, send, history, backup — via your own node's RPC, or node-less with `--explorer` |
| Card module | `card_seed.py` | NTAG 424 DNA hardware-key support (optional; needs `pyscard` + `cryptography`) |

The CLI derives and signs offline in the native keytool, which is built from the
node's own PQClean sources (vendored in `pqcrypto/`) — so derivation and signing
are the identical code paths the node itself validates. The node's former
`pqderiveaddress` and `pqsignrawtransaction` RPCs were removed on 2026-09-14;
the keytool is their replacement, and keys never touch the node.

## Build & install

Requires Xcode Command Line Tools on an Apple Silicon Mac. The repository is
standalone: the PQClean ML-DSA-65 sources are vendored in `pqcrypto/`, so a fresh
clone builds with no other tree present. If you do have the xCoin node source,
`NEX=/path/to/it ./build.sh` builds against the node's copy instead, so wallet and
node can never drift.

```bash
./build.sh               # builds the native keytool ./xcoin-wallet
./install.sh             # symlinks into ~/.local/bin (PREFIX=… to change)
```

`install.sh` installs the Python CLI as **`xcoin-wallet`** (the final command) and the
native binary as **`xcoin-keytool`**. In-tree names are unchanged, and it refuses to
overwrite anything it didn't create.

## Create your wallet OFFLINE (recommended)

```bash
# 1. Go offline: turn OFF Wi-Fi and unplug Ethernet.

# 2. Create the wallet (default: ~/.xcoin/wallet.mmm, encrypted, chmod 600).
#    You'll be offered an encryption passphrase — take it.
xcoin-wallet new --offline

# 3. WRITE THE SEED DOWN on paper or metal, then press Enter —
#    the wallet wipes the seed from your screen AND scrollback.

# 4. Show your receiving address (safe to share):
xcoin-wallet address

# 5. Turn Wi-Fi back on.
```

For maximum (air-gap) security, run steps 2–4 on a Mac that never goes back online and
carry only the address (never the seed) to your online machine.

## Commands

Global options: `--file <wallet>`, `--config <nex.conf>`, `--rpc-host/-port/-user/-password`,
`--json` (machine-readable output for every command).

| Command | What it does |
|---|---|
| `new [--offline] [--no-clear]` | Create a wallet; prints the seed once, then offers a screen+scrollback wipe. |
| `address` / `receive [--index N] [--verbose] [--identity]` | Show a receiving address; `--identity` shows the key's forum identity (`xid1…`) instead. |
| `identity [--index N] [--verbose]` | Show the forum identity `xid1…` of the key at `--index` (same as `address --identity`). |
| `addresses [--start N] [--count N] [--identity]` | List derived addresses; `--identity` lists each key's `xid1…` beside it. |
| `signmessage --template T \| --message M [--index N] [--as identity\|address]` | Sign a message with the key at `--index` (FIPS 204 ML-DSA-65) for the MineDifferent sign-in; `{address}` in the template names the signer. |
| `balance` / `status [--index N]` | Balance split into **spendable** vs **immature** (coinbase < 1,000 confs). |
| `utxos [--index N]` | Every UTXO with height, confirmations, and maturity status. |
| `send <dest> <amount> [--index N] [--fee X \| --feerate R] [--max-fee X] [--yes] [--dry-run]` | Select coins, estimate fee, sign with ML-DSA, confirm, broadcast. |
| `history [--index N] [--from-height H]` | Full send/receive history (scans the chain; includes mempool). |
| `info` | Chain, sync state, peers, mempool, and relay-fee status. |
| `seed [--copy [--timeout S]] [--yes]` | Re-display the seed (type `REVEAL`) or copy it to the clipboard. |
| `card-provision` (`new --card`) | Create a **card-bound** wallet on an NTAG 424 DNA card — the seed is never displayed. |
| `card-backup` | Provision a duplicate backup card that unlocks the same wallet. |
| `card-test` | Prove a provisioned card authenticates and yields its factor (read-only). |
| `card-list` | List provisioned cards known to this Mac. |
| `card-reset --yes` | Factory-reset a card and retire its key file (refused on permanent cards). |
| `restore` / `import [<seed> \| --paste \| --from-file F]` | Recreate the wallet from a seed (hidden prompt by default); writes `.mmm`. |
| `encrypt` | Convert a legacy plaintext `wallet.seed` to `.mmm`, or re-key an existing `.mmm`. |
| `backup <dest>` | Copy the wallet file somewhere safe (0600); `.mmm` backups stay encrypted. |
| `reset --backup <dest> --yes` | Retire the wallet — **moves** the seed to the backup path, never deletes. |

### Forum identity (`xid1…`)

Every key also has a **forum identity**: the same 32 bytes the addresses commit to
(SHA-256 of the ML-DSA-65 public key) written as bech32m under the prefix `xid` with
no witness-version byte, 62 characters (`xid1` + 52 + 6). It has no chain prefix and no
version, so no node ever reads it as an address and nothing can be paid to it: it is
the handle you post and chat under on MineDifferent, not a place to send coins.

```bash
xcoin-wallet identity --index 101              # xid1…
xcoin-wallet addresses --count 3 --identity    # index  xpa1r…  xid1…
```

`signmessage` signs **as the identity** by default: `{address}` in the template and the
JSON `address` field are the `xid1…` string (NerdMiner posts that field to the forum as
`address`); `identity` and `witness_v2_address` are always in the JSON. `--as address`
names the witness v3 payment address instead, for a verifier that expects one.

### The `.mmm` wallet file

New wallets are written as **`wallet.mmm`** — a branded binary format only this CLI
reads: `XCOINMMM1` magic, 16-byte salt + nonce, the seed encrypted with a
scrypt-derived SHAKE-256 keystream, and an HMAC-SHA256 integrity tag
(encrypt-then-MAC). Other programs see opaque bytes; any tampering or a wrong
passphrase is detected before the seed is used.

Honesty about guarantees: a file extension can't stop other software from *opening* a
file — encryption is what does. **With a passphrase**, the `.mmm` file is real
encryption: useless without the passphrase, even to someone with this CLI.
**Without one**, it is still opaque and tamper-evident, but anyone holding the file
plus this open-source tool could decode it.

- No-passphrase wallets unlock silently; passphrase-protected ones prompt (or read
  hand it over a file descriptor with the top-level `--passphrase-fd N` for
  automation; the environment variable route is deliberately refused, see below).
- Legacy plaintext `wallet.seed` files are still read transparently; migrate with
  `xcoin-wallet encrypt` (the plaintext original is *moved* to a `.plaintext-backup`
  file for you to verify and dispose of — never silently deleted).
- The default `--file` prefers `~/.xcoin/wallet.mmm` and falls back to a legacy
  `~/.xcoin/wallet.seed` if that's all that exists.

### Sending

- Coinbase outputs younger than **1,000 confirmations are immature** and are excluded
  from coin selection automatically; `balance`/`utxos` show exactly how long is left.
- Fees default to **auto-estimation from real transaction size**: ML-DSA signatures are
  ~3.3 KB and pubkeys ~2 KB per input, so a 1-in/2-out spend is ~5.4 KB (~1455 vbytes).
  The rate comes from `estimatesmartfee`, else your `fallbackfee`, else the relay floor.
  Override with `--feerate` (XCF/kvB) or an absolute `--fee`.
- `--max-fee` (default 0.1 XCF) refuses runaway fees.
- Change below 0.00001 XCF is folded into the fee instead of creating dust.
- Every transaction is checked with `testmempoolaccept` before broadcast — a spend the
  network would reject (e.g. immature coinbase) never leaves the wallet.
- `--dry-run` signs, decodes, and policy-checks without broadcasting anything.

### Offline signing (seed never touches the node)

By default, `send` signs **offline** in the native `xcoin-wallet` keytool: the wallet
builds the unsigned transaction with the node (no secrets), pipes the seed + unsigned
tx + prevouts to the keytool over stdin (never argv), and the keytool produces real
ML-DSA-65 witness signatures locally. The seed — and, for card wallets, the card factor
it came from — never reaches `nexd`. The node only broadcasts and validates the
finished transaction.

The keytool reimplements the consensus signing paths **offline, without the
node**: witness v3 (the live chains' post-quantum script tree — tagged sighash
per `src/script/xcoin_v3.h`, single ML-DSA leaf, bare SIGHASH_DEFAULT
signature) and legacy witness v2 (BIP143-style, kept for sweeping private
chains). `./xcoin-wallet _v3vectors` replays the node's golden test vectors so
a drifted build fails loudly

For a true air gap: build the unsigned tx online, carry it to an offline machine holding
the seed/cards, run the keytool there, and carry the signed hex back to broadcast.

### Testnet examples

```bash
alias xw='./xcoin-wallet-cli --config $HOME/.xcoin/nex.conf --rpc-port 19432'   # testnet A RPC port

xw info                          # chain height, sync, mempool
xw balance --index 1             # spendable vs immature
xw utxos --index 1               # per-UTXO maturity countdown
xw history --index 1             # coinbase + send/receive history
xw --json balance --index 1      # automation-friendly output

# Dry run: sign + policy-check, broadcast nothing (sends to the wallet's own index-0 address):
xw send "$(xw address --index 0)" 1.0 \
   --index 1 --yes --dry-run
```

## Hardware-key wallets (NTAG 424 DNA)

The strictest mode: bind the wallet to a physical **NTAG 424 DNA** RFID card so
the seed is sealed to the chip and **never displayed — from creation through every
use**. This needs a PC/SC reader (ACR1252) and `pyscard` + `cryptography`.

```bash
# Create a card-bound wallet (tap a FACTORY card when prompted):
xcoin-wallet new --card --file ~/.xcoin/wallet001.mmm

# From then on, any command that needs the key asks you to tap the card:
xcoin-wallet balance --index 0        # tap to scan
xcoin-wallet send <dest> 1.0          # tap to sign

# Make a duplicate backup card (there is no paper backup — do this):
xcoin-wallet card-backup --file ~/.xcoin/wallet001.mmm

xcoin-wallet card-test                 # verify a card without touching a wallet
xcoin-wallet card-list                 # cards provisioned on this Mac
```

**How it works — genuine two-factor decryption.** A random 32-byte *card factor* is
written into the chip's proprietary file, which the chip releases only after AES
**EV2 authentication** over an encrypted, MAC'd channel (NXP AN12196, validated
against real NTAG 424 DNA hardware). The Mac keeps only the card's
per-card AES keys (`~/.xcoin/card-<uid>.auth`, mode 600) and the encrypted wallet
(`XCOINMMM2` format). The wallet key is `scrypt(card_factor [+ optional passphrase])`.

**Permanent by default (non-resettable).** Provisioning changes all three card keys
(master/read/write) to random values. By default the card is then **sealed**: the
master and write keys are discarded everywhere, leaving only the read key needed to
unlock. A sealed card can never be reset to factory, never have its factor rewritten,
and never have its file access relaxed — so nobody can accidentally wipe or reuse it.
This is irreversible; pass `--resettable` at creation to keep the rollback keys
instead (then `card-reset` can return the card to blank).

- **Disk alone is useless** — the wallet file has no key material; without the card it
  cannot be decrypted.
- **Card alone is useless** — the factor is meaningless without the auth keys on this
  Mac; add a passphrase (typed at the prompt, or `--passphrase-fd N` when scripted) for a third factor.
- **The seed is never revealed** — `new --card` does not print it, and `seed`, `encrypt`,
  and JSON reveal all refuse on a card wallet. It exists only inside `mlock`'d,
  auto-zeroized secure buffers during signing.

**Honest limits — read these:**

- **No paper backup, and permanent cards can't be recycled.** If you lose every card
  for a wallet, the coins are gone — and a sealed card can never be reset, so a lost
  card is also lost hardware. *Always* make at least one `card-backup` and store the
  cards apart.
- **A file extension cannot enforce access — encryption does.** `.mmm` is opaque and
  tamper-evident, but it's the card (and optional passphrase) that make it unopenable
  by anything else, including this CLI.
- **The seed no longer reaches the node by default.** Signing now happens **offline in
  the native keytool** — the unlocked seed goes to the local `xcoin-wallet sign` binary
  (over a pipe, never argv) and never to `nexd`. The node is used only to build the
  unsigned tx and to broadcast/validate the finished one. See "Offline signing" below.
- **Python can't guarantee zero secret copies.** `SecureBuffer` mlocks against swap,
  zeroizes on release, and core dumps are disabled — best effort, honestly labeled.

## Seed hygiene: history, scrollback, clipboard

Three different places a seed can leak, and what this wallet does about each:

**Terminal scrollback** — anything *printed* (e.g. by `new`) stays in your terminal's
scrollback even after `clear`. After showing a seed, the wallet offers a wipe that
clears the screen **and scrollback** (ESC[3J — works in Terminal.app and iTerm2; if
your terminal ignores it, use Cmd+K). The seed remains safe in the wallet file and can
be re-displayed any time with `xcoin-wallet seed`.

**Shell history** — anything *typed as an argument* (e.g. `restore <seed>`) lands in
`~/.zsh_history` and is visible in `ps` while running. Avoid it entirely:

- `restore` with no argument uses a **hidden prompt** (nothing echoed, nothing saved);
- `restore --paste` reads the clipboard and clears it afterwards;
- `restore --from-file /Volumes/USB/backup.seed` reads a file — best for air-gap moves.

If you must type a secret into the shell: `setopt HIST_IGNORE_SPACE` in `~/.zshrc`,
then prefix the command with a space and zsh never records it. To purge after the
fact, delete the line from `~/.zsh_history` and start a new shell.

**Clipboard** — `seed --copy` pipes the seed to the clipboard without printing it and
**auto-clears after 60 seconds** (`--timeout` to change, `0` to disable; it only clears
if the clipboard still holds the seed). Caveats: clipboard-manager apps keep history,
and Handoff/Universal Clipboard can sync your clipboard to other Apple devices — check
those before using `--copy`.

## Mining with your address

Point any Xcoin miner (e.g. the MMM Mac Metal Miner) at the pool using your address as
the stratum username. Append `.aName` to name your rig on the leaderboard:

```
xpa1r<youraddress>.studio-m3pro
```

Pool: `pool.macmetalminer.com:3333`. Mined coinbase outputs mature after 100 blocks —
`balance` shows the countdown.

## Environment variables

None are required for interactive use — you'll be prompted for anything secret, and
nothing persists. They exist only to run the wallet headless/scripted.

| Variable | Kind | When / why |
|---|---|---|
| `XCOIN_RPC_USER` / `XCOIN_RPC_PASSWORD` | **secret** | Node RPC login, used only if not passed via `--rpc-user/--rpc-password` or found in `nex.conf`. Keeps the RPC password off the command line (where `ps` would show it). This is the *node's* password, not your seed. |
| `HOME` | config | Locates `~/.xcoin/`. Standard; set by your shell. |
| `NEX` | config | `build.sh` only — path to the Xcoin source tree (to find the PQClean sources). |
| `PREFIX` | config | `install.sh` only — install prefix for the CLI symlinks (default `~/.local`). |

**Your seed, card factor, and wallet passphrase are NEVER read from an environment
variable** — anywhere. `XCOIN_WALLET_PASSPHRASE` is **deliberately refused**: if it is
set, the CLI exits immediately (code 2), because an environment variable is readable
by every process you run and tends to land in shell history. The only secret that may
live in env is the node's RPC password — the node's secret, not yours.

**Automation** uses a file descriptor instead: the top-level `--passphrase-fd N`
option reads the passphrase from fd `N`, so it never appears in the command line,
the environment, `ps`, or history:

```bash
xcoin-wallet --passphrase-fd 3 balance 3</path/to/passphrase-file   # fd, mode 0600
printf '%s\n' "$pass" | xcoin-wallet --passphrase-fd 0 signmessage …  # or stdin
```

For normal interactive use, set nothing — just answer the prompts.

## Tests

```bash
python3 -m unittest discover -s tests      # the offline suite (RPC + NFC simulated)
python3 card_seed.py --selftest            # card EV2/FULL crypto against the simulator
tests/integration_testnet.sh              # read-only + dry-run against a live node
```

The card tests need the optional `cryptography` module and are skipped cleanly
without it.

Card tests run entirely against a software NTAG 424 DNA model — no hardware needed.
Before trusting a real card, run `card-test` with a factory card on your reader.

The integration script never broadcasts and never modifies the wallet.

## Security notes

- **The seed is everything.** Generate it offline, back it up on paper/metal, never
  share it, never type it into a website or app.
- The wallet file is encrypted `.mmm` format (see above), created `0600` with
  `O_EXCL` (never overwrites), and `reset` moves the seed instead of deleting it.
- The CLI talks only to **your own node** over localhost RPC, and only for chain
  data and broadcast. Derivation and signing happen in the local keytool; the seed
  goes to it over a pipe and **never reaches the node** — or anything else.
- Amounts are handled as exact decimals end-to-end; no floating point ever touches a
  value that gets signed.
- Deterministic keys: the same seed always restores the same wallet — verified
  byte-for-byte against the derivation the node's former `pqderiveaddress` RPC used
  (SHAKE256 HD path → ML-DSA-65 keygen → bech32m address).

## License

MIT — see LICENSE.

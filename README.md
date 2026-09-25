# xcoin-wallet

A minimal, auditable **post-quantum** command-line wallet for xCoin (XCF).

Every Xcoin address is a witness v3 script tree over **post-quantum keys only**: an
**ML-DSA-65** (FIPS 204) leaf plus an **SLH-DSA-SHA2-128s** (FIPS 205, hash-based)
fallback leaf from the same key position. Addresses look like `xpa1r…` (`txa1r…` on
testnet A). There is no non-quantum spend path — coins can only be moved with a real
post-quantum signature (this wallet signs through the ML-DSA-65 leaf).

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
standalone: the node's PQClean ML-DSA-65 and SLH-DSA-SHA2-128s sources are vendored in
`pqcrypto/` (provenance in `pqcrypto/*/PQCLEAN`), so a fresh clone builds with no other
tree present. If you do have the xCoin node source,
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
| `address` / `receive [--index N] [--verbose] [--identity] [--carried]` | Show the receiving (two-leaf) address; `--carried` shows the single-leaf form of the same key, `--identity` the key's forum identity (`xid1…`) instead. `--json` includes both address forms. |
| `identity [--index N] [--verbose]` | Show the forum identity `xid1…` of the key at `--index` (same as `address --identity`). |
| `addresses [--start N] [--count N] [--identity] [--carried]` | List derived (two-leaf) addresses, one per line; `--carried` adds each key's single-leaf form, `--identity` its `xid1…`. |
| `signmessage --template T \| --message M [--index N] [--as identity\|address]` | Sign a message with the key at `--index` (FIPS 204 ML-DSA-65) for the MineDifferent sign-in; `{address}` in the template names the signer. |
| `balance` / `status [--index N]` | Balance split into **spendable** vs **immature** (coinbase < 1,000 confs), over both address forms of the key; `--json` adds a per-form breakdown (`forms.two_leaf`, `forms.carried`). |
| `utxos [--index N]` | Every UTXO with height, confirmations, maturity status and form (`two_leaf` / `carried`). |
| `send <dest> <amount> [--index N] [--fee X \| --feerate R] [--max-fee X] [--split] [--yes] [--dry-run]` | Select coins from both forms, estimate fee, sign with ML-DSA, confirm, broadcast; change goes to the two-leaf address. `--split` pays an amount too large for one transaction as several. |
| `history [--index N] [--from-height H]` | Full send/receive history (scans the chain; includes mempool). |
| `info` | Chain, sync state, peers, mempool, and relay-fee status. |
| `seed [--copy [--timeout S]] [--yes]` | Re-display the seed (type `REVEAL`) or copy it to the clipboard. |
| `card-provision` (`new --card`) | Create a **card-bound** wallet on an NTAG 424 DNA card — the seed is never displayed. |
| `card-backup [--auto-swap]` | Provision a duplicate backup card that unlocks the same wallet. `--auto-swap` sees the swap on the reader (wallet card off, blank card on) instead of waiting for Enter; a card that is not factory-fresh, or the wallet card put back, is refused before anything is written. |
| `card-status` | Which cards unlock this card wallet (from `~/.xcoin` key files; no tap, no passphrase). `backup_supported` is `false`, with a `note` saying why, when no backup card can be made on this Mac: no key file for the wallet's cards here (they were set up on another Mac), the card software is not installed (`pyscard`, which the reader needs, or `cryptography`; each is checked by importing it, and the note names only the missing ones), or a dex-era wallet (made with dex-wallet-cli, where its backup cards are made). |
| `card-test` | Prove a provisioned card authenticates and yields its factor (read-only). |
| `card-list` | List provisioned cards known to this Mac. |
| `card-reset --yes` | Factory-reset a card and retire its key file (refused on permanent cards). |
| `restore` / `import [<seed> \| --paste \| --from-file F]` | Recreate the wallet from a seed (hidden prompt by default); writes `.mmm`. |
| `encrypt` | Convert a legacy plaintext `wallet.seed` to `.mmm`, or re-key an existing `.mmm`. |
| `backup <dest>` | Copy the wallet file somewhere safe (0600); `.mmm` backups stay encrypted. |
| `reset --backup <dest> --yes` | Retire the wallet — **moves** the seed to the backup path, never deletes. |

### Addresses: two-leaf standard, carried form still yours

The receiving address of key index `i` is the protocol-standard **two-leaf** witness v3
tree, the same shape the node's own wallet hands out (`pqtr({pq(K),slh(K')})`,
REGENESIS.md section 4):

| Leaf | Version | Script |
|---|---|---|
| ML-DSA-65 | `0xc0` | `<SHA-256(ML-DSA pubkey)> OP_CHECKSIG` |
| SLH-DSA-SHA2-128s (fallback) | `0xc2` | `<SLH-DSA pubkey (32 B)> OP_CHECKSIG` |

The program is the sorted `XCoinBranch` of the two leaf hashes. Both keys come from
the same seed position: the ML-DSA-65 key exactly as before, the SLH-DSA key from
`SHAKE-256(child || "xcoin/hd/slh-dsa-sha2-128s/seed")[48]` (the same derivation as
dex-wallet-cli, so both tools show the same address for the same seed and index).
The wallet spends through the ML-DSA leaf; the SLH-DSA leaf is a hash-based fallback
should ML-DSA ever be weakened.

Earlier builds of this wallet printed the **single-leaf** tree `{ML-DSA-65 leaf}` of the
same key as the address. That form is now called **carried**: it is still derived, still
scanned by `balance`/`utxos`/`history`, and still spent by `send` (inputs of both forms
can mix in one transaction). Nothing needs to be moved; new payments and change simply
go to the two-leaf address.

```bash
xcoin-wallet address                  # xpa1r…  (two-leaf: ML-DSA + SLH-DSA)
xcoin-wallet address --carried        # xpa1r…  (single-leaf form of the same key)
xcoin-wallet --json address           # both, with their scriptPubKeys
```

After upgrading, rebuild the keytool (`./build.sh`): the CLI refuses a keytool that
predates two-leaf addresses rather than mistake one form for the other.

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
`address`); `identity` and `witness_address` (the two-leaf payment address) are always
in the JSON. `--as address` names the witness v3 payment address instead, for a verifier
that expects one.

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
- Change below 0.0001 XCF (the 10,000-sat consensus output floor) is folded into the fee instead of creating dust.
- Every transaction is checked with `testmempoolaccept` before broadcast — a spend the
  network would reject (e.g. immature coinbase) never leaves the wallet. On the node path a
  refusal there ends like a refused broadcast (`Nothing was sent: …` and the `rejected`
  event; in a split send it names the refused transaction and none is broadcast); a
  transaction the node says it already has goes on to the broadcast and counts as sent.
- `--dry-run` signs, decodes, and policy-checks without broadcasting anything.
- One transaction carries at most 72 ML-DSA inputs (the node's 400,000 WU standard
  weight). A payment needing more fails with "split the send"; `--split` instead plans
  it as several independent transactions (largest coins first, each paying the
  destination, every output and change at least 10,000 sat), signs them all with one
  unlock (one card tap), then broadcasts them in turn. If a later broadcast fails after
  earlier ones went out, the send exits 0 with `"partial": true`, the `txids` that went
  out, `unsent_txids` and `broadcast_error`. `--max-fee` then guards the total fee.
  The first of `unsent_txids` is the one whose broadcast failed: a lost connection can
  hide its success, so look it up before paying the rest again (the others were never
  tried). A failed first broadcast exits 1 and names that txid the same way.
- A **refusal** is told apart from a **lost connection**. When the explorer or the node
  answers that it refuses a transaction (the explorer's `400 {"error": "rejected",
  "reason": ...}`, `bad_hex`, `too_large`; the node's RPC errors -26, -25, -22), it was
  not accepted and not relayed: a refused first transaction exits 1 with
  `error: Nothing was sent: <reason in plain words> (<the network's own reason>)`, for
  example "these coins are already being spent by an earlier send that has not confirmed
  yet. Wait for the next block, then send again. (replacement-failed)". The explorer runs
  the node's `testmempoolaccept` first, so this chain answers `missing-inputs` for coins
  that were already spent ("these coins were already spent.") and `insufficient fee` or
  `replacement-failed` for coins already in an unconfirmed send. A refused later
  one keeps the partial-send report above, adds `"broadcast_rejected": true`, and marks it
  `NOT SENT: the network refused it`. `txn-already-in-mempool`, `txn-already-known`,
  "Transaction already in block chain" / "…already in utxo set" (RPC -27) mean the network
  already has that transaction: it counts as sent under the txid computed before the send.
  Only a timeout, a dropped connection or an answer that is no verdict (503 from the
  explorer, a warming-up node) keeps the "Nothing is confirmed sent, … look up <txid>" wording.

### Offline signing (seed never touches the node)

By default, `send` signs **offline** in the native `xcoin-wallet` keytool: the wallet
builds the unsigned transaction with the node (no secrets), pipes the seed + unsigned
tx + prevouts to the keytool over stdin (never argv), and the keytool produces real
ML-DSA-65 witness signatures locally. The seed — and, for card wallets, the card factor
it came from — never reaches `nexd`. The node only broadcasts and validates the
finished transaction.

The keytool reimplements the consensus signing paths **offline, without the
node**: witness v3 (the live chains' post-quantum script tree — tagged sighash
per `src/script/xcoin_v3.h`, the ML-DSA-65 leaf of either address form, bare
SIGHASH_DEFAULT signature; the control block is 65 bytes for a two-leaf output and
33 for a carried single-leaf one) and legacy witness v2 (BIP143-style, kept for
sweeping private chains). `./xcoin-wallet _v3vectors` replays the node's golden
test vectors, and the two-leaf and carried programs of a fixed test seed as
dex-wallet-cli's keytool derives them, so a drifted build fails loudly

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

**Card and reader faults.** If the reader resets the card (or loses it for a moment) in
the middle of a *read*, the CLI reconnects and reads again, at most twice: keep the card
on the reader. A fault in the middle of a *write* (a new card, a backup card, a reset) is
never retried and is reported as "did not finish … do not rely on that card". Every card
or reader fault ends in one line, `error: <what happened>; <what was or was not done>`
(for example "nothing was sent" or "nothing was written"), with exit code 1 and no Python
traceback. That includes pyscard's low-level `scard.error` and faults from below pyscard
during a read or a write (an OSError or timeout from the reader's driver, an answer that
makes no sense). Reader-level faults add "If this keeps happening, unplug the card reader,
plug it back in, and try again." A key file that cannot be saved during a write (a full
or read-only disk) is named as that, without the reader hint.

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
| `XCOIN_CARD_TIMEOUT` | config | Seconds to wait for a card tap (default 60, 5..300). The wait watches the reader's PICC interface with `SCardGetStatusChange` and connects once the card is there. |
| `XCOIN_EVENTS` | config | `1`: machine-readable progress on stderr for a parent program (MMM): `XCOIN-EVENT card-wait <s>` before every card tap (unlock, `new --card`, `card-backup`, `card-test`, `card-reset`) and `card-ok` after it succeeds; `card-retry <attempt>` when the reader reset the card (or lost it) mid-read and the read is tried again (attempt 1 or 2; the card stays on the reader; never during a write); `card-backup --auto-swap` adds `card-swap` (take the wallet card off, place a blank one), `card-removed`, `card-provisioning` (the commit point of the backup, like `broadcast-begin`: a strict write, so a parent already gone means nothing is written; then a 0.5 s pause in which a cancel already on its way still stops the run with the blank card untouched; from the first write until the backup's key file is sealed, SIGTERM and SIGPIPE are ignored so the card is never left half written) and `done`; `new --card` sends `card-provisioning` the same way once the blank card passed its checks (same strict write and pause), and holds SIGTERM and SIGPIPE off from its first write until the card is sealed and the wallet file is written (its passphrase is asked before the card is touched); `signing <i> <n>`; `broadcast-begin <n>` just before the first broadcast (from here the parent must not stop the CLI; a 0.5 s pause follows so a cancel already on its way lands before anything is sent; if the parent quits or dies, the CLI still attempts every broadcast: SIGPIPE is ignored and output to a closed pipe is dropped); `broadcast <i> <n> <txid>` per accepted transaction (also when the network answers it already has it); `rejected <i> <n> <reason>` just before the error when the explorer or node refused the first transaction, or the node path's own check refused transaction `<i>` before anything went out (nothing was sent; `<reason>` is one token such as `missing-inputs`, `replacement-failed`, `insufficient-fee` or `bad-txns-inputs-missingorspent`); `done`. |
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
  (SHAKE256 HD path → ML-DSA-65 keygen), and against dex-wallet-cli's keytool for the
  SLH-DSA-SHA2-128s key and the two-leaf / carried trees (`_v3vectors`).

## License

MIT — see LICENSE.

#!/usr/bin/env python3
"""xcoin-wallet transaction CLI using Xcoin's consensus-native PQ RPCs.

All money is handled as Decimal end-to-end (RPC responses are parsed with
parse_float=Decimal and amounts are sent to the node as 8-decimal strings),
so no float ever touches an amount that gets signed or broadcast.

Addresses are witness v3 script trees. The receiving address of key index i is
the protocol-standard two-leaf tree {ML-DSA-65 leaf 0xc0, SLH-DSA-SHA2-128s
fallback leaf 0xc2}; the single-leaf tree {ML-DSA-65 leaf} of the same key (the
"carried" form, which earlier builds printed as the address) is still scanned,
counted and spent. Derivation and signing live in the native keytool.
"""

import argparse, base64, contextlib, getpass, hashlib, hmac, json, os, shutil, signal, subprocess, sys, time, urllib.request, urllib.error
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path

DEFAULT_CONFIG = Path.home() / ".xcoin" / "nex.conf"

def default_wallet():
    """Prefer wallet.mmm, then any other .mmm (e.g. wallet001.mmm), then legacy."""
    d = Path.home() / ".xcoin"
    if (d / "wallet.mmm").exists(): return d / "wallet.mmm"
    others = sorted(d.glob("*.mmm")) if d.exists() else []
    if others: return others[0]
    if (d / "wallet.seed").exists(): return d / "wallet.seed"
    return d / "wallet.mmm"

COINBASE_MATURITY = 1000         # every xCoin chain: COINBASE_MATURITY_MAINNET in kernel/chainparams.cpp
PQ_SIGNATURE_SIZE = 3309         # ML-DSA-65 signature (pqkey.h)
PQ_PUBKEY_SIZE = 1952            # ML-DSA-65 public key
V3_LEAF_SIZE = 34                # PUSH32 <SHA-256(pubkey)> OP_CHECKSIG
V3_CONTROL_ONE_LEAF = 33         # leaf version 0xc0 || SHA256("xcoin/v3/nokey"): carried single-leaf tree
V3_CONTROL_TWO_LEAF = 65         # ... || SLH-DSA sibling leaf hash: the two-leaf tree (every new address)
# Witness stack per v3 input, 4 items: count(1) + push(3)+pubkey + push(3)+sig
# (bare, SIGHASH_DEFAULT) + push(1)+leaf script + push(1)+control block.
WITNESS_V3_TWO_LEAF = 1 + 3 + PQ_PUBKEY_SIZE + 3 + PQ_SIGNATURE_SIZE + 1 + V3_LEAF_SIZE + 1 + V3_CONTROL_TWO_LEAF
WITNESS_V3_CARRIED = 1 + 3 + PQ_PUBKEY_SIZE + 3 + PQ_SIGNATURE_SIZE + 1 + V3_LEAF_SIZE + 1 + V3_CONTROL_ONE_LEAF
# Every input is budgeted as a two-leaf ML-DSA spend: exact for those, a 32-byte
# overestimate for carried inputs (never an underpaid fee).
WITNESS_PER_INPUT = WITNESS_V3_TWO_LEAF
INPUT_BASE_SIZE = 36 + 1 + 4     # outpoint + empty scriptSig len + sequence
OUTPUT_SIZE = 8 + 1 + 34         # value + script len + witness-v3 script
DUST_CHANGE = Decimal("0.0001")  # change below the consensus output floor (MIN_OUTPUT_VALUE_SAT = 10,000 sat) is folded into the fee; below it the tx is bad-txout-below-min-value
DEFAULT_MAX_FEE = Decimal("0.1")
MAX_STANDARD_TX_WEIGHT = 400_000  # node policy.h: heavier transactions are never relayed or mined

class WalletError(RuntimeError): pass

def money(v, what="amount"):
    try: return Decimal(str(v)).quantize(Decimal("0.00000001"))
    except InvalidOperation: raise WalletError(f"invalid {what}: {v!r}")

def money_ceil_sat(v):
    return v.quantize(Decimal("0.00000001"), rounding=ROUND_CEILING)

def fmt(v): return f"{money(v):f} XCF"
def fmt8(v): return f"{money(v):.8f}"

def jdefault(o):
    if isinstance(o, Decimal): return fmt8(o)
    raise TypeError(f"not JSON serializable: {type(o)}")

COMMITTED = False   # set once broadcast-begin reached the parent; before that a dead parent must stop the run

def say(text="", stream=None):
    """print + flush. Before the send is committed a closed pipe raises as usual, so a CLI whose
    parent (MMM) died before broadcast-begin stops with nothing sent. Once committed the text is
    dropped and the stream pointed at /dev/null, so an orphan finishes every broadcast and exits cleanly."""
    stream = stream or sys.stdout
    try: print(text, file=stream, flush=True)
    except OSError:
        if not COMMITTED: raise
        with contextlib.suppress(OSError, ValueError):
            fd = os.open(os.devnull, os.O_WRONLY); os.dup2(fd, stream.fileno()); os.close(fd)

def emit_json(data): say(json.dumps(data, indent=2, default=jdefault))

def event(*parts):
    """`XCOIN-EVENT <parts>` progress line on stderr for a parent program (MMM); only under XCOIN_EVENTS=1."""
    if os.getenv("XCOIN_EVENTS") == "1": say("XCOIN-EVENT " + " ".join(map(str, parts)), sys.stderr)

BROADCAST_GRACE = 0.5   # seconds between broadcast-begin and the first send (events on only)

def broadcast_begin(n):
    """Just before the first send. From here only a broadcast's own failure stops the loop:
    SIGPIPE is ignored and output goes through say(), so an orphaned CLI finishes every
    broadcast. XCOIN-EVENT broadcast-begin <n> stops the parent offering cancel; one it sent
    before reading the line lands in the pause, while nothing has gone out yet."""
    global COMMITTED
    if os.getenv("XCOIN_EVENTS") == "1":
        event("broadcast-begin", n)   # strict write: a parent already gone means nobody records the send, so send nothing
    COMMITTED = True
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    if os.getenv("XCOIN_EVENTS") == "1": time.sleep(BROADCAST_GRACE)

# --- .mmm wallet file format ---------------------------------------------
# magic(10) | salt(16) | nonce(16) | ciphertext(32-64) | hmac-sha256(32)
# key material: scrypt(passphrase, salt) -> enc_key(32) + mac_key(32)
# cipher: seed XOR shake256(enc_key || nonce); integrity: encrypt-then-MAC.
# With a passphrase this is real encryption; with an empty passphrase the file
# is still opaque + tamper-evident, but anyone with this open-source CLI could
# decode it — the passphrase is what makes it truly CLI-and-you-only.
MMM_MAGIC = b"XCOINMMM1\n"    # passphrase / plaintext-passphrase wallet
MMM2_MAGIC = b"XCOINMMM2\n"   # NTAG 424 DNA card-bound wallet
SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 15, 8, 1

def _scrypt(secret, salt):
    dk = hashlib.scrypt(secret, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=128 * 1024 * 1024, dklen=64)
    return dk[:32], dk[32:]

def _mmm_keys(passphrase, salt):
    return _scrypt(passphrase.encode(), salt)

def _card_module():
    """Lazy import — passphrase wallets never need pyscard/cryptography for cards."""
    d = str(Path(__file__).resolve().parent)
    if d not in sys.path: sys.path.insert(0, d)
    try:
        import card_seed
        return card_seed
    except Exception as e:
        raise WalletError(f"card support unavailable ({e}); install pyscard + cryptography")

def mmm2_encode(seed_hex, factor_bytes, family_hex, passphrase=""):
    payload = bytes.fromhex(seed_hex)
    salt, nonce = os.urandom(16), os.urandom(16)
    enc_key, mac_key = _scrypt(factor_bytes + passphrase.encode(), salt)
    stream = hashlib.shake_256(enc_key + nonce).digest(len(payload))
    body = MMM2_MAGIC + bytes.fromhex(family_hex) + salt + nonce + bytes(a ^ b for a, b in zip(payload, stream))
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()

def mmm2_family(blob):
    return blob[10:18].hex()

def mmm2_decode(blob, factor_bytes, passphrase=""):
    if len(blob) < len(MMM2_MAGIC) + 8 + 16 + 16 + 32 + 32: raise WalletError("corrupt .mmm (card) wallet file")
    salt, nonce = blob[18:34], blob[34:50]
    ct, mac = blob[50:-32], blob[-32:]
    if not 32 <= len(ct) <= 64: raise WalletError("corrupt .mmm (card) wallet file")
    enc_key, mac_key = _scrypt(factor_bytes + passphrase.encode(), salt)
    if not hmac.compare_digest(hmac.new(mac_key, blob[:-32], hashlib.sha256).digest(), mac):
        raise WalletError("wrong card (or passphrase), or corrupt wallet file")
    stream = hashlib.shake_256(enc_key + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream)).hex()

def is_card_wallet(path):
    """True for every card-bound format: mmm2, and the dex-era mmm3/mmm5 and card-kind mmm4."""
    return _wallet_format(path)[1]

def mmm_encode(seed_hex, passphrase):
    payload = bytes.fromhex(seed_hex)
    salt, nonce = os.urandom(16), os.urandom(16)
    enc_key, mac_key = _mmm_keys(passphrase, salt)
    stream = hashlib.shake_256(enc_key + nonce).digest(len(payload))
    body = MMM_MAGIC + salt + nonce + bytes(a ^ b for a, b in zip(payload, stream))
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()

def mmm_decode(blob, passphrase):
    if len(blob) < len(MMM_MAGIC) + 16 + 16 + 32 + 32: raise WalletError("corrupt .mmm wallet file")
    salt, nonce = blob[10:26], blob[26:42]
    ct, mac = blob[42:-32], blob[-32:]
    if not 32 <= len(ct) <= 64: raise WalletError("corrupt .mmm wallet file")
    enc_key, mac_key = _mmm_keys(passphrase, salt)
    if not hmac.compare_digest(hmac.new(mac_key, blob[:-32], hashlib.sha256).digest(), mac):
        raise WalletError("wrong passphrase (or corrupt .mmm wallet file)")
    stream = hashlib.shake_256(enc_key + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream)).hex()

def _valid_seed(seed):
    return len(seed) in range(64, 129, 2) and all(c in "0123456789abcdef" for c in seed.lower())

# --- dex-wallet-era formats (XCOINMMM3/4/5): READ/UNLOCK-ONLY ----------------
# Ported from dex-wallet-cli/wallet_cli.py so this CLI (and the MMM app that
# shells out to it) can OPEN those wallets; dex-wallet-cli remains the writer.
# v4: XCOINMMM4\n | kind(1: 1=passphrase,2=card,3=namelock) | [family(8) iff card kind]
#     | salt(16) | nonce(16) | ct | hmac(32); payload = 0x04 | seed_len(1) | seed(32-64) | slh_seed(48)
# v5: XCOINMMM5\n | kind 0x02 | family(8) | u16be len(A) | A | B
#     A = seal(passphrase, "XCOINMMM5A", json card key records)
#     B = seal(factor + passphrase, "XCOINMMM5B", v4 payload)
# Key material is the SAME scrypt as v1/v2 above (dex's SCRYPT_N/R/P are also
# 2^15/8/1, verified against its source); encrypt-then-MAC over the whole body.
MMM3_MAGIC = b"XCOINMMM3\n"   # v3: card-bound, FILENAME-locked (dex-only; not unlocked here)
MMM4_MAGIC = b"XCOINMMM4\n"   # v4: any kind; master seed + SLH-DSA seed (dex `new` wrote passphrase kind only)
MMM5_MAGIC = b"XCOINMMM5\n"   # v5: ONE-FILE card wallet (card key records live in the file)
MMM5A, MMM5B = b"XCOINMMM5A", b"XCOINMMM5B"
KIND_PASSPHRASE, KIND_CARD, KIND_NAMELOCK = 1, 2, 3
PAYLOAD_VERSION = 4

# HD derivation up to the SLH seed (pure hashing, ported verbatim from
# dex-wallet-cli/wallet_cli.py; must match src/pqhd.h and the keytool).
PQ_MASTER_DOMAIN = b"NEX-PQ-MASTER"
PQ_CHILD_DOMAIN = b"NEX-PQ-CHILD"
XCOIN_HD_SLH_SEED_DOMAIN = b"xcoin/hd/slh-dsa-sha2-128s/seed"
SLH_SEED_SIZE = 48

def child_seed(seed_hex, index):
    """SHAKE-256(SHAKE-256(seed || "NEX-PQ-MASTER")[32] || u32le(index) || "NEX-PQ-CHILD")[32]:
    the ML-DSA-65 KeyGen seed of key index `index` (the first chain's derivation, frozen)."""
    master = hashlib.shake_256(bytes.fromhex(seed_hex) + PQ_MASTER_DOMAIN).digest(32)
    return hashlib.shake_256(master + index.to_bytes(4, "little") + PQ_CHILD_DOMAIN).digest(32)

def slh_seed_from_child(child):
    """SHAKE-256(child32 || "xcoin/hd/slh-dsa-sha2-128s/seed")[48]: dex-wallet-cli's SLH seed (the
    node's stage-B3 domain; the keytool derives the same bytes for the 0xc2 leaf of every address)."""
    return hashlib.shake_256(child + XCOIN_HD_SLH_SEED_DOMAIN).digest(SLH_SEED_SIZE)

def slh_seed(seed_hex, index): return slh_seed_from_child(child_seed(seed_hex, index))

def _unseal(secret, blob, body_offset, min_ct, max_ct, wrong):
    """Ported verbatim from dex-wallet-cli (its _seal counterpart is write-side, not here)."""
    if len(blob) < body_offset + 16 + 16 + min_ct + 32: raise WalletError("corrupt .mmm wallet file")
    salt, nonce = blob[body_offset:body_offset + 16], blob[body_offset + 16:body_offset + 32]
    ct, mac = blob[body_offset + 32:-32], blob[-32:]
    if not min_ct <= len(ct) <= max_ct: raise WalletError("corrupt .mmm wallet file")
    enc_key, mac_key = _scrypt(secret, salt)
    if not hmac.compare_digest(hmac.new(mac_key, blob[:-32], hashlib.sha256).digest(), mac):
        raise WalletError(wrong)
    stream = hashlib.shake_256(enc_key + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream))

def parse_wallet_payload(payload):
    """Return the master seed hex of a v4 payload after checking its SLH-DSA seed
    (recomputed as slh_seed(seed, 0); a drifted derivation must never pass silently)."""
    if len(payload) < 2 or payload[0] != PAYLOAD_VERSION: raise WalletError("unknown .mmm payload version")
    n = payload[1]
    if not 32 <= n <= 64 or len(payload) != 2 + n + SLH_SEED_SIZE: raise WalletError("corrupt .mmm payload")
    seed_hex = payload[2:2 + n].hex()
    if not hmac.compare_digest(payload[2 + n:], slh_seed(seed_hex, 0)):
        raise WalletError("the SLH-DSA seed stored in this wallet does not match the one derived from its master seed "
                          "(key derivation drift: do not spend with this build; re-vendor pqcrypto and rebuild)")
    return seed_hex

def wallet_header(blob):
    """Describe any .mmm blob (ported verbatim from dex-wallet-cli): version, kind,
    family (card wallets) and where salt/nonce/ct start."""
    if blob.startswith(MMM4_MAGIC):
        if len(blob) < 11: raise WalletError("corrupt .mmm wallet file")
        kind = blob[10]
        if kind == KIND_PASSPHRASE: return {"version": 4, "kind": kind, "family": None, "body": 11}
        if kind in (KIND_CARD, KIND_NAMELOCK):
            if len(blob) < 19: raise WalletError("corrupt .mmm wallet file")
            return {"version": 4, "kind": kind, "family": blob[11:19].hex(), "body": 19}
        raise WalletError("unknown .mmm wallet kind")
    if blob.startswith(MMM3_MAGIC): return {"version": 3, "kind": KIND_NAMELOCK, "family": blob[10:18].hex(), "body": 18}
    if blob.startswith(MMM2_MAGIC): return {"version": 2, "kind": KIND_CARD, "family": blob[10:18].hex(), "body": 18}
    if blob.startswith(MMM_MAGIC): return {"version": 1, "kind": KIND_PASSPHRASE, "family": None, "body": 10}
    return None

def mmm4_decode(blob, secret_bytes):
    h = wallet_header(blob)
    if not h or h["version"] != 4: raise WalletError("not a v4 .mmm wallet file")
    wrong = ("wrong passphrase (or corrupt .mmm wallet file)" if h["kind"] == KIND_PASSPHRASE
             else "wrong card (or passphrase), or corrupt wallet file" if h["kind"] == KIND_CARD
             else "corrupt .mmm wallet file")   # a wrong FILENAME looks exactly like corruption
    return parse_wallet_payload(_unseal(secret_bytes, blob, h["body"], 2 + 32 + SLH_SEED_SIZE, 2 + 64 + SLH_SEED_SIZE, wrong))

def mmm5_parts(blob):
    if not blob.startswith(MMM5_MAGIC) or len(blob) < 21: raise WalletError("corrupt .mmm wallet file")
    if blob[10] != KIND_CARD: raise WalletError("unknown .mmm wallet kind")
    family = blob[11:19].hex()
    la = int.from_bytes(blob[19:21], "big")
    a, b = blob[21:21 + la], blob[21 + la:]
    if len(a) != la or not a.startswith(MMM5A) or not b.startswith(MMM5B): raise WalletError("corrupt .mmm wallet file")
    return family, a, b

def mmm5_cards(blob, passphrase):
    """The card key records, or WalletError('wrong passphrase…')."""
    _, a, _ = mmm5_parts(blob)
    raw = _unseal(passphrase.encode(), a, len(MMM5A), 2, 65536, "wrong passphrase (or corrupt .mmm wallet file)")
    try:
        cards = json.loads(raw.decode())
    except ValueError:
        raise WalletError("corrupt .mmm wallet file (card block)")
    if not isinstance(cards, list): raise WalletError("corrupt .mmm wallet file (card block)")
    return cards

def mmm5_seed(blob, factor_bytes, passphrase):
    _, _, b = mmm5_parts(blob)
    return parse_wallet_payload(_unseal(factor_bytes + passphrase.encode(), b, len(MMM5B),
                                        2 + 32 + SLH_SEED_SIZE, 2 + 64 + SLH_SEED_SIZE,
                                        "wrong card (or passphrase), or corrupt wallet file"))

class Mmm5CardStore:
    """READ-ONLY view of card_seed's key store kept INSIDE the .mmm file (block A).
    Adapted from dex-wallet-cli's MmmCardStore: unlock scope only, so the writing
    half (save/update/atomic rewrite) is deliberately not ported."""
    def __init__(self, path, passphrase):
        self.path, self.pw = Path(path), passphrase
        self.blob = self.path.read_bytes()
        self.family, _, self.sealed_b = mmm5_parts(self.blob)
        self.cards = mmm5_cards(self.blob, passphrase)
    def exists(self, uid_hex): return any(c.get("uid") == uid_hex for c in self.cards)
    def load(self, uid_hex):
        for c in self.cards:
            if c.get("uid") == uid_hex: return dict(c)
        raise WalletError(f"card {uid_hex} does not belong to this wallet")

def _head(path, n=32):
    try:
        with open(path, "rb") as f: return f.read(n)
    except OSError: return None

def _wallet_format(path):
    """(format, card) by sniffing the file head: mmm1|mmm2|mmm3|mmm4|mmm5-card|seed."""
    head = _head(path)
    if head is None: return None, False
    if head.startswith(MMM5_MAGIC): return "mmm5-card", True
    try: h = wallet_header(head)
    except WalletError: return "mmm4", False       # v4 magic, header truncated/unknown kind
    if h is None: return "seed", False             # no magic: plaintext seed (or foreign) file
    return f"mmm{h['version']}", h["kind"] in (KIND_CARD, KIND_NAMELOCK)

# A passphrase reaches this process in exactly two ways: typed at the terminal, or
# handed over a file descriptor by a parent program (--passphrase-fd N; NerdMiner
# login uses a pipe). Never the environment: an environment variable is readable
# by every other program the user runs and lands in shell history in plain text,
# so XCOIN_WALLET_PASSPHRASE is refused at startup (see main()).
PASSPHRASE_FROM_FD = None

def supplied_passphrase():
    """The passphrase a parent handed over --passphrase-fd, or None."""
    return PASSPHRASE_FROM_FD

def read_passphrase_fd(fd):
    """Read one line from fd (the passphrase), strip the newline, close the fd."""
    global PASSPHRASE_FROM_FD
    try:
        with os.fdopen(int(fd), "r", closefd=True) as f:
            PASSPHRASE_FROM_FD = f.readline().rstrip("\r\n")
    except (OSError, ValueError) as e:
        raise WalletError(f"--passphrase-fd {fd}: cannot read it ({e})")

def can_prompt():
    """True when this process may read the terminal: stdin is a tty AND we are the
    terminal's foreground process group. A child that a parent program started
    in its own process group (NerdMiner login) is not: reading the terminal would
    get it SIGTTIN and a silent hang, so it must report that it cannot ask and let
    the parent ask instead (the text below is what NerdMiner looks for)."""
    try:
        return sys.stdin.isatty() and os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp()
    except OSError:
        return False

NO_TERMINAL = "no terminal available to ask for the passphrase"

def unlock_passphrase_candidates():
    """Cheap candidates first: no-passphrase wallets never prompt."""
    yield ""
    pw = supplied_passphrase()
    if pw is not None: yield pw

def card_passphrase(required=False):
    """required=True (v5 one-file card wallets): the passphrase also guards the card
    keys kept in the file, so an empty one is refused early — exactly dex's rule."""
    pw = supplied_passphrase()
    if pw is None:
        if not can_prompt():
            if required: raise WalletError(f"card wallet: {NO_TERMINAL}; run it from a terminal or hand the passphrase over --passphrase-fd")
            return ""
        pw = getpass.getpass("Card wallet passphrase: " if required else "Card wallet passphrase (Enter if none): ")
    if required and not pw: raise WalletError("a card wallet needs its passphrase")
    return pw

@contextlib.contextmanager
def card_reader(cs):
    """A transport for ONE NFC wait, announced as XCOIN-EVENT card-wait <budget>;
    every card flow opens its waits here (the caller emits card-ok on success)."""
    transport = cs.PCSCTransport()
    try:
        event("card-wait", cs.card_timeout())
        yield transport
    finally:
        transport.close()

def tap_factor(cs, store=None):
    """The one card wait of an unlock."""
    with card_reader(cs) as transport:
        return cs.read_factor(transport, store)

def read_seed_card(blob):
    """Unlock a card-bound wallet: tap the matching card, read its factor over
    an authenticated+encrypted channel, derive the wallet key. The factor and
    seed live only in mlock'd secure buffers here."""
    cs = _card_module()
    cs.disable_core_dumps()
    want_family = mmm2_family(blob)
    factor, auth = tap_factor(cs)
    try:
        if cs.family_of(factor.bytes()) != want_family:
            raise WalletError("this card does not belong to this wallet (family mismatch)")
        pw = card_passphrase()
        seed = mmm2_decode(blob, factor.bytes(), pw)
        if not _valid_seed(seed): raise WalletError("decryption produced an invalid seed")
        event("card-ok")
        return seed.lower()
    finally:
        factor.close()

def read_seed_mmm5(path, blob):
    """Unlock a dex-era one-file card wallet (adapted from dex-wallet-cli's
    read_seed_mmm5): passphrase first (it opens the card keys), then the tap
    (the factor), then the seed. Factor and seed live in secure buffers."""
    cs = _card_module(); cs.disable_core_dumps()
    pw = card_passphrase(required=True)
    store = Mmm5CardStore(path, pw)                       # wrong passphrase fails here, before any tap
    print("Tap your wallet card on the reader…", file=sys.stderr)
    factor, _auth = tap_factor(cs, store)
    try:
        if cs.family_of(factor.bytes()) != store.family:
            raise WalletError("this card does not belong to this wallet (family mismatch)")
        seed = mmm5_seed(blob, factor.bytes(), pw)
        if not _valid_seed(seed): raise WalletError("decryption produced an invalid seed")
        event("card-ok")
        return seed.lower()
    finally:
        factor.close()

def _read_seed_passphrase(blob, decode):
    """The passphrase unlock loop (ported verbatim from dex-wallet-cli): a v4 SLH
    derivation-drift error must surface, never read as one more wrong passphrase."""
    for pw in unlock_passphrase_candidates():
        try: seed = decode(blob, pw)
        except WalletError as e:
            if "drift" in str(e): raise
            continue
        if _valid_seed(seed): return seed.lower()
    if not can_prompt():
        raise WalletError(f"wallet is passphrase-protected and {NO_TERMINAL}; run it from a terminal or hand the passphrase over --passphrase-fd")
    for _ in range(3):
        try:
            seed = decode(blob, getpass.getpass("Wallet passphrase: "))
            if _valid_seed(seed): return seed.lower()
        except WalletError as e:
            if "drift" in str(e): raise
            print(f"error: {e}", file=sys.stderr)
    raise WalletError("could not unlock wallet")

def read_seed(path):
    try: blob = Path(path).read_bytes()
    except FileNotFoundError: raise WalletError(f"no wallet at {path}; run `xcoin-wallet new`")
    if blob.startswith(MMM5_MAGIC):
        return read_seed_mmm5(path, blob)
    if blob.startswith(MMM4_MAGIC):
        if wallet_header(blob)["kind"] != KIND_PASSPHRASE:
            # dex-wallet-cli's `new` only ever wrote passphrase-kind v4 (its card wallets are v5)
            raise WalletError("this v4 wallet uses a card (unsupported kind here); unlock it with dex-wallet-cli")
        return _read_seed_passphrase(blob, lambda b, pw: mmm4_decode(b, pw.encode()))
    if blob.startswith(MMM3_MAGIC):
        raise WalletError("this is a name-locked card wallet (XCOINMMM3); unlock it with dex-wallet-cli")
    if blob.startswith(MMM2_MAGIC):
        return read_seed_card(blob)
    if blob.startswith(MMM_MAGIC):
        return _read_seed_passphrase(blob, mmm_decode)
    try: seed = blob.decode().strip()
    except UnicodeDecodeError: raise WalletError("wallet seed file is invalid")
    if not _valid_seed(seed): raise WalletError("wallet seed file is invalid")
    return seed.lower()

def new_passphrase(args):
    """Ask (twice) for a passphrase for a wallet being created; '' = none."""
    pw = supplied_passphrase()
    if pw is not None: return pw
    if not can_prompt() or args.json: return ""
    while True:
        a = getpass.getpass("Encryption passphrase (Enter for none): ")
        if not a:
            print("No passphrase: the .mmm file is opaque + tamper-evident, but not secret from")
            print("someone who has both the file and this open-source CLI. A passphrase fixes that.")
            return ""
        b = getpass.getpass("Confirm passphrase: ")
        if a == b: return a
        print("passphrases do not match, try again", file=sys.stderr)

def write_seed(path, seed, passphrase=None):
    """New wallets are written in .mmm format; plaintext is legacy/read-only.
    The KDF runs before anything touches disk, and the wallet appears complete or
    not at all: link() publishes the temp file and never replaces an existing one."""
    p = Path(path); p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    blob = mmm_encode(seed, passphrase or "")
    def put(q):
        fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f: f.write(blob); f.flush(); os.fsync(f.fileno())
        except BaseException:
            q.unlink(missing_ok=True); raise
    tmp = p.with_name(f".{p.name}.{os.urandom(6).hex()}.tmp"); put(tmp)
    try: os.link(tmp, p); return
    except FileExistsError: raise
    except OSError: pass   # no hard links here (exFAT, some shares): exclusive create instead
    finally: tmp.unlink(missing_ok=True)
    put(p)

def parse_conf(path):
    out = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1); out[k.strip()] = v.strip()
    except FileNotFoundError: pass
    return out

# ── bech32m + local transaction tooling (for the --explorer backend) ─────────
# The bech32m math is the chain's own (BIP-350); witness v3 programs are the
# 32-byte Merkle roots the keytool derives (two-leaf, or the carried single leaf).
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _b32_polymod(values):
    GEN = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1: chk ^= GEN[i]
    return chk
def _b32_hrp_expand(hrp): return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
def _convertbits(data, frombits, tobits, pad):
    acc = bits = 0; ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or v >> frombits: return None
        acc = (acc << frombits) | v; bits += frombits
        while bits >= tobits:
            bits -= tobits; ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret
def bech32m_decode_address(addr, hrps=("xpa", "txa")):
    """-> (hrp, witver, program bytes) or None."""
    a = addr.strip()
    if a != a.lower() and a != a.upper(): return None
    a = a.lower()
    if "1" not in a: return None
    hrp, data = a.rsplit("1", 1)
    if hrp not in hrps or len(data) < 7: return None
    try: values = [_B32.index(c) for c in data]
    except ValueError: return None
    if _b32_polymod(_b32_hrp_expand(hrp) + values) != 0x2bc830a3: return None
    prog = _convertbits(values[1:-6], 5, 8, False)
    if prog is None: return None
    return hrp, values[0], bytes(prog)
def address_to_spk(addr, hrp):
    dec = bech32m_decode_address(addr, hrps=(hrp,))
    if not dec or dec[1] != 3 or len(dec[2]) != 32:
        raise WalletError(f"destination is not a witness-v3 {hrp}1r… address")
    return bytes([0x53, 0x20]) + dec[2]

def _compactsize(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")
def build_unsigned_tx(inputs, outputs, locktime=0):
    """inputs: [{"txid","vout"}], outputs: [(spk bytes, sats int)] -> raw hex.
    version 2, RBF sequence 0xfffffffd — the node wallet's own defaults."""
    b = bytearray()
    b += (2).to_bytes(4, "little")
    b += _compactsize(len(inputs))
    for i in inputs:
        b += bytes.fromhex(i["txid"])[::-1]
        b += int(i["vout"]).to_bytes(4, "little")
        b += b"\x00"
        b += (0xFFFFFFFD).to_bytes(4, "little")
    b += _compactsize(len(outputs))
    for spk, sats in outputs:
        b += int(sats).to_bytes(8, "little")
        b += _compactsize(len(spk)) + spk
    b += int(locktime).to_bytes(4, "little")
    return bytes(b).hex()
def parse_signed_tx(hexstr):
    """-> {"txid", "vsize", "size"} computed locally (no node needed)."""
    raw = bytes.fromhex(hexstr); pos = 0
    def u32():
        nonlocal pos; v = int.from_bytes(raw[pos:pos+4], "little"); pos += 4; return v
    def cpt():
        nonlocal pos; c = raw[pos]; pos += 1
        if c < 0xfd: return c
        n = {0xfd: 2, 0xfe: 4, 0xff: 8}[c]
        v = int.from_bytes(raw[pos:pos+n], "little"); pos += n; return v
    base = bytearray()
    version = raw[0:4]; pos = 4
    segwit = raw[pos] == 0 and raw[pos+1] == 1
    if segwit: pos += 2
    base += version
    nin_at = pos; nin = cpt(); base += raw[nin_at:pos]
    for _ in range(nin):
        start = pos; pos += 36; sl = cpt(); pos += sl; pos += 4
        base += raw[start:pos]
    nout_at = pos; nout = cpt(); base += raw[nout_at:pos]
    for _ in range(nout):
        start = pos; pos += 8; sl = cpt(); pos += sl
        base += raw[start:pos]
    if segwit:
        for _ in range(nin):
            items = cpt()
            for _ in range(items):
                il = cpt(); pos += il
    base += raw[pos:pos+4]                     # locktime
    h = hashlib.sha256(hashlib.sha256(bytes(base)).digest()).digest()
    weight = len(base) * 3 + len(raw)
    return {"txid": h[::-1].hex(), "vsize": (weight + 3) // 4, "size": len(raw)}

class ExplorerRPC:
    """The explorer backend: balance, UTXOs, feerate and broadcast through the
    public superknet.com JSON API — for wallets (MMM miners) with no node of
    their own. Same trust story the page states: the explorer only reports
    chain data and forwards raw transactions; keys and signing stay here."""
    is_explorer = True
    def __init__(self, base, hrp=None):
        self.base = base.rstrip("/")
        if not self.base.startswith(("http://", "https://")): self.base = "https://" + self.base
        self._hrp_given = hrp
        self.conf = {}
    @property
    def _hrp(self):
        if self._hrp_given: return self._hrp_given
        try:
            self._hrp_given = str(self._get("/api/stats").get("hrp") or "txa")
        except WalletError:
            self._hrp_given = "txa"
        return self._hrp_given
    def _get(self, path, timeout=60):
        req = urllib.request.Request(self.base + path, headers={"User-Agent": "xcoin-wallet-cli"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r, parse_float=Decimal)
        except urllib.error.HTTPError as e:
            try: out = json.loads(e.read().decode(), parse_float=Decimal)
            except Exception: raise WalletError(f"explorer {path}: HTTP {e.code}")
            raise WalletError(f"explorer {path}: {out.get('error', 'failed') if isinstance(out, dict) else out}")
        except Exception as e:
            raise WalletError(f"cannot reach the explorer at {self.base}: {e}")
    def call(self, method, params=None, timeout=60):
        params = params or []
        if method == "getblockchaininfo":
            return {"chain": f"via explorer ({self._hrp})"}
        if method == "validateaddress":
            dec = bech32m_decode_address(params[0], hrps=(self._hrp,))
            if not dec or dec[1] != 3 or len(dec[2]) != 32: return {"isvalid": False}
            return {"isvalid": True, "witness_version": 3,
                    "scriptPubKey": (bytes([0x53, 0x20]) + dec[2]).hex()}
        if method == "scantxoutset":
            # The caller hands us raw(<spk>) descriptors (a key index's two-leaf AND
            # carried scripts); recover each address for the API and merge. Both
            # forms are OP_3 PUSH32 <root>, so one re-encoding covers them.
            height, total, unspents, seen = None, Decimal(0), [], set()
            for desc in params[1]:
                spk = desc[4:-1] if desc.startswith("raw(") and desc.endswith(")") else ""
                if not (len(spk) == 68 and spk.startswith("5320")):
                    raise WalletError("explorer backend can only scan witness-v3 scripts")
                data = _convertbits(bytes.fromhex(spk[4:]), 8, 5, True)
                values = [3] + data
                chk = _b32_polymod(_b32_hrp_expand(self._hrp) + values + [0]*6) ^ 0x2bc830a3
                addr = self._hrp + "1" + "".join(_B32[v] for v in values) + "".join(_B32[(chk >> (5*(5-i))) & 31] for i in range(6))
                out = self._get(f"/api/utxos/{addr}", timeout=timeout)
                if not isinstance(out, dict) or not isinstance(out.get("utxos"), list):
                    raise WalletError(f"explorer returned no UTXO list for {addr}")
                if out.get("height") is not None: height = max(height or 0, int(out["height"]))
                for u in out["utxos"]:
                    key = (u["txid"], u["vout"])
                    if key in seen: continue          # never count one output twice
                    seen.add(key)
                    total += Decimal(str(u["amount"]))
                    unspents.append({k: v for k, v in {
                        "txid": u["txid"], "vout": u["vout"],
                        # the explorer's own script, so tag_kinds can cross-check it
                        "scriptPubKey": str(u.get("scriptPubKey") or spk).lower(), "amount": u["amount"],
                        "coinbase": u.get("coinbase", False), "height": u.get("height"),
                        "confirmations": u.get("confirmations")}.items() if v is not None})
            return {"success": True, "height": height, "total_amount": total, "unspents": unspents}
        if method == "getmempoolinfo":
            # the chain's relay floor: DEFAULT_MIN_RELAY_TX_FEE = 1,000 sat/kvB = 1 sat/vB
            return {"minrelaytxfee": Decimal("0.00001000")}
        if method == "estimatesmartfee":
            out = self._get("/api/feerate")
            satvb = Decimal(str(out.get("feerate_sat_vb", 1)))
            return {"feerate": satvb * 1000 / Decimal(100000000)}   # sat/vB -> XCF/kvB
        if method == "createrawtransaction":
            ins, outs = params[0], params[1]
            pairs = []
            for o in outs:
                for addr, amt in o.items():
                    sats = int((money(amt) * Decimal(100000000)).to_integral_value())
                    pairs.append((address_to_spk(addr, self._hrp), sats))
            return build_unsigned_tx(ins, pairs)
        if method == "sendrawtransaction":
            body = json.dumps({"hex": params[0]}).encode()
            req = urllib.request.Request(self.base + "/api/broadcast", data=body,
                                         headers={"Content-Type": "application/json", "User-Agent": "xcoin-wallet-cli"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return json.load(r)["txid"]
            except urllib.error.HTTPError as e:
                try: out = json.loads(e.read().decode())
                except Exception: raise WalletError(f"broadcast failed: HTTP {e.code}")
                raise WalletError(f"broadcast rejected: {out.get('reason', out.get('error', 'unknown')) if isinstance(out, dict) else out}")
            except WalletError: raise
            except Exception as e:
                raise WalletError(f"cannot reach the explorer at {self.base}: {e}")
        raise WalletError(f"`{method}` needs a node; it is not available via the explorer backend")

def make_backend(args):
    explorer = getattr(args, "explorer", None) or os.getenv("XCOIN_EXPLORER")
    if explorer: return ExplorerRPC(explorer, getattr(args, "hrp", None))
    rpc = RPC(args)
    if getattr(args, "hrp", None): rpc._hrp = args.hrp
    return rpc

class RPC:
    def __init__(self, args):
        self.conf = parse_conf(args.config)
        self.host = args.rpc_host or self.conf.get("rpcconnect", "127.0.0.1")
        self.port = args.rpc_port or int(self.conf.get("rpcport", "9432"))
        self.user = args.rpc_user or self.conf.get("rpcuser") or os.getenv("XCOIN_RPC_USER")
        self.password = args.rpc_password or self.conf.get("rpcpassword") or os.getenv("XCOIN_RPC_PASSWORD")
        if not self.user or not self.password:
            raise WalletError("RPC credentials missing; set them in nex.conf or use --rpc-user/--rpc-password")
    def call(self, method, params=None, timeout=60):
        body = json.dumps({"jsonrpc": "1.0", "id": "xcoin-wallet", "method": method,
                           "params": params or []}, default=jdefault).encode()
        req = urllib.request.Request(f"http://{self.host}:{self.port}/", data=body,
                                     headers={"Content-Type": "application/json"})
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result = json.load(response, parse_float=Decimal)
        except urllib.error.HTTPError as e:
            # The node answers RPC-level errors with HTTP 500 + a JSON body;
            # surface the real message instead of a generic connection error.
            try: result = json.loads(e.read().decode(), parse_float=Decimal)
            except Exception: raise WalletError(f"RPC {method} failed: HTTP {e.code}")
        except Exception as e:
            raise WalletError(f"cannot reach nexd RPC at {self.host}:{self.port}: {e}")
        if result.get("error"):
            raise WalletError(f"RPC {method}: {result['error'].get('message', result['error'])}")
        return result.get("result")

def keytool_path():
    """The native ML-DSA keytool binary (offline signer), alongside this script."""
    p = Path(__file__).resolve().parent / "xcoin-wallet"
    return p if p.exists() and os.access(p, os.X_OK) else None

def sign_offline(seed, raw, prev):
    """Sign the raw tx with the native keytool — the seed never leaves this host
    or reaches the node. Seed + tx + prevouts go to the tool over stdin (never
    argv). Returns the signed tx hex."""
    tool = keytool_path()
    if not tool:
        raise WalletError("offline signer not found: build the native keytool (`NEX=.. ./build.sh`) "
                          "; there is no alternative: the seed never leaves this host")
    lines = [seed, raw]
    for u in prev:
        sats = int((money(u["amount"]) * Decimal("100000000")).to_integral_value())
        lines.append(f'{u["txid"]} {u["vout"]} {u["scriptPubKey"]} {sats} {u["keyindex"]}')
    stdin = ("\n".join(lines) + "\n").encode()
    try:
        proc = subprocess.run([str(tool), "sign"], input=stdin, capture_output=True, timeout=120)
    except Exception as e:
        raise WalletError(f"offline signer could not run: {e}")
    if proc.returncode != 0:
        raise WalletError(f"offline signing failed: {proc.stderr.decode(errors='replace').strip()}")
    out = proc.stdout.decode().strip()
    if not out or any(c not in "0123456789abcdef" for c in out.lower()):
        raise WalletError("offline signer returned no valid transaction")
    return out


def resolve_hrp(args):
    """HRP for offline-capable commands: --hrp wins; a configured explorer is
    asked; a fully offline run defaults to mainnet's xpa."""
    if getattr(args, "hrp", None): return args.hrp
    if getattr(args, "explorer", None) or os.getenv("XCOIN_EXPLORER"):
        try: return backend_hrp(make_backend(args))
        except WalletError: pass
    return "xpa"

def backend_hrp(rpc, args=None):
    """The chain's address HRP: --hrp wins, else the backend's chain answers
    (main -> xpa, anything else -> txa), else xpa. Cached on the backend."""
    if args is not None and getattr(args, "hrp", None): return args.hrp
    if rpc is None: return "xpa"
    h = getattr(rpc, "_hrp", None)
    if h: return h
    try:
        chain = (rpc.call("getblockchaininfo") or {}).get("chain", "")
    except WalletError:
        chain = ""
    h = "xpa" if chain in ("", "main", "mainnet") else "txa"
    rpc._hrp = h
    return h

def derive_offline(seed, index, hrp="xpa"):
    """Derive address `index` with the native keytool — the seed never leaves this
    host or reaches the node. The seed goes to the tool over stdin (never argv).
    Returns {address, scriptPubKey, program, carried_address, carried_scriptPubKey,
    carried_program, identity, ...}: `address` is the witness v3 xpa1r…/txa1r…
    two-leaf tree {ML-DSA-65, SLH-DSA-SHA2-128s}, `carried_address` the single-leaf
    {ML-DSA-65} tree of the same key (what earlier builds printed; still ours and
    spendable), `identity` the forum handle xid1… of the same key (bech32m over
    SHA-256(pubkey) with no witness version: a handle, nothing can be paid to it)."""
    tool = keytool_path()
    if not tool:
        raise WalletError("offline keytool not found: build the native keytool (`NEX=.. ./build.sh`) "
                          "; there is no alternative: the seed never leaves this host")
    try:
        proc = subprocess.run([str(tool), "_address", "--index", str(int(index)), "--hrp", hrp],
                              input=(seed + "\n").encode(), capture_output=True, timeout=60)
    except Exception as e:
        raise WalletError(f"offline keytool could not run: {e}")
    if proc.returncode != 0:
        raise WalletError(f"offline derivation failed: {proc.stderr.decode(errors='replace').strip()}")
    try:
        info = json.loads(proc.stdout.decode())
    except ValueError:
        raise WalletError("offline keytool returned no valid address")
    if not isinstance(info, dict) or not info.get("address") or not info.get("scriptPubKey") or not info.get("identity"):
        raise WalletError("offline keytool returned an incomplete address (rebuild it: `NEX=.. ./build.sh`)")
    # A keytool from before the two-leaf upgrade prints the single-leaf tree as
    # "address" and no carried_* fields: refuse it rather than mistake one form for the other.
    if not info.get("carried_address") or not info.get("carried_scriptPubKey"):
        raise WalletError("offline keytool predates two-leaf addresses (rebuild it: `NEX=.. ./build.sh`)")
    return info

def derive(rpc, seed, index):
    """Address for key `index`, derived OFFLINE: the seed never reaches the node."""
    return derive_offline(seed, index, backend_hrp(rpc))

def scan(rpc, scripts):
    """scantxoutset over raw(<scriptPubKey>) descriptors (one hex script or a list)."""
    if isinstance(scripts, str): scripts = [scripts]
    result = rpc.call("scantxoutset", ["start", [f"raw({s})" for s in scripts]], timeout=300)
    if not result or not result.get("success"): raise WalletError("UTXO scan failed")
    return result

def wallet_scripts(info):
    """scriptPubKey hex -> kind for one key index: the two-leaf tree and the carried tree."""
    return {info["scriptPubKey"]: "two_leaf", info["carried_scriptPubKey"]: "carried"}

def tag_kinds(result, kinds):
    """Tag each scanned UTXO with the form ("two_leaf" | "carried") of the script it
    pays. A UTXO on neither script is not this key's and is dropped (a scan only
    returns what was asked for; this guards a misbehaving backend)."""
    unspents = []
    for u in result.get("unspents", []):
        spk = u.get("scriptPubKey")
        kind = kinds.get(spk.lower()) if isinstance(spk, str) else None
        if kind is None: continue
        u["kind"] = kind
        unspents.append(u)
    result["unspents"] = unspents
    return result

def require_seed(args): return read_seed(args.file)

def classify_utxos(result):
    """Split scan results into (mature, immature) with normalized Decimal amounts."""
    tip = result.get("height", 0)
    mature, immature = [], []
    for u in result.get("unspents", []):
        u["amount"] = money(u["amount"])
        confs = u.get("confirmations")
        if confs is None: confs = tip - u.get("height", tip) + 1
        u["confirmations"] = confs
        if u.get("coinbase") and confs < COINBASE_MATURITY:
            u["blocks_to_maturity"] = COINBASE_MATURITY - confs
            immature.append(u)
        else:
            mature.append(u)
    return mature, immature

def estimate_sizes(n_in, n_out):
    """(total_bytes, vsize) for a fully signed PQ transaction."""
    def varint(n): return 1 if n < 0xfd else 3
    base = 4 + varint(n_in) + INPUT_BASE_SIZE * n_in + varint(n_out) + OUTPUT_SIZE * n_out + 4
    witness = 2 + WITNESS_PER_INPUT * n_in  # marker+flag + per-input stacks
    total = base + witness
    vsize = (base * 4 + witness + 3) // 4
    return total, vsize

def fee_for(n_in, n_out, feerate):
    _, vsize = estimate_sizes(n_in, n_out)
    return money_ceil_sat(feerate * vsize / 1000)

def resolve_feerate(rpc, args):
    """Return (feerate XCF/kvB, source). Never below the node's relay floor."""
    floor = Decimal("0.00001000")   # 1 sat/vB: the chain's DEFAULT_MIN_RELAY_TX_FEE
    try:
        mi = rpc.call("getmempoolinfo")
        floor = max(money(mi.get("minrelaytxfee", floor)), money(mi.get("mempoolminfee", 0)))
    except WalletError: pass
    if args.feerate is not None:
        rate = money(args.feerate, "feerate")
        if rate < floor: raise WalletError(f"feerate {fmt8(rate)} is below the relay floor {fmt8(floor)}")
        return rate, "--feerate"
    try:
        est = rpc.call("estimatesmartfee", [6])
        if est and est.get("feerate"): return max(money(est["feerate"]), floor), "estimatesmartfee"
    except WalletError: pass
    fallback = rpc.conf.get("fallbackfee")
    if fallback: return max(money(fallback, "fallbackfee"), floor), "fallbackfee"
    return max(floor * 10, floor), "relay floor x10"

def max_inputs():
    """Most inputs one transaction can carry within MAX_STANDARD_TX_WEIGHT (2 outputs budgeted)."""
    n = 0
    while estimate_sizes(n + 1, 2)[1] * 4 <= MAX_STANDARD_TX_WEIGHT: n += 1
    return n

def plan_payment(mature, amount, feerate=None, fixed_fee=None, split=False):
    """Largest-first selection (fewer huge PQ inputs = smaller tx = lower fee), as
    a list of independent transactions [(selected, pay, fee, change)] paying
    `amount` in total. Each carries at most max_inputs() inputs; one that cannot
    finish the payment spends them all to the destination and the next carries
    on (only with `split`: otherwise that is the "split the send" error). Every
    payment and change is >= DUST_CHANGE: sub-dust change of the last transaction
    is folded into its fee, and an earlier one that would leave a sub-dust rest
    keeps DUST_CHANGE as change instead. Fees budget 2 outputs per transaction."""
    coins = sorted(mature, key=lambda x: x["amount"], reverse=True)
    cap, plan, left, pos = max_inputs(), [], amount, 0
    def short(selected, total, fee):
        have = sum((u["amount"] for u in coins[:pos + len(selected)]), Decimal(0))
        return WalletError(f"insufficient spendable funds: have {fmt(have)}, need about {fmt(have - total + left + fee)}")
    while True:
        selected, total, fee = [], Decimal(0), fixed_fee
        for u in coins[pos:pos + cap]:
            selected.append(u); total += u["amount"]
            fee = fixed_fee if fixed_fee is not None else fee_for(len(selected), 2, feerate)
            if total >= left + fee:
                change = money(total - left - fee)
                if 0 < change < DUST_CHANGE:
                    fee = money(fee + change); change = Decimal(0)
                plan.append((selected, money(left), money(fee), change)); return plan
        if fee is None: fee = fee_for(1, 2, feerate)
        if len(selected) < cap or pos + cap >= len(coins): raise short(selected, total, fee)
        if not split:
            if sum((x["amount"] for x in mature), Decimal(0)) >= amount:
                raise WalletError(f"one transaction can carry at most {len(selected)} inputs ({fmt(total)} from these UTXOs); "
                                  f"send at most about {fmt(total)} now and the rest in another send")
            raise short(selected, total, fee)
        if fixed_fee is not None:
            raise WalletError("--fee fixes one transaction's fee; a split send needs a fee rate (--feerate, or neither)")
        pay, change = money(total - fee), Decimal(0)
        if left - pay < DUST_CHANGE: pay, change = money(pay - DUST_CHANGE), DUST_CHANGE
        if pay < DUST_CHANGE: raise short(selected, total, fee)
        plan.append((selected, pay, money(fee), change))
        left -= pay; pos += cap

def select_coins(mature, amount, feerate=None, fixed_fee=None):
    """One-transaction selection: (selected, fee, change); see plan_payment."""
    (selected, _pay, fee, change), = plan_payment(mature, amount, feerate, fixed_fee)
    return selected, fee, change

def wallet_scan(args):
    """Derive key --index and scan BOTH of its scripts (two-leaf + carried) in one call."""
    rpc, seed = make_backend(args), require_seed(args); info = derive(rpc, seed, args.index)
    kinds = wallet_scripts(info)
    return rpc, seed, info, tag_kinds(scan(rpc, list(kinds)), kinds)

def maturity_note(immature):
    if not immature: return ""
    soonest = min(u["blocks_to_maturity"] for u in immature)
    total = sum(u["amount"] for u in immature)
    return f"{fmt(total)} immature ({len(immature)} coinbase UTXO{'s' if len(immature) != 1 else ''}, next spendable in {soonest} block{'s' if soonest != 1 else ''})"

def clipboard_copy(text):
    """Copy via pbcopy stdin — the secret never appears in argv, env, or ps."""
    if not shutil.which("pbcopy"): raise WalletError("pbcopy not found (clipboard support is macOS-only)")
    subprocess.run(["pbcopy"], input=text.encode(), check=True)

def clipboard_paste():
    if not shutil.which("pbpaste"): raise WalletError("pbpaste not found (clipboard support is macOS-only)")
    return subprocess.run(["pbpaste"], capture_output=True, check=True).stdout.decode()

def clipboard_clear():
    subprocess.run(["pbcopy"], input=b"", check=True)

def schedule_clipboard_clear(seconds, secret):
    """Detached watcher that clears the clipboard after N seconds — but only if
    it still holds the seed (compared by SHA-256, so no secret is passed to the
    watcher in any form)."""
    digest = hashlib.sha256(secret.encode()).hexdigest()
    script = ('sleep "$1"; '
              'if [ "$(pbpaste | /usr/bin/shasum -a 256 | cut -d" " -f1)" = "$2" ]; '
              'then printf "" | pbcopy; fi')
    subprocess.Popen(["/bin/sh", "-c", script, "clipwipe", str(int(seconds)), digest],
                     start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def offer_wipe(args):
    """After a seed was shown, wipe it from the screen AND scrollback on request.

    `clear` only blanks the visible screen — the seed survives in terminal
    scrollback. ESC[3J purges scrollback too (Terminal.app, iTerm2). The seed
    stays retrievable from the wallet file (mode 600) via `xcoin-wallet seed`.
    """
    if getattr(args, "no_clear", False) or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    try:
        input("\nWrite the seed down now. Press Enter to WIPE it from screen + scrollback (Ctrl-C to leave it)... ")
    except (KeyboardInterrupt, EOFError):
        print("\nseed left on screen — clear it yourself with Cmd+K (Terminal/iTerm)"); return
    print("\033[2J\033[3J\033[H", end="", flush=True)
    print("Seed wiped from screen and scrollback. (If your terminal still shows it, use Cmd+K.)")
    print("It remains safe in the wallet file; re-display any time with `xcoin-wallet seed`.")

def cmd_new(args):
    p = Path(args.file)
    if p.exists(): raise WalletError(f"refusing to overwrite existing wallet {p}")
    if args.card:
        return cmd_new_card(args, p)
    seed = os.urandom(32).hex(); write_seed(p, seed, new_passphrase(args))
    data = {"file": str(p)}
    if not args.offline:
        data["address"] = derive(make_backend(args), seed, 0)["address"]
    if args.json:
        # The seed is deliberately NOT included in JSON output; read the file
        # or use `seed --json --yes`.
        emit_json(data); return
    print(f"Created wallet: {p}\nSeed: {seed}\n\nWRITE THE SEED DOWN OFFLINE. Anyone with it controls the wallet.")
    offer_wipe(args)
    print(f"Wallet file:     {p}")
    if "address" in data: print(f"Primary address: {data['address']}")

def cmd_new_card(args, p):
    """Create a card-bound wallet. The seed is generated, encrypted to the
    card, and NEVER displayed — no paper backup exists by design, so a duplicate
    backup card is offered immediately."""
    cs = _card_module(); cs.disable_core_dumps()
    if not args.offline and args.json:
        raise WalletError("card wallet creation is interactive; use --offline for JSON")
    factor = cs.SecureBuffer(os.urandom(cs.FACTOR_LEN))
    seedbuf = cs.SecureBuffer(os.urandom(32))
    try:
        family = cs.family_of(factor.bytes())
        print("Provisioning the PRIMARY card — tap and hold it on the reader.", file=sys.stderr)
        with card_reader(cs) as transport:
            record = cs.provision_card(transport, factor, family, label=args.label or "primary")
        event("card-ok")
        auth_file = cs.auth_path(record["uid"])   # provision_card already saved it (crash-safe)
        pw = new_passphrase(args)   # optional second factor
        blob = mmm2_encode(seedbuf.hex(), factor.bytes(), family, pw)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f: f.write(blob)
        address = derive(make_backend(args), seedbuf.hex(), 0)["address"] if not args.offline else None
        permanent = not args.resettable
        if permanent:
            cs.make_permanent(record["uid"])   # commit: discard master+write keys — IRREVERSIBLE
        data = {"file": str(p), "card_uid": record["uid"], "family": family,
                "auth_file": str(auth_file), "passphrase_protected": bool(pw),
                "permanent": permanent}
        if address: data["address"] = address
    finally:
        seedbuf.close(); factor.close()
    if args.json: emit_json(data); return
    print(f"\nCard-bound wallet created: {p}")
    print(f"  Primary card UID: {data['card_uid']}   family: {family}")
    print(f"  Card keys stored: {data['auth_file']} (mode 600)")
    print("  The seed was NEVER displayed and cannot be — the card is the key.")
    if data["permanent"]:
        print("  SEALED PERMANENTLY: master + write keys discarded — this card can never")
        print("  be reset or reused, and its factor can never be rewritten.")
    if "address" in data: print(f"  Primary address:  {data['address']}")
    print("\nIMPORTANT: with no printed seed, this card is your ONLY backup.")
    print("Make a DUPLICATE backup card now:  xcoin-wallet card-backup --file " + str(p))

def cmd_card_backup(args):
    """Make a DUPLICATE backup card carrying the same factor as this wallet.
    Tap the existing card (to read the factor), then tap a factory card."""
    cs = _card_module(); cs.disable_core_dumps()
    p = Path(args.file)
    if not is_card_wallet(p): raise WalletError(f"{p} is not a card-bound wallet")
    if _wallet_format(p)[0] != "mmm2":
        raise WalletError("this is a dex-wallet-era card wallet (read-only here); make backup cards with dex-wallet-cli")
    want_family = mmm2_family(p.read_bytes())
    print("Step 1/2 — tap an EXISTING card for this wallet (to copy its key).", file=sys.stderr)
    with card_reader(cs) as t1:
        factor, _auth = cs.read_factor(t1)
    try:
        if cs.family_of(factor.bytes()) != want_family:
            raise WalletError("that card does not belong to this wallet")
        event("card-ok")
        input("Step 2/2 — remove it, place a FACTORY card, then press Enter... ")
        with card_reader(cs) as t2:
            record = cs.provision_card(t2, factor, want_family, label=args.label or "backup")
        event("card-ok")
        auth_file = cs.auth_path(record["uid"])
        permanent = not args.resettable
        if permanent:
            cs.make_permanent(record["uid"])
    finally:
        factor.close()
    if args.json: emit_json({"backup_card_uid": record["uid"], "auth_file": str(auth_file),
                             "family": want_family, "permanent": permanent}); return
    print(f"\nBackup card ready — UID {record['uid']} (family {want_family}).")
    print(f"Card keys stored: {auth_file}")
    if permanent: print("Sealed permanently (master + write keys discarded).")
    print("Either card now unlocks this wallet. Store them in separate physical locations.")

def cmd_card_test(args):
    """Read-only proof that a provisioned card authenticates and yields a factor.
    Does not touch any wallet file; safe to run anytime."""
    cs = _card_module(); cs.disable_core_dumps()
    with card_reader(cs) as t:
        factor, auth = cs.read_factor(t)
    event("card-ok")
    try:
        fam = cs.family_of(factor.bytes())
    finally:
        factor.close()
    if args.json: emit_json({"ok": True, "uid": auth["uid"], "family": fam, "label": auth.get("label")}); return
    print(f"Card OK — UID {auth['uid']}, family {fam}, label {auth.get('label','?')}")
    print("EV2 authentication succeeded and a wallet factor was read over the encrypted channel.")

def cmd_card_reset(args):
    """Factory-reset a card (wipe factor + restore factory keys) and remove its
    auth file. Guarded: refuses unless --yes. Never touches a wallet file."""
    cs = _card_module(); cs.disable_core_dumps()
    if not args.yes: raise WalletError("card-reset erases the card; pass --yes to confirm")
    with card_reader(cs) as t:
        uid = cs.factory_reset_card(t)
    event("card-ok")
    auth = cs.auth_path(uid)
    moved = None
    if auth.exists():
        moved = auth.with_suffix(".auth.removed")
        shutil.move(auth, moved)
    if args.json: emit_json({"reset_uid": uid, "auth_moved_to": str(moved) if moved else None}); return
    print(f"Card {uid} returned to factory state.")
    if moved: print(f"Its key file was moved to {moved} (kept, not deleted — remove it yourself once sure).")
    print("WARNING: if this was the last card for a wallet, that wallet is now UNRECOVERABLE.")

def cmd_card_list(args):
    """List provisioned cards known to this Mac (from ~/.xcoin/card-*.auth)."""
    cs = _card_module()
    rows = []
    for f in sorted(cs.AUTH_DIR.glob("card-*.auth")):
        try: rec = json.loads(f.read_text())
        except Exception: continue
        rows.append({"uid": rec.get("uid"), "family": rec.get("family"),
                     "label": rec.get("label"), "created": rec.get("created")})
    if args.json: emit_json(rows); return
    if not rows: print("No provisioned cards on this Mac."); return
    for r in rows:
        print(f"{r['uid']}  family={r['family']}  {r.get('label','')}  ({r.get('created','')})")

def cmd_seed(args):
    """Re-display or copy the master seed from the wallet file, with guarded output."""
    if is_card_wallet(args.file):
        raise WalletError("this is a card-bound wallet — the seed is sealed to the card and is "
                          "never revealed by design. Use the card to sign; back it up with `card-backup`.")
    seed = require_seed(args)
    if args.copy:
        if not args.yes:
            if not sys.stdin.isatty():
                raise WalletError("refusing to copy the seed non-interactively; pass --yes to override")
            answer = input(f"Copy the MASTER SEED to the clipboard? Auto-clears in {args.timeout}s. [y/N] ").strip().lower()
            if answer != "y": raise WalletError("cancelled")
        clipboard_copy(seed)
        if args.timeout > 0: schedule_clipboard_clear(args.timeout, seed)
        note = f"clipboard auto-clears in {args.timeout}s" if args.timeout > 0 else "clipboard will NOT auto-clear (--timeout 0)"
        msg = (f"Seed copied to clipboard ({note}).\n"
               "WARNING: clipboard managers keep history, and Handoff/Universal Clipboard\n"
               "can sync the clipboard to your other Apple devices. Paste it, then clear.")
        if args.json: emit_json({"copied": True, "timeout": args.timeout}); return
        print(msg); return
    if args.json:
        if not args.yes: raise WalletError("seed --json requires --yes (explicit confirmation to emit the seed)")
        emit_json({"file": str(args.file), "seed": seed}); return
    if not args.yes:
        if not sys.stdin.isatty():
            raise WalletError("refusing to print the seed non-interactively; pass --yes to override")
        answer = input("This prints your MASTER SEED. Anyone who sees it controls the wallet.\nType REVEAL to continue: ").strip()
        if answer != "REVEAL": raise WalletError("cancelled")
    print(f"Seed: {seed}")
    offer_wipe(args)

def cmd_receive(args):
    # Address derivation is offline: no node, no RPC credentials needed.
    # `address`/`receive` print the two-leaf address; `--carried` the single-leaf
    # form of the same key; `--identity` (or the `identity` subcommand) the same
    # key's forum handle xid1… instead.
    info = derive_offline(require_seed(args), args.index, resolve_hrp(args))
    carried = getattr(args, "carried", False)
    if args.json:
        emit_json({"address": info["address"], "identity": info["identity"], "index": args.index,
                   "scriptPubKey": info["scriptPubKey"], "carried_address": info["carried_address"],
                   "carried_scriptPubKey": info["carried_scriptPubKey"]}); return
    print(info["identity"] if args.identity else info["carried_address"] if carried else info["address"])
    if args.verbose:
        print(f"index: {args.index}\nscriptPubKey: {info['carried_scriptPubKey'] if carried and not args.identity else info['scriptPubKey']}")
        if args.identity or carried: print(f"address: {info['address']}")
        if not args.identity: print(f"identity: {info['identity']}")
        if not carried: print(f"carried address (single-leaf, same key): {info['carried_address']}")
        print("tree: {ML-DSA-65 leaf 0xc0} (carried single-leaf form)" if carried and not args.identity
              else "tree: {ML-DSA-65 leaf 0xc0, SLH-DSA-SHA2-128s fallback leaf 0xc2}")

def cmd_signmessage(args):
    """Sign a text message with the ML-DSA-65 key at --index, for a service that
    verifies FIPS 204 signatures (MineDifferent sign-in). The signer is named by
    its forum identity xid1… by default: `{address}` in the template is replaced
    by the xid1… string and the JSON "address" field carries it (NerdMiner posts
    that field to the forum as 'address'), so one unlock signs a message that
    names the signer. `--as address` names the witness v3 payment address instead.
    Prints one JSON line {"address","identity","witness_address","pubkey",
    "sig","message_hex","index"}; the seed goes to the native keytool over stdin
    and never reaches the node or the network."""
    seed = read_seed(args.file)
    index = int(args.index)
    tool = keytool_path()
    if not tool:
        raise WalletError("offline keytool not found: build the native keytool (`NEX=.. ./build.sh`)")
    template = args.template if args.template is not None else args.message
    if template is None or template == "":
        raise WalletError("signmessage needs --template TEXT (with {address}) or --message TEXT")
    hrp = resolve_hrp(args)
    info = derive_offline(seed, index, hrp)
    signer = info["address"] if args.sign_as == "address" else info["identity"]
    message = template.replace("{address}", signer)
    # Multi-line messages are fine (the forum's challenge is four lines): the
    # message travels to the keytool as one hex line, never as raw text.
    msg_hex = message.encode("utf-8").hex()
    try:
        proc = subprocess.run([str(tool), "_signmsg", "--index", str(index), "--hrp", hrp],
                              input=(seed + "\n" + msg_hex + "\n").encode(), capture_output=True, timeout=120)
    except Exception as e:
        raise WalletError(f"offline keytool could not run: {e}")
    if proc.returncode != 0:
        raise WalletError(f"signing failed: {proc.stderr.decode(errors='replace').strip()}")
    try:
        out = json.loads(proc.stdout.decode())
    except ValueError:
        raise WalletError("offline keytool returned no signature")
    if out.get("address") != info["address"]:
        raise WalletError("keytool address does not match the derived address")
    if out.get("identity") != info["identity"]:
        raise WalletError("keytool identity does not match the derived identity")
    result = {"address": signer, "identity": info["identity"], "witness_address": info["address"],
              "pubkey": out["pubkey"], "sig": out["sig"], "message_hex": msg_hex, "index": index}
    print(json.dumps(result))

def cmd_addresses(args):
    seed = require_seed(args)                  # offline derivation: no RPC needed
    rows = []
    hrp = resolve_hrp(args)
    for i in range(args.start, args.start + args.count):
        info = derive_offline(seed, i, hrp)
        row = {"index": i, "address": info["address"], "carried_address": info["carried_address"]}
        if args.identity: row["identity"] = info["identity"]
        rows.append(row)
    if args.json: emit_json(rows); return
    # one two-leaf address per line; --carried adds the single-leaf column, --identity the xid1… one
    for r in rows: print(f"{r['index']:5d}  {r['address']}" + (f"  {r['carried_address']}" if args.carried else "")
                         + (f"  {r['identity']}" if args.identity else ""))

def form_totals(mature, immature, kind, address):
    sp = sum((u["amount"] for u in mature if u["kind"] == kind), Decimal(0))
    im = sum((u["amount"] for u in immature if u["kind"] == kind), Decimal(0))
    return {"address": address, "spendable": sp, "immature": im, "total": sp + im,
            "utxos": sum(1 for u in mature + immature if u["kind"] == kind),
            "immature_utxos": sum(1 for u in immature if u["kind"] == kind)}

def cmd_balance(args):
    _, _, info, result = wallet_scan(args)
    mature, immature = classify_utxos(result)
    spendable = sum((u["amount"] for u in mature), Decimal(0))
    pending = sum((u["amount"] for u in immature), Decimal(0))
    forms = {"two_leaf": form_totals(mature, immature, "two_leaf", info["address"]),
             "carried": form_totals(mature, immature, "carried", info["carried_address"])}
    data = {"address": info["address"], "carried_address": info["carried_address"], "index": args.index,
            "spendable": spendable, "immature": pending, "total": spendable + pending,
            "utxos": len(mature) + len(immature), "immature_utxos": len(immature),
            "height": result.get("height"), "forms": forms}
    if args.json: emit_json(data); return
    print(f"Address:       {info['address']}\nIndex:         {args.index}")
    print(f"Spendable:     {fmt(spendable)}")
    if immature:
        print(f"Immature:      {maturity_note(immature)}")
    print(f"Total:         {fmt(spendable + pending)}")
    if forms["carried"]["utxos"]:
        c, t = forms["carried"], forms["two_leaf"]
        print(f"  two-leaf:    {fmt(t['total'])} in {t['utxos']} UTXO{'s' if t['utxos'] != 1 else ''}")
        print(f"  carried:     {fmt(c['total'])} in {c['utxos']} UTXO{'s' if c['utxos'] != 1 else ''} on {info['carried_address']} (single-leaf, same key; spendable)")
    print(f"UTXOs:         {data['utxos']}\nScan height:   {data['height']}")

def cmd_utxos(args):
    _, _, _, result = wallet_scan(args)
    mature, immature = classify_utxos(result)
    rows = [{"txid": u["txid"], "vout": u["vout"], "amount": u["amount"], "kind": u["kind"],
             "height": u.get("height"), "confirmations": u["confirmations"],
             "coinbase": bool(u.get("coinbase")), "spendable": u not in immature,
             **({"blocks_to_maturity": u["blocks_to_maturity"]} if u in immature else {})}
            for u in mature + immature]
    if args.json: emit_json(rows); return
    if not rows: print("No unspent outputs."); return
    for r in rows:
        note = " coinbase" if r["coinbase"] else ""
        if r["kind"] == "carried": note += " carried"
        if not r["spendable"]: note += f" IMMATURE ({r['blocks_to_maturity']} blocks left)"
        print(f"{r['txid']}:{r['vout']}  {fmt(r['amount'])}  height={r['height']} confs={r['confirmations']}{note}")
    print(f"Total: {fmt(sum(r['amount'] for r in rows))}  (spendable: {fmt(sum(r['amount'] for r in rows if r['spendable']))})")

def cmd_send(args):
    rpc, seed, own, result = wallet_scan(args)
    chain = rpc.call("getblockchaininfo").get("chain", "?")
    valid = rpc.call("validateaddress", [args.destination])
    if not valid or not valid.get("isvalid"): raise WalletError("destination is not a valid address for this node")
    amount = money(args.amount)
    if amount <= 0: raise WalletError("amount must be positive")
    if amount < DUST_CHANGE:
        raise WalletError(f"amount {fmt(amount)} is below the consensus output floor {fmt(DUST_CHANGE)} (10,000 sat); the network rejects such outputs")
    max_fee = money(args.max_fee, "max-fee")
    mature, immature = classify_utxos(result)

    split = getattr(args, "split", False)
    try:
        if args.fee is not None:
            fixed = money(args.fee, "fee")
            if fixed < 0: raise WalletError("fee must be non-negative")
            plan = plan_payment(mature, amount, fixed_fee=fixed, split=split)
            rate_desc = "fixed via --fee"
        else:
            feerate, source = resolve_feerate(rpc, args)
            plan = plan_payment(mature, amount, feerate=feerate, split=split)
            rate_desc = f"{fmt8(feerate)}/kvB via {source}"
    except WalletError as e:
        if immature and "insufficient" in str(e):
            raise WalletError(f"{e}; note: {maturity_note(immature)}")
        raise
    n = len(plan)
    fee, change = money(sum(t[2] for t in plan)), money(sum(t[3] for t in plan))
    if fee > max_fee:   # a split send is guarded on its total
        raise WalletError(f"{'total fee' if n > 1 else 'fee'} {fmt(fee)} exceeds --max-fee {fmt(max_fee)}; pass a higher --max-fee to allow it")

    selected = [u for t in plan for u in t[0]]
    sizes = [estimate_sizes(len(s), 2 if c > 0 else 1) for s, _, _, c in plan]
    est_total, est_vsize = sum(b for b, _ in sizes), sum(v for _, v in sizes)
    n_carried = sum(1 for u in selected if u["kind"] == "carried")
    many = " in total" if n > 1 else ""
    if not args.json:
        print("Transaction preview" + (f" (split into {n} transactions)" if n > 1 else ""))
        print(f"  Chain:       {chain}")
        print(f"  From:        {own['address']} (index {args.index})" + (" + its carried single-leaf form" if n_carried else ""))
        print(f"  To:          {args.destination}")
        print(f"  Amount:      {fmt(amount)}{many}")
        print(f"  Fee:         {fmt(fee)}{many} ({rate_desc})")
        print(f"  Change:      {fmt(change)}")
        print(f"  Inputs:      {len(selected)}" + (f" ({n_carried} carried)" if n_carried else "") + f"  (~{est_total} bytes, ~{est_vsize} vbytes signed)")
        for i, (s, pay, f, c) in enumerate(plan if n > 1 else [], 1):
            print(f"  Tx {i}/{n}:".ljust(15) + f"{len(s)} inputs, pays {fmt(pay)}, fee {fmt(f)}" + (f", change {fmt(c)}" if c > 0 else ""))
        print("  Signing:     OFFLINE keytool (seed stays here)" + ("; all signed before the first broadcast" if n > 1 else ""))
        if immature: print(f"  Excluded:    {maturity_note(immature)}")
    if not args.yes:
        if args.json: raise WalletError("--json send requires --yes (no interactive prompt in JSON mode)")
        answer = input("Type SEND to sign" + (f" all {n} transactions" if n > 1 else "") + (" (dry run)" if args.dry_run else " and broadcast") + ": ").strip()
        if answer != "SEND": raise WalletError("cancelled")

    # The seed was unlocked once (one card tap) by wallet_scan; every transaction is
    # signed with it before the first broadcast.
    txs = []
    for i, (sel, pay, f, c) in enumerate(plan, 1):
        outputs = [{args.destination: fmt8(pay)}]
        if c > 0: outputs.append({own["address"]: fmt8(c)})   # change always to the two-leaf address
        raw = rpc.call("createrawtransaction", [[{"txid": u["txid"], "vout": u["vout"]} for u in sel], outputs])
        # Each prevout carries its own script (two-leaf or carried); the keytool matches it
        # against the key's two trees and signs the ML-DSA leaf with the right control block.
        prev = [{"txid": u["txid"], "vout": u["vout"], "scriptPubKey": u["scriptPubKey"],
                 "amount": u["amount"], "keyindex": args.index} for u in sel]
        # Sign OFFLINE in the native keytool: the seed never reaches the node.
        event("signing", i, n)
        txs.append({"hex": sign_offline(seed, raw, prev), "pay": pay, "fee": f, "change": c, "inputs": len(sel),
                    "carried_inputs": sum(1 for u in sel if u["kind"] == "carried")})
    signer = "offline keytool"

    for t in txs:
        if getattr(rpc, "is_explorer", False):
            # No local node: txid/vsize computed here; the explorer's broadcast
            # endpoint runs testmempoolaccept itself before relaying.
            local = parse_signed_tx(t["hex"])
            t.update(txid=local["txid"], size=local["size"], vsize=local["vsize"], mempool_accept=None)
        else:
            # one per call: two near-cap transactions exceed the node's package weight limit
            verdict = (rpc.call("testmempoolaccept", [[t["hex"]]]) or [{}])[0]
            decoded = rpc.call("decoderawtransaction", [t["hex"]])
            t.update(txid=decoded.get("txid"), size=len(t["hex"]) // 2, vsize=decoded.get("vsize"),
                     mempool_accept=bool(verdict.get("allowed")))
            if not verdict.get("allowed"): t["reject_reason"] = verdict.get("reject-reason", "unknown")
    bad = [(i, t) for i, t in enumerate(txs, 1) if t["mempool_accept"] is False]
    if bad and not args.dry_run:
        i, t = bad[0]
        raise WalletError(f"node would reject {'this transaction' if n == 1 else f'transaction {i} of {n}'} "
                          f"({t['reject_reason']}); nothing was broadcast")

    sent, error = [], None
    if not args.dry_run: broadcast_begin(n)
    for i, t in enumerate([] if args.dry_run else txs, 1):
        try: t["txid"] = rpc.call("sendrawtransaction", [t["hex"]])
        except Exception as e:
            if not sent:        # a lost connection can hide a success: name what to look up
                raise WalletError(f"{e}. Nothing is confirmed sent, but if the connection dropped it may have gone out: "
                                  f"look up {t['txid']} before sending again"
                                  + (f" (the other {n - 1} transactions were never broadcast)" if n > 1 else "")) from e
            error = e; break    # earlier ones are out (independent coins): report exactly those
        sent.append(t); event("broadcast", i, n, t["txid"])

    shown = txs if args.dry_run else sent
    if not split:
        t = txs[0]
        data = {"txid": t["txid"], "size": t["size"], "vsize": t["vsize"], "fee": fee, "change": change, "signer": signer,
                "inputs": t["inputs"], "carried_inputs": t["carried_inputs"], "mempool_accept": t["mempool_accept"], "broadcast": bool(sent)}
        if "reject_reason" in t: data["reject_reason"] = t["reject_reason"]
    else:
        # totals cover exactly the listed txids: all of them, or the ones a partial send got out
        data = {"broadcast": bool(sent), "txid": shown[0]["txid"], "txids": [t["txid"] for t in shown], "transactions": n,
                "amount": money(sum(t["pay"] for t in shown)), "fee": money(sum(t["fee"] for t in shown)),
                "vsize": sum(t["vsize"] or 0 for t in shown), "change": money(sum(t["change"] for t in shown)),
                "inputs": sum(t["inputs"] for t in shown), "carried_inputs": sum(t["carried_inputs"] for t in shown),
                "signer": signer, "partial": error is not None, "size": sum(t["size"] for t in shown),
                "mempool_accept": None if txs[0]["mempool_accept"] is None else not bad}
        if bad: data["reject_reason"] = bad[0][1]["reject_reason"] if n == 1 else "; ".join(f"transaction {i}: {t['reject_reason']}" for i, t in bad)
        if error is not None:   # a lost connection can hide a success: name what to look up
            data.update(broadcast_error=str(error), unsent_txids=[t["txid"] for t in txs[len(sent):]])
    if args.json: emit_json(data)
    elif n == 1:
        t = txs[0]
        if not args.dry_run: say(f"Broadcast successful\nTXID: {t['txid']}")
        else:
            say(f"Dry run: signed OK, NOT broadcast.\nTXID: {t['txid']}\nSigned bytes: {t['size']} ({t['vsize']} vbytes)")
            say("Mempool check: performed by the explorer at broadcast" if t["mempool_accept"] is None else
                "Mempool check: would be accepted" if t["mempool_accept"] else f"Mempool check: would be REJECTED ({t['reject_reason']})")
    else:
        say(f"Dry run: {n} transactions signed OK, NOT broadcast." if args.dry_run else
            f"Broadcast successful: {n} transactions" if error is None else
            f"PARTIAL SEND: {len(sent)} of {n} transactions broadcast; transaction {len(sent) + 1} failed: {error}")
        for i, t in enumerate(txs, 1):
            # the one that failed is UNKNOWN (a lost connection can hide a success); later ones were never tried
            check = (("" if i <= len(sent) else "  UNKNOWN: look it up" if i == len(sent) + 1 else "  NOT SENT") if not args.dry_run else
                     "  (mempool check at broadcast)" if t["mempool_accept"] is None else
                     "  (would be accepted)" if t["mempool_accept"] else f"  (would be REJECTED: {t['reject_reason']})")
            say(f"  {i}/{n}  TXID: {t['txid']}  pays {fmt(t['pay'])}, fee {fmt(t['fee'])}, {t['vsize']} vbytes{check}")
        if error is not None:
            say(f"Paid {fmt(data['amount'])} of {fmt(amount)}. Look up {txs[len(sent)]['txid']} before paying the rest again: "
                "if the connection dropped it may have gone out." + (" The NOT SENT transactions were never broadcast." if len(sent) + 1 < n else ""))
    event("done")

def cmd_history(args):
    rpc, seed = make_backend(args), require_seed(args)
    info = derive(rpc, seed, args.index); scripts = set(wallet_scripts(info))   # two-leaf + carried
    tip = rpc.call("getblockcount")
    events, my_outpoints = [], {}
    for h in range(args.from_height, tip + 1):
        block = rpc.call("getblock", [rpc.call("getblockhash", [h]), 2], timeout=300)
        for tx in block.get("tx", []):
            received = Decimal(0); spent = Decimal(0)
            is_coinbase = any("coinbase" in vin for vin in tx.get("vin", []))
            for vin in tx.get("vin", []):
                key = (vin.get("txid"), vin.get("vout"))
                if key in my_outpoints: spent += my_outpoints.pop(key)
            for out in tx.get("vout", []):
                if out.get("scriptPubKey", {}).get("hex") in scripts:
                    amt = money(out["value"])
                    received += amt; my_outpoints[(tx["txid"], out["n"])] = amt
            if received or spent:
                events.append({"txid": tx["txid"], "height": h, "time": block.get("time"),
                               "received": received, "spent": spent, "net": received - spent,
                               "coinbase": is_coinbase, "confirmations": tip - h + 1})
    for txid in rpc.call("getrawmempool", []):
        try: tx = rpc.call("getrawtransaction", [txid, 1])
        except WalletError: continue
        received = sum((money(o["value"]) for o in tx.get("vout", [])
                        if o.get("scriptPubKey", {}).get("hex") in scripts), Decimal(0))
        spent = sum((my_outpoints[(v.get("txid"), v.get("vout"))] for v in tx.get("vin", [])
                     if (v.get("txid"), v.get("vout")) in my_outpoints), Decimal(0))
        if received or spent:
            events.append({"txid": txid, "height": None, "time": None, "received": received,
                           "spent": spent, "net": received - spent, "coinbase": False, "confirmations": 0})
    if args.json: emit_json({"address": info["address"], "carried_address": info["carried_address"], "index": args.index, "tip": tip, "events": events}); return
    if not events: print(f"No transactions for {info['address']} (or its carried form)"); return
    print(f"History for {info['address']} (index {args.index}, tip {tip}; includes the carried address)")
    for e in events:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(e["time"])) if e["time"] else "mempool         "
        where = f"{e['height']:>7}" if e["height"] is not None else "unconf."
        sign = "+" if e["net"] >= 0 else ""
        note = " coinbase" if e["coinbase"] else ""
        if e["coinbase"] and e["confirmations"] < COINBASE_MATURITY:
            note += f" (immature, {COINBASE_MATURITY - e['confirmations']} blocks left)"
        print(f"{where}  {when}  {sign}{fmt(e['net'])}  {e['txid']}{note}")

def cmd_info(args):
    rpc = make_backend(args)
    chain = rpc.call("getblockchaininfo"); net = rpc.call("getnetworkinfo"); mem = rpc.call("getmempoolinfo")
    data = {"chain": chain.get("chain"), "blocks": chain.get("blocks"), "headers": chain.get("headers"),
            "bestblockhash": chain.get("bestblockhash"), "difficulty": str(chain.get("difficulty")),
            "mediantime": chain.get("mediantime"), "initialblockdownload": chain.get("initialblockdownload"),
            "size_on_disk": chain.get("size_on_disk"), "warnings": chain.get("warnings"),
            "version": net.get("subversion"), "connections": net.get("connections"),
            "connections_in": net.get("connections_in"), "connections_out": net.get("connections_out"),
            "relayfee": money(net.get("relayfee", 0)),
            "mempool_txs": mem.get("size"), "mempool_bytes": mem.get("bytes"),
            "mempool_min_fee": money(mem.get("mempoolminfee", 0))}
    if args.json: emit_json(data); return
    sync = "synced" if not data["initialblockdownload"] else "SYNCING (initial block download)"
    print(f"Chain:         {data['chain']} ({sync})")
    print(f"Height:        {data['blocks']} (headers {data['headers']})")
    print(f"Best block:    {data['bestblockhash']}")
    print(f"Median time:   {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['mediantime']))}")
    print(f"Difficulty:    {data['difficulty']}")
    print(f"Node:          {data['version']}  peers={data['connections']} (in {data['connections_in']} / out {data['connections_out']})")
    print(f"Mempool:       {data['mempool_txs']} txs, {data['mempool_bytes']} bytes, min fee {fmt8(data['mempool_min_fee'])}/kvB")
    print(f"Relay fee:     {fmt8(data['relayfee'])}/kvB")
    for w in data.get("warnings") or []: print(f"Warning:       {w}")

def cmd_restore(args):
    p = Path(args.file)
    if p.exists(): raise WalletError(f"refusing to overwrite existing wallet {p}; use reset or another --file")
    sources = [bool(args.seed), args.paste, bool(args.from_file)]
    if sum(sources) > 1: raise WalletError("pick one seed source: argument, --paste, or --from-file")
    used_clipboard = False
    if args.paste:
        seed = clipboard_paste(); used_clipboard = True
    elif args.from_file:
        src = Path(args.from_file).expanduser()
        try: seed = src.read_text()
        except OSError as e: raise WalletError(f"cannot read seed file {src}: {e}")
    elif args.seed:
        print("warning: seed passed on the command line lands in your shell history and `ps` output;\n"
              "         prefer the hidden prompt, --paste, or --from-file — see README 'Seed hygiene'", file=sys.stderr)
        seed = args.seed
    else:
        seed = getpass.getpass("Seed (hidden): ")
    seed = seed.strip().lower()
    if not _valid_seed(seed):
        raise WalletError("seed must be 32-64 bytes of hex" + (" (clipboard did not hold a valid seed)" if used_clipboard else ""))
    write_seed(p, seed, new_passphrase(args))
    if used_clipboard:
        clipboard_clear()
    note = "; clipboard cleared" if used_clipboard else ""
    if args.json: emit_json({"file": str(p), "restored": True, "clipboard_cleared": used_clipboard}); return
    print(f"Wallet restored to {p}{note}")

def cmd_backup(args):
    src = Path(args.file)
    if is_card_wallet(src):
        # Copy the encrypted file only — never touch the card. Useless without it.
        dst = Path(args.destination).expanduser()
        if dst.is_dir(): dst /= f"xcoin-wallet-{time.strftime('%Y%m%d-%H%M%S')}.mmm"
        if dst.exists(): raise WalletError(f"backup destination exists: {dst}")
        dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst); os.chmod(dst, 0o600)
        if args.json: emit_json({"backup": str(dst), "card_bound": True}); return
        print(f"Encrypted wallet file copied: {dst}")
        print("This file is useless without the card. To back up the KEY itself, use `card-backup`.")
        return
    read_seed(src)
    encrypted = src.read_bytes().startswith(MMM_MAGIC)
    dst = Path(args.destination).expanduser()
    if dst.is_dir(): dst /= f"xcoin-wallet-{time.strftime('%Y%m%d-%H%M%S')}" + (".mmm" if encrypted else ".seed")
    if dst.exists(): raise WalletError(f"backup destination exists: {dst}")
    dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst); os.chmod(dst, 0o600)
    if args.json: emit_json({"backup": str(dst), "encrypted": encrypted}); return
    print(f"Backup created: {dst}")
    if not encrypted:
        print("note: this backup is PLAINTEXT (legacy format); run `xcoin-wallet encrypt` to switch to .mmm")

def cmd_encrypt(args):
    """Convert a legacy plaintext wallet to .mmm, or re-key an existing .mmm wallet."""
    src = Path(args.file)
    if is_card_wallet(src):
        raise WalletError("this is a card-bound wallet; converting it to a passphrase would expose the seed. "
                          "Use `card-backup` for redundancy or `card-reset` to retire a card.")
    seed = read_seed(src)                      # prompts for the current passphrase if needed
    was_mmm = src.read_bytes().startswith(MMM_MAGIC)
    if supplied_passphrase() is None and not can_prompt():
        raise WalletError(f"encrypt needs a passphrase and {NO_TERMINAL}: run it from a terminal or hand it over --passphrase-fd")
    pw = new_passphrase(args)
    if was_mmm:
        tmp = src.with_name(src.name + ".rekey-tmp")
        if tmp.exists(): raise WalletError(f"stale temp file exists: {tmp}")
        write_seed(tmp, seed, pw); os.replace(tmp, src)
        if args.json: emit_json({"file": str(src), "rekeyed": True}); return
        print(f"Wallet re-encrypted in place: {src}"); return
    target = src.with_suffix(".mmm")
    if target.exists(): raise WalletError(f"target already exists: {target}")
    write_seed(target, seed, pw)
    moved = src.with_name(src.name + ".plaintext-backup")
    if moved.exists(): raise WalletError(f"backup destination exists: {moved}")
    shutil.move(src, moved); os.chmod(moved, 0o600)
    if args.json: emit_json({"file": str(target), "plaintext_moved_to": str(moved)}); return
    print(f"Encrypted wallet written: {target}")
    print(f"Old PLAINTEXT seed moved to: {moved}")
    print("Verify the new wallet (e.g. `xcoin-wallet address`), then store that file offline or delete it yourself.")

def cmd_wallets(args):
    """List the wallet files in ~/.xcoin AND ~/.dex-wallet (dex-era formats open
    read-only here): every *.mmm plus the legacy wallet.seed. The starred/default
    entry is what commands use when no --file is given (same precedence as
    default_wallet(): ~/.xcoin only). Sniffs headers only — never prompts."""
    default = Path(default_wallet())
    rows = []
    for d in (Path.home() / ".xcoin", Path.home() / ".dex-wallet"):
        if not d.exists(): continue
        candidates = sorted(d.glob("*.mmm"))
        legacy = d / "wallet.seed"
        if legacy.exists(): candidates.append(legacy)
        for f in candidates:
            st = f.stat()
            fmt, card = _wallet_format(f)
            rows.append({"name": f.name, "file": str(f), "format": fmt, "card": card,
                         "modified": int(st.st_mtime), "default": f == default})
    if args.json: emit_json(rows); return
    if not rows: print("No wallets in ~/.xcoin or ~/.dex-wallet — run `xcoin-wallet-cli new`."); return
    home = str(Path.home())
    for r in rows:
        shown = r["file"].replace(home, "~", 1)
        print(f"{'*' if r['default'] else ' '} {shown}  ({r['format']}{', card' if r['card'] else ''}, modified {time.strftime('%Y-%m-%d %H:%M', time.localtime(r['modified']))})")

def cmd_reset(args):
    src = Path(args.file); read_seed(src)
    if not args.yes: raise WalletError("reset requires --yes and --backup <path>")
    dst = Path(args.backup).expanduser()
    if dst.is_dir(): dst /= f"xcoin-wallet-reset-{time.strftime('%Y%m%d-%H%M%S')}.seed"
    if dst.exists(): raise WalletError(f"backup destination exists: {dst}")
    dst.parent.mkdir(parents=True, exist_ok=True); shutil.move(src, dst); os.chmod(dst, 0o600)
    if args.json: emit_json({"moved_to": str(dst)}); return
    print(f"Wallet reset. Original seed moved safely to: {dst}\nRun `xcoin-wallet new` to create a new wallet.")

def parser():
    p = argparse.ArgumentParser(prog="xcoin-wallet", description="Post-quantum Xcoin self-custody wallet")
    p.add_argument("--file", default=str(default_wallet())); p.add_argument("--config", default=str(DEFAULT_CONFIG))
    p.add_argument("--rpc-host"); p.add_argument("--rpc-port", type=int); p.add_argument("--rpc-user"); p.add_argument("--rpc-password")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--explorer", metavar="URL", help="use a public explorer (e.g. superknet.com) instead of a local node: balance/UTXOs/fees/broadcast go through its JSON API; keys and signing stay on this Mac (env: XCOIN_EXPLORER)")
    p.add_argument("--hrp", choices=("xpa", "txa"), help="address HRP: xpa mainnet, txa testnet A (default: asked of the node, or txa via --explorer)")
    p.add_argument("--passphrase-fd", type=int, metavar="N", help="read the wallet passphrase from file descriptor N (a pipe from a parent program); never from the environment")
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("new", help="create a new wallet")
    q.add_argument("--offline", action="store_true")
    q.add_argument("--no-clear", action="store_true", help="skip the screen/scrollback wipe offer")
    q.add_argument("--card", action="store_true", help="bind the wallet to an NTAG 424 DNA card (seed never displayed)")
    q.add_argument("--label", help="label for the provisioned card")
    q.add_argument("--resettable", action="store_true", help="keep factory-key rollback (card can be reset); default is permanent/sealed")
    q.set_defaults(fn=cmd_new)
    q = sub.add_parser("card-provision", help="alias: create a card-bound wallet"); q.add_argument("--offline", action="store_true"); q.add_argument("--label"); q.add_argument("--resettable", action="store_true"); q.set_defaults(fn=cmd_new, card=True, no_clear=True)
    q = sub.add_parser("card-backup", help="make a duplicate backup card for a card wallet"); q.add_argument("--label"); q.add_argument("--resettable", action="store_true"); q.set_defaults(fn=cmd_card_backup)
    q = sub.add_parser("card-test", help="prove a provisioned card authenticates (read-only)"); q.set_defaults(fn=cmd_card_test)
    q = sub.add_parser("card-reset", help="factory-reset a card and remove its key file"); q.add_argument("--yes", action="store_true"); q.set_defaults(fn=cmd_card_reset)
    q = sub.add_parser("card-list", help="list provisioned cards on this Mac"); q.set_defaults(fn=cmd_card_list)
    q = sub.add_parser("seed", help="re-display or copy the master seed (guarded)")
    q.add_argument("--copy", action="store_true", help="copy to clipboard instead of printing (macOS)")
    q.add_argument("--timeout", type=int, default=60, help="auto-clear clipboard after N seconds (0 = never)")
    q.add_argument("--yes", action="store_true"); q.add_argument("--no-clear", action="store_true"); q.set_defaults(fn=cmd_seed)
    for name, fn in (("receive", cmd_receive), ("address", cmd_receive)):
        q = sub.add_parser(name, help="show a receiving address"); q.add_argument("--index", type=int, default=0); q.add_argument("--verbose", action="store_true")
        q.add_argument("--identity", action="store_true", help="show the key's forum identity (xid1…) instead: a chat handle, nothing can be paid to it")
        q.add_argument("--carried", action="store_true", help="show the single-leaf (carried) form of the same key instead of the two-leaf address")
        q.set_defaults(fn=fn)
    q = sub.add_parser("identity", help="show the forum identity (xid1…) of the key at --index; same as `address --identity`")
    q.add_argument("--index", type=int, default=101, help="key index (the forum identity convention is 101)"); q.add_argument("--verbose", action="store_true"); q.set_defaults(fn=cmd_receive, identity=True)
    q = sub.add_parser("addresses", help="list derived addresses"); q.add_argument("--start", type=int, default=0); q.add_argument("--count", type=int, default=5)
    q.add_argument("--identity", action="store_true", help="also list each key's forum identity (xid1…)")
    q.add_argument("--carried", action="store_true", help="also list each key's single-leaf (carried) address"); q.set_defaults(fn=cmd_addresses)
    for name, fn in (("balance", cmd_balance), ("status", cmd_balance), ("utxos", cmd_utxos)):
        q = sub.add_parser(name, help="show balance/UTXOs (maturity-aware; two-leaf and carried outputs)"); q.add_argument("--index", type=int, default=0); q.set_defaults(fn=fn)
    q = sub.add_parser("send", help="send XCF (fee auto-estimated unless --fee)")
    q.add_argument("destination"); q.add_argument("amount")
    q.add_argument("--fee", help="absolute fee in XCF (overrides --feerate)")
    q.add_argument("--feerate", help="fee rate in XCF/kvB (default: auto)")
    q.add_argument("--max-fee", default=str(DEFAULT_MAX_FEE), help=f"refuse fees above this (default {DEFAULT_MAX_FEE} XCF; with --split, the total)")
    q.add_argument("--split", action="store_true", help="pay an amount too large for one standard transaction as several independent ones, "
                   "all signed with one unlock (one card tap), then broadcast in turn")
    q.add_argument("--index", type=int, default=0); q.add_argument("--yes", action="store_true"); q.add_argument("--dry-run", action="store_true")
    q.set_defaults(fn=cmd_send)
    q = sub.add_parser("history", help="transaction history (scans the chain)")
    q.add_argument("--index", type=int, default=0); q.add_argument("--from-height", type=int, default=0); q.set_defaults(fn=cmd_history)
    q = sub.add_parser("info", help="node/chain/mempool status"); q.set_defaults(fn=cmd_info)
    for name in ("restore", "import"):
        q = sub.add_parser(name, help="restore wallet from a seed")
        q.add_argument("seed", nargs="?")
        q.add_argument("--paste", action="store_true", help="read the seed from the clipboard, then clear it (macOS)")
        q.add_argument("--from-file", help="read the seed from a file (e.g. a USB-stick backup)")
        q.set_defaults(fn=cmd_restore)
    q = sub.add_parser("wallets", help="list wallet files in ~/.xcoin and ~/.dex-wallet (the * entry is the default)"); q.set_defaults(fn=cmd_wallets)
    q = sub.add_parser("backup", help="copy the wallet file somewhere safe"); q.add_argument("destination"); q.set_defaults(fn=cmd_backup)
    q = sub.add_parser("encrypt", help="convert to / re-key the encrypted .mmm wallet format"); q.set_defaults(fn=cmd_encrypt)
    q = sub.add_parser("signmessage", help="sign a one-line message with the key at --index (FIPS 204 ML-DSA-65); used by NerdMiner login")
    q.add_argument("--template", help="message with {address} standing for the signer's name: its forum identity xid1… (default) or, with --as address, its xpa1r… two-leaf address")
    q.add_argument("--message", help="literal message (no substitution)")
    q.add_argument("--index", type=int, default=101, help="key index (the forum identity convention is 101)")
    q.add_argument("--as", dest="sign_as", choices=("identity", "address"), default="identity",
                   help="sign as the forum identity xid1… (default) or as the witness v3 payment address")
    q.set_defaults(fn=cmd_signmessage)
    q = sub.add_parser("reset", help="move the seed away (never deletes)"); q.add_argument("--backup", required=True); q.add_argument("--yes", action="store_true"); q.set_defaults(fn=cmd_reset)
    return p

def main(argv=None):
    if os.getenv("XCOIN_WALLET_PASSPHRASE") is not None:
        print("error: XCOIN_WALLET_PASSPHRASE is not accepted: an environment variable is readable by every "
              "program you run and lands in shell history in plain text. Type the passphrase when asked, "
              "or hand it to the wallet over a pipe with --passphrase-fd N.", file=sys.stderr)
        return 2
    # --passphrase-fd is a top-level option, but a parent program may put it after the
    # subcommand; accept it anywhere by lifting it out before argparse sees the rest.
    argv = list(sys.argv[1:] if argv is None else argv)
    fd_value = None
    i = 0
    while i < len(argv):
        if argv[i] == "--passphrase-fd" and i + 1 < len(argv):
            fd_value = argv[i + 1]; del argv[i:i + 2]; continue
        if argv[i].startswith("--passphrase-fd="):
            fd_value = argv[i].split("=", 1)[1]; del argv[i]; continue
        i += 1
    if fd_value is not None:
        argv = ["--passphrase-fd", fd_value] + argv
    p = parser(); args = p.parse_args(argv)
    try:
        if args.passphrase_fd is not None:
            read_passphrase_fd(args.passphrase_fd)
        args.fn(args)
    except KeyboardInterrupt:
        say("cancelled", sys.stderr); return 130
    except WalletError as e:
        say(f"error: {e}", sys.stderr); return 1
    except Exception as e:
        # card_seed.CardError (lazily imported) and other card/hardware faults
        try: from card_seed import CardError
        except Exception: CardError = ()
        if CardError and isinstance(e, CardError):
            say(f"error: {e}", sys.stderr); return 1
        raise
    return 0

if __name__ == "__main__": raise SystemExit(main())

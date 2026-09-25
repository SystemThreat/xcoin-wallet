#!/usr/bin/env python3
"""NTAG 424 DNA card factor for xcoin-wallet .mmm (v2) wallets.

Design — true two-factor wallet decryption:
  * A random 32-byte CARD FACTOR is stored in the chip's proprietary file
    (file 0x03), which the chip only releases after AES EV2 authentication,
    over an encrypted+MACed (CommMode.FULL) channel.
  * The Mac stores only the card's per-card AES app keys (the "auth file")
    and the encrypted wallet. Disk alone decrypts nothing; card alone
    releases nothing.
  * The wallet seed is NEVER displayed: created encrypted, used in memory,
    reveal disabled for card-bound wallets. Loss protection = duplicate
    cards (same factor family), not paper.

Crypto lineage: EV2First authentication, session-key derivation (SV1/SV2),
derived IVs (A55A/5AA5 || TI || CmdCtr) and odd-byte MAC truncation follow
NXP AN12196 and were validated against real NTAG 424 DNA hardware.
CommMode.FULL ReadData/WriteData is implemented
here per the same app note and validated against the built-in simulator
(`python3 card_seed.py --selftest`) — first run against real hardware should
use `xcoin-wallet card-test` with a factory card.

Requires: pyscard (PC/SC, e.g. ACR1252) + cryptography. Both are soft
dependencies — passphrase wallets never import this module.
"""

import ctypes, ctypes.util, json, os, secrets, sys, time, zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac as _cmac_mod

class CardError(RuntimeError): pass

class ReaderError(CardError):
    """The reader or the Mac's PC/SC service failed, not the card's answer: unplugging
    the reader and plugging it back in is the fix worth suggesting."""

class CardWriteError(CardError):
    """A fault after the first write to a card began: the card may be half written.
    Never retried. `cause` is the original fault."""
    def __init__(self, message, cause=None):
        super().__init__(message)
        self.cause = cause

FACTOR_LEN = 32
CARD_FILE = 0x03            # proprietary file, 128 bytes, CommMode.FULL from factory
FACTOR_OFFSET = 0
# Empirically verified access map of file 0x03 on real NTAG 424 DNA:
#   READ  works with key2 OR key3;  WRITE works with key3 ONLY;  key0 = master.
# So key2 is a READ-ONLY key (keep it to unlock — it can't rewrite the factor),
# key3 is the read+write key (used to write the factor, discarded on seal), and
# key0 is the master (discarded on seal to block reset / re-key / settings change).
KEY_APP_MASTER = 0         # master (ChangeKey / ChangeFileSettings)
KEY_READ = 2               # READ-ONLY access to file 0x03 — the KEPT unlock key
KEY_WRITE = 3              # read+write access — writes the factor, discarded on seal
FACTORY_KEY = bytes(16)
CRC_DESFIRE_XOROUT = True  # JAMCRC (zlib.crc32 ^ 0xFFFFFFFF); flipped if a card wants raw
AUTH_DIR = Path.home() / ".xcoin"

def _desfire_crc32(data):
    c = zlib.crc32(data) & 0xFFFFFFFF
    if CRC_DESFIRE_XOROUT: c ^= 0xFFFFFFFF
    return c.to_bytes(4, "little")

# --- secure-ish memory -------------------------------------------------------
# Python cannot guarantee zero copies of a secret (serialization and string
# operations make transients the GC controls). What we CAN do: keep secrets in
# mutable bytearrays, mlock the buffer against swapping, zero it when done,
# and disable core dumps. That is what SecureBuffer provides — best effort,
# honestly labeled.

_libc = None
def _get_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _libc

def disable_core_dumps():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

class SecureBuffer:
    """bytearray wrapper: mlock'd against swap, zeroized on close/exit."""
    def __init__(self, data=b""):
        self.buf = bytearray(data)
        self._locked = False
        if self.buf:
            try:
                addr = ctypes.addressof((ctypes.c_char * len(self.buf)).from_buffer(self.buf))
                self._locked = _get_libc().mlock(addr, len(self.buf)) == 0
            except Exception:
                self._locked = False
    def bytes(self): return bytes(self.buf)
    def hex(self): return self.buf.hex()
    def close(self):
        for i in range(len(self.buf)): self.buf[i] = 0
        if self._locked:
            try:
                addr = ctypes.addressof((ctypes.c_char * len(self.buf)).from_buffer(self.buf))
                _get_libc().munlock(addr, len(self.buf))
            except Exception: pass
        self.buf = bytearray()
    def __enter__(self): return self
    def __exit__(self, *a): self.close()

# --- AES helpers -------------------------------------------------------------

def _aes_ecb_enc(key, data):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()

def _aes_ecb_dec(key, data):
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()

def _aes_cbc_enc(key, iv, data):
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()

def _aes_cbc_dec(key, iv, data):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()

def _cmac(key, data):
    c = _cmac_mod.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()

def _mac_t(full):
    return bytes(full[i] for i in range(1, 16, 2))   # odd-byte truncation

def _pad80(data):
    n = 16 - (len(data) % 16)
    return data + b"\x80" + b"\x00" * (n - 1) if n != 16 else data + b"\x80" + b"\x00" * 15

def _unpad80(data):
    i = data.rstrip(b"\x00")
    if not i or i[-1] != 0x80: raise CardError("bad padding in card response")
    return i[:-1]

# --- transport ---------------------------------------------------------------

CARD_TIMEOUT = 60           # seconds to wait for a tap; XCOIN_CARD_TIMEOUT overrides (5..300)

def card_timeout():
    try: return max(5, min(300, int(os.environ["XCOIN_CARD_TIMEOUT"])))
    except (KeyError, ValueError): return CARD_TIMEOUT

def pcsc_available():
    """True when pyscard, the PC/SC library PCSCTransport needs, imports with this Python. This
    module itself loads with cryptography alone, so loading it says nothing about the reader."""
    try:
        from smartcard.System import readers  # noqa: F401
        from smartcard import scard  # noqa: F401
    except Exception:
        return False
    return True

class PCSCTransport:
    """Thin PC/SC wrapper (ACR1252 or any PC/SC reader)."""
    def __init__(self):
        try:
            from smartcard.System import readers
            from smartcard.Exceptions import NoCardException
            from smartcard import scard
        except ImportError:
            raise CardError("pyscard not installed (pip3 install pyscard)")
        self._readers, self._NoCard, self._scard = readers, NoCardException, scard
        self.conn = None
    def _interfaces(self):
        rs = self._readers()
        if not rs: raise ReaderError("no PC/SC reader found — plug in the ACR1252")
        # the ACR1252's contactless interface is its PICC one (its SAM slot never holds the card)
        return {str(r): r for r in rs if "PICC" in str(r).upper()} or {str(r): r for r in rs}
    def _watch(self, names, timeout, step):
        """SCardGetStatusChange on `names` until step(reported) is true (True), or False once
        the budget is spent. 1 s slices keep Ctrl-C live; handing back the last state is what
        makes each call block."""
        sc = self._scard
        hr, ctx = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)
        if hr != sc.SCARD_S_SUCCESS: raise ReaderError(f"PC/SC unavailable: {sc.SCardGetErrorMessage(hr)}")
        try:
            states, deadline = [(n, sc.SCARD_STATE_UNAWARE) for n in names], time.monotonic() + timeout
            while (left := deadline - time.monotonic()) > 0:
                hr, got = sc.SCardGetStatusChange(ctx, max(1, int(min(left, 1.0) * 1000)), states)
                if hr not in (sc.SCARD_S_SUCCESS, sc.SCARD_E_TIMEOUT):
                    raise ReaderError(f"card reader wait failed: {sc.SCardGetErrorMessage(hr)}")
                if hr == sc.SCARD_S_SUCCESS:
                    if all(ev & sc.SCARD_STATE_UNKNOWN for _, ev, _ in got): raise ReaderError("the card reader went away")
                    if step(got): return True
                    states = [(n, ev & ~sc.SCARD_STATE_CHANGED) for n, ev, _ in got]
                time.sleep(0.05)                     # a driver that returns at once must not spin
            return False
        finally:
            sc.SCardReleaseContext(ctx)
    def wait_for_card(self, timeout=None, prompt=True):
        """Wait for presence with SCardGetStatusChange, then SCardConnect once per
        arrival. Never poll with SCardConnect: one that hung mid-poll wedged the
        reader for every later process."""
        timeout = card_timeout() if timeout is None else timeout
        cand = self._interfaces()
        if prompt: print(f"Tap and hold the card on the reader ({len(cand)} interface(s))...", file=sys.stderr)
        sc, tried, failed = self._scard, set(), None
        def arrived(got):
            nonlocal failed
            for name, ev, _atr in got:
                if not ev & sc.SCARD_STATE_PRESENT: tried.discard(name); continue
                if name in tried or ev & (sc.SCARD_STATE_MUTE | sc.SCARD_STATE_EXCLUSIVE): continue
                tried.add(name)
                conn = cand[name].createConnection()
                try: conn.connect()
                except Exception as e:       # left the field mid-tap: wait for the next arrival
                    failed = e; continue
                self.conn = conn; return True
            return False
        if not self._watch(cand, timeout, arrived):
            raise ReaderError("no card presented in time" + (f" (last connect failed: {failed})" if failed else ""))
    def wait_for_removal(self, timeout=None):
        """Return once no card is on the reader: the same status wait, never a connect
        and never a key press. Our own handle goes first so it cannot hold the card."""
        timeout = card_timeout() if timeout is None else timeout
        self.close()
        sc = self._scard
        if not self._watch(self._interfaces(), timeout, lambda got: not any(ev & sc.SCARD_STATE_PRESENT for _, ev, _ in got)):
            raise CardError("the card was not taken off the reader in time")
    def transmit(self, apdu):
        resp, sw1, sw2 = self.conn.transmit(list(apdu))
        return bytes(resp), sw1, sw2
    def close(self):
        try:
            if self.conn: self.conn.disconnect()
        except Exception: pass
        self.conn = None

# --- NTAG 424 DNA ------------------------------------------------------------

class NTAG424:
    STATUS_OK, STATUS_MORE = 0x00, 0xAF

    def __init__(self, transport):
        self.t = transport
        self._reset()

    def _reset(self):
        self.k_enc = self.k_mac = self.ti = None
        self.ctr = 0
        self.authenticated = False

    def _native(self, cmd, data=b""):
        apdu = bytearray([0x90, cmd, 0x00, 0x00])
        if data: apdu += bytes([len(data)]) + data
        apdu.append(0x00)
        resp, sw1, sw2 = self.t.transmit(apdu)
        if sw1 != 0x91: raise CardError(f"card command {cmd:02X} failed: SW={sw1:02X}{sw2:02X}")
        return resp, sw2

    def uid(self):
        resp, sw1, sw2 = self.t.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        if (sw1, sw2) != (0x90, 0x00): raise CardError("could not read card UID")
        return bytes(resp)

    def select_app(self):
        # ISO SELECT of the NTAG424 NDEF application
        resp, sw1, sw2 = self.t.transmit([0x00, 0xA4, 0x04, 0x0C, 0x07,
                                          0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00])
        if (sw1, sw2) != (0x90, 0x00): raise CardError(f"select application failed: {sw1:02X}{sw2:02X}")

    def auth_ev2(self, key_no, key):
        """EV2 First authentication (AN12196) — establishes session keys."""
        self._reset()
        resp, st = self._native(0x71, bytes([key_no, 0x00]))
        if st != self.STATUS_MORE: raise CardError(f"auth part 1 rejected (key {key_no}): {st:02X}")
        rnd_b = _aes_ecb_dec(key, bytes(resp))
        rnd_a = secrets.token_bytes(16)
        ct = _aes_cbc_enc(key, bytes(16), rnd_a + rnd_b[1:] + rnd_b[:1])
        resp, st = self._native(0xAF, ct)
        if st != self.STATUS_OK: raise CardError(f"auth part 2 rejected (key {key_no}): {st:02X}")
        plain = _aes_cbc_dec(key, bytes(16), bytes(resp[:32]))
        self.ti = plain[0:4]
        if plain[4:20] != rnd_a[1:] + rnd_a[:1]: raise CardError("card failed RndA proof — not a genuine session")
        sv = bytearray(32)
        sv[0:6] = b"\xA5\x5A\x00\x01\x00\x80"; sv[6:8] = rnd_a[0:2]
        for i in range(6): sv[8 + i] = rnd_a[2 + i] ^ rnd_b[i]
        sv[14:24] = rnd_b[6:16]; sv[24:32] = rnd_a[8:16]
        self.k_enc = _cmac(key, bytes(sv))
        sv[0:6] = b"\x5A\xA5\x00\x01\x00\x80"
        self.k_mac = _cmac(key, bytes(sv))
        self.ctr = 0
        self.authenticated = True
        self.auth_key_no = key_no

    def _cmd_iv(self):
        return _aes_ecb_enc(self.k_enc, b"\xA5\x5A" + self.ti + self.ctr.to_bytes(2, "little") + bytes(8))

    def _resp_iv(self):
        return _aes_ecb_enc(self.k_enc, b"\x5A\xA5" + self.ti + self.ctr.to_bytes(2, "little") + bytes(8))

    def _full(self, cmd, header, plaintext=None):
        """CommMode.FULL command. Data is 0x80-block padded before encryption
        (confirmed against real hardware). Returns the raw decrypted response
        bytes; the caller slices to the known length (the card 0x80-pads the
        response, so a fixed unpad is unreliable — slice by expected length)."""
        if not self.authenticated: raise CardError("not authenticated")
        enc = _aes_cbc_enc(self.k_enc, self._cmd_iv(), _pad80(plaintext)) if plaintext is not None else b""
        mac = _mac_t(_cmac(self.k_mac, bytes([cmd]) + self.ctr.to_bytes(2, "little") + self.ti + header + enc))
        resp, st = self._native(cmd, header + enc + mac)
        if st != self.STATUS_OK: raise CardError(f"card command {cmd:02X} rejected: {st:02X}")
        self.ctr += 1
        if len(resp) < 8: raise CardError("card response missing MAC")
        body, rmac = resp[:-8], resp[-8:]
        expect = _mac_t(_cmac(self.k_mac, b"\x00" + self.ctr.to_bytes(2, "little") + self.ti + body))
        if rmac != expect: raise CardError("card response MAC mismatch — possible tampering")
        if body:
            return _aes_cbc_dec(self.k_enc, self._resp_iv(), body)
        return b""

    def read_full(self, file_no, offset, length):
        header = bytes([file_no]) + offset.to_bytes(3, "little") + length.to_bytes(3, "little")
        return self._full(0xAD, header)[:length]

    def write_full(self, file_no, offset, data):
        header = bytes([file_no]) + offset.to_bytes(3, "little") + len(data).to_bytes(3, "little")
        self._full(0x8D, header, data)

    def change_key_same(self, key_no, new_key, key_version=1):
        """ChangeKey for the currently authenticated key (Case 2, AN12196).
        Session ends afterwards."""
        if key_no != self.auth_key_no: raise CardError("can only same-key-change the authenticated key")
        plaintext = bytearray(32)
        plaintext[0:16] = new_key; plaintext[16] = key_version; plaintext[17] = 0x80
        enc = _aes_cbc_enc(self.k_enc, self._cmd_iv(), bytes(plaintext))
        mac = _mac_t(_cmac(self.k_mac, b"\xC4" + self.ctr.to_bytes(2, "little") + self.ti + bytes([key_no]) + enc))
        resp, st = self._native(0xC4, bytes([key_no]) + enc + mac)
        if st != self.STATUS_OK: raise CardError(f"ChangeKey key {key_no} failed: {st:02X}")
        self._reset()   # session ends when the auth key changes

    def change_key_diff(self, key_no, new_key, old_key, key_version=1):
        """ChangeKey for a key OTHER than the authenticated one (Case 1, AN12196).
        Must be authenticated with the app master (key 0). Plaintext carries
        (NewKey XOR OldKey) || KeyVer || CRC32(NewKey), padded. Session persists."""
        if key_no == self.auth_key_no: raise CardError("use change_key_same for the authenticated key")
        xored = bytes(a ^ b for a, b in zip(new_key, old_key))
        plain = _pad80(xored + bytes([key_version]) + _desfire_crc32(new_key))
        enc = _aes_cbc_enc(self.k_enc, self._cmd_iv(), plain)
        mac = _mac_t(_cmac(self.k_mac, b"\xC4" + self.ctr.to_bytes(2, "little") + self.ti + bytes([key_no]) + enc))
        resp, st = self._native(0xC4, bytes([key_no]) + enc + mac)
        if st != self.STATUS_OK: raise CardError(f"ChangeKey (diff) key {key_no} failed: {st:02X}")
        self.ctr += 1
        if resp:   # session persists → response MAC over RC || CmdCtr || TI
            expect = _mac_t(_cmac(self.k_mac, b"\x00" + self.ctr.to_bytes(2, "little") + self.ti))
            if resp != expect: raise CardError("ChangeKey response MAC mismatch")

# --- simulated card (spec model, for tests + selftest) -----------------------

class SimNTAG424:
    """Software model of the subset of NTAG 424 DNA behavior used above."""
    def __init__(self):
        self.keys = {0: bytes(16), 1: bytes(16), 2: bytes(16), 3: bytes(16), 4: bytes(16)}
        self.key_ver = {n: 0 for n in self.keys}
        self.files = {0x03: bytearray(128)}
        # Mirror the empirically verified map of file 0x03: READ={key2,key3},
        # WRITE={key3}. key0 is master (no direct file access).
        self.file_access = {0x03: {"read": {2, 3}, "write": {3}}}
        self.uid_bytes = b"\x04" + secrets.token_bytes(6)
        self._session = None
        self._pending = None
    def _can_read(self, fno, kno):
        return kno in self.file_access[fno]["read"]
    def _can_write(self, fno, kno):
        return kno in self.file_access[fno]["write"]

    def transmit(self, apdu):
        apdu = bytes(apdu)
        if apdu[:4] == b"\xFF\xCA\x00\x00": return list(self.uid_bytes), 0x90, 0x00
        if apdu[:2] == b"\x00\xA4": return [], 0x90, 0x00
        if apdu[0] != 0x90: return [], 0x6D, 0x00
        cmd, data = apdu[1], bytes(apdu[5:-1]) if apdu[4:5] and len(apdu) > 6 else b""
        try: resp, st = self._dispatch(cmd, data)
        except Exception: resp, st = b"", 0x9E
        return list(resp), 0x91, st

    def _dispatch(self, cmd, data):
        if cmd == 0x71:
            key_no = data[0]
            if key_no not in self.keys: return b"", 0x40
            self._pending = (key_no, secrets.token_bytes(16))
            return _aes_ecb_enc(self.keys[key_no], self._pending[1]), 0xAF
        if cmd == 0xAF and self._pending:
            key_no, rnd_b = self._pending; self._pending = None
            key = self.keys[key_no]
            plain = _aes_cbc_dec(key, bytes(16), data)
            rnd_a, rnd_b_rot = plain[:16], plain[16:]
            if rnd_b_rot != rnd_b[1:] + rnd_b[:1]: return b"", 0xAE
            ti = secrets.token_bytes(4)
            out = _aes_cbc_enc(key, bytes(16), ti + rnd_a[1:] + rnd_a[:1] + bytes(12))
            sv = bytearray(32)
            sv[0:6] = b"\xA5\x5A\x00\x01\x00\x80"; sv[6:8] = rnd_a[0:2]
            for i in range(6): sv[8 + i] = rnd_a[2 + i] ^ rnd_b[i]
            sv[14:24] = rnd_b[6:16]; sv[24:32] = rnd_a[8:16]
            k_enc = _cmac(key, bytes(sv))
            sv[0:6] = b"\x5A\xA5\x00\x01\x00\x80"
            k_mac = _cmac(key, bytes(sv))
            self._session = {"key_no": key_no, "k_enc": k_enc, "k_mac": k_mac, "ti": ti, "ctr": 0}
            return out, 0x00
        s = self._session
        if cmd in (0xAD, 0x8D, 0xC4):
            if not s: return b"", 0xAE
            return self._full_cmd(cmd, data, s)
        return b"", 0x1C

    def _full_cmd(self, cmd, data, s):
        ctr_b = s["ctr"].to_bytes(2, "little")
        if cmd == 0xAD:
            header, mac = data[:7], data[7:]
            if _mac_t(_cmac(s["k_mac"], bytes([cmd]) + ctr_b + s["ti"] + header)) != mac: return b"", 0xAE
            file_no = header[0]
            if not self._can_read(file_no, s["key_no"]): return b"", 0x9D
            off = int.from_bytes(header[1:4], "little"); ln = int.from_bytes(header[4:7], "little")
            s["ctr"] += 1; ctr2 = s["ctr"].to_bytes(2, "little")
            iv = _aes_ecb_enc(s["k_enc"], b"\x5A\xA5" + s["ti"] + ctr2 + bytes(8))
            raw = bytes(self.files[file_no][off:off + ln])
            body = _aes_cbc_enc(s["k_enc"], iv, _pad80(raw))   # card 0x80-pads the response
            return body + _mac_t(_cmac(s["k_mac"], b"\x00" + ctr2 + s["ti"] + body)), 0x00
        if cmd == 0x8D:
            header = data[:7]
            ln = int.from_bytes(header[4:7], "little")
            enc_len = (ln + 16) // 16 * 16   # 0x80 padding always adds at least one block
            enc, mac = data[7:7 + enc_len], data[7 + enc_len:]
            if _mac_t(_cmac(s["k_mac"], bytes([cmd]) + ctr_b + s["ti"] + header + enc)) != mac: return b"", 0xAE
            file_no = header[0]
            if not self._can_write(file_no, s["key_no"]): return b"", 0x9D
            iv = _aes_ecb_enc(s["k_enc"], b"\xA5\x5A" + s["ti"] + ctr_b + bytes(8))
            plain = _aes_cbc_dec(s["k_enc"], iv, enc)[:ln]
            off = int.from_bytes(header[1:4], "little")
            self.files[file_no][off:off + len(plain)] = plain
            s["ctr"] += 1; ctr2 = s["ctr"].to_bytes(2, "little")
            return _mac_t(_cmac(s["k_mac"], b"\x00" + ctr2 + s["ti"])), 0x00
        if cmd == 0xC4:
            key_no = data[0]; enc, mac = data[1:33], data[33:]
            if _mac_t(_cmac(s["k_mac"], b"\xC4" + ctr_b + s["ti"] + bytes([key_no]) + enc)) != mac: return b"", 0xAE
            iv = _aes_ecb_enc(s["k_enc"], b"\xA5\x5A" + s["ti"] + ctr_b + bytes(8))
            plain = _aes_cbc_dec(s["k_enc"], iv, enc)
            if key_no == s["key_no"]:
                # Case 2: same-key change. Only the master key permits same-key change.
                if key_no != 0: return b"", 0xAE
                self.keys[key_no] = plain[:16]; self.key_ver[key_no] = plain[16]
                self._session = None
                return b"", 0x00
            # Case 1: changing a different key requires master (key 0) auth.
            if s["key_no"] != 0: return b"", 0xAE
            new_xored = plain[:16]; ver = plain[16]; crc = plain[17:21]
            new_key = bytes(a ^ b for a, b in zip(new_xored, self.keys[key_no]))
            if crc != _desfire_crc32(new_key): return b"", 0x1E   # integrity error
            self.keys[key_no] = new_key; self.key_ver[key_no] = ver
            s["ctr"] += 1; ctr2 = s["ctr"].to_bytes(2, "little")
            return _mac_t(_cmac(s["k_mac"], b"\x00" + ctr2 + s["ti"])), 0x00
        return b"", 0x1C

class SimTransport:
    def __init__(self, card): self.card = card
    def wait_for_card(self, timeout=None, prompt=True): pass
    def wait_for_removal(self, timeout=None): pass
    def transmit(self, apdu): return tuple(self.card.transmit(apdu)) if False else self._t(apdu)
    def _t(self, apdu):
        resp, sw1, sw2 = self.card.transmit(apdu)
        return bytes(resp), sw1, sw2
    def close(self): pass

# --- auth files + high-level operations --------------------------------------

def auth_path(uid_hex):
    return AUTH_DIR / f"card-{uid_hex}.auth"

def load_auth(uid_hex):
    p = auth_path(uid_hex)
    if not p.exists(): raise CardError(f"card {uid_hex} is not provisioned for this wallet (no {p.name})")
    try: return json.loads(p.read_text())
    except (OSError, ValueError) as e: raise CardError(f"the key file {p.name} of card {uid_hex} cannot be read ({e})") from None

def save_auth(record):
    AUTH_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    p = auth_path(record["uid"])
    if p.exists(): raise CardError(f"auth file already exists: {p}")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: json.dump(record, f, indent=2)
    return p

def _one_line(e):
    """An exception as one line of text (a KeyboardInterrupt says so)."""
    text = " ".join(str(e).split()) or type(e).__name__
    return "interrupted" if isinstance(e, KeyboardInterrupt) else text

def _connect(transport):
    card = NTAG424(transport)
    card.select_app()
    return card

def _update_auth(uid_hex, updates):
    p = auth_path(uid_hex)
    rec = json.loads(p.read_text()); rec.update(updates)
    tmp = p.with_suffix(".auth.upd")
    if tmp.exists(): tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: json.dump(rec, f, indent=2)
    os.replace(tmp, p)
    return rec

def _key_file_step(uid_hex, step, *args):
    """save_auth / _update_auth inside a card write: a failure of this Mac's disk (full, not
    writable) is named as such, a CardError, so it is never taken for a fault of the reader."""
    try: return step(*args)
    except (OSError, ValueError) as e:
        raise CardError(f"the key file for card {uid_hex} could not be saved on this Mac: {_one_line(e)}") from e

def require_blank(card, uid_hex):
    """Refuse, before anything is written, a card whose master, read or write key is off
    factory: it belongs to a wallet (maybe on another computer) and provisioning needs all three."""
    for key_no in (KEY_APP_MASTER, KEY_READ, KEY_WRITE):
        try: card.auth_ev2(key_no, FACTORY_KEY)
        except CardError:
            raise CardError(f"card {uid_hex} is not blank (its keys were changed: it already belongs to a wallet) — "
                            "use a NEW factory-fresh card; nothing was written") from None

def provision_card(transport, factor, family, label="", exclude=(), before_write=None):
    """Provision a FACTORY card and store the factor. Saves the auth file itself
    (the caller no longer calls save_auth) and returns the record.

    Order is chosen for safety and to isolate faults:
      0. Refuse a UID in `exclude` (the wallet card placed again), a card with an
         auth file here, or one whose keys are off factory — nothing written yet.
         `before_write` runs once the card has passed, just before the first write.
      1. Write + verify the factor using the KNOWN factory keys (Write=key3,
         Read=key2 are factory here) — any WriteData fault happens while the card
         is still all-factory (recoverable / no brick).
      2. Save the auth record (all keys) BEFORE any key is rotated — a fault
         during rotation leaves the keys on disk, never a bricked card.
      3. Rotate key2 (read) + key3 (write) via master Case-1, then the master
         itself (Case-2). key2 (read-only) is KEPT to unlock; key0 (master) +
         key3 (write) are what make_permanent() discards. Never prints secrets."""
    transport.wait_for_card()
    card = _connect(transport)
    uid_hex = card.uid().hex()
    if uid_hex in exclude:
        raise CardError(f"card {uid_hex} is the wallet card itself — take it off and place a NEW blank card; nothing was written")
    if auth_path(uid_hex).exists():
        raise CardError(f"card {uid_hex} is already provisioned — use a factory card")
    require_blank(card, uid_hex)
    if before_write: before_write()
    try:
        read_key, write_key, master_key = (secrets.token_bytes(16) for _ in range(3))
        # 1) write + verify with factory keys (isolates any WriteData fault safely)
        card.auth_ev2(KEY_WRITE, FACTORY_KEY)
        card.write_full(CARD_FILE, FACTOR_OFFSET, factor.bytes())
        card.auth_ev2(KEY_READ, FACTORY_KEY)
        if card.read_full(CARD_FILE, FACTOR_OFFSET, FACTOR_LEN) != factor.bytes():
            raise CardError("factor write/verify failed with factory keys — card left untouched")
        # 2) persist the keys BEFORE rotating (crash-safety recovery point)
        record = {"version": 3, "uid": uid_hex, "family": family, "label": label,
                  "read_key_no": KEY_READ, "read_key": read_key.hex(),
                  "master_key": master_key.hex(), "write_key": write_key.hex(),
                  "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "permanent": False, "state": "factor_written"}
        _key_file_step(uid_hex, save_auth, record)
        # 3) rotate keys off factory (master session; master changed last)
        card.auth_ev2(KEY_APP_MASTER, FACTORY_KEY)
        card.change_key_diff(KEY_READ, read_key, FACTORY_KEY)
        card.change_key_diff(KEY_WRITE, write_key, FACTORY_KEY)
        card.change_key_same(KEY_APP_MASTER, master_key)
        # verify unlock with the rotated read-only key
        card.auth_ev2(KEY_READ, read_key)
        if card.read_full(CARD_FILE, FACTOR_OFFSET, FACTOR_LEN) != factor.bytes():
            raise CardError("verification read failed after key rotation")
        return _key_file_step(uid_hex, _update_auth, uid_hex, {"state": "provisioned"})
    except (Exception, KeyboardInterrupt) as e:
        # from the first write on a fault may leave the card half made: never retried, always named
        raise CardWriteError(f"the write to card {uid_hex} did not finish ({_one_line(e)})", e) from e

def make_permanent(uid_hex):
    """Seal a provisioned card: drop the master and write keys from its auth file,
    keeping only the READ-ONLY key. After this the card can never be reset or
    re-keyed (master gone), its factor can never be rewritten (write key gone),
    and its access rights can never be relaxed. IRREVERSIBLE."""
    p = auth_path(uid_hex)
    rec = json.loads(p.read_text())
    rec.pop("master_key", None); rec.pop("write_key", None)
    rec["permanent"] = True
    tmp = p.with_suffix(".auth.sealing")
    if tmp.exists(): tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: json.dump(rec, f, indent=2)
    os.replace(tmp, p)
    return p

def read_factor(transport, store=None):
    """Tap a provisioned card, return (SecureBuffer factor, auth record).
    Reads via the stored read key (file 0x03 Read access = key 3).
    `store` (ported from dex-wallet-cli's read_factor, unlock scope only): an
    object with .load(uid_hex) -> key record — the dex-era v5 one-file wallet
    keeps its records INSIDE the .mmm file; None keeps the card-<uid>.auth files."""
    transport.wait_for_card()
    card = _connect(transport)
    auth = store.load(card.uid().hex()) if store is not None else load_auth(card.uid().hex())
    read_no = auth.get("read_key_no", KEY_READ)
    card.auth_ev2(read_no, bytes.fromhex(auth["read_key"]))
    factor = SecureBuffer(card.read_full(CARD_FILE, FACTOR_OFFSET, FACTOR_LEN))
    if len(factor.bytes()) != FACTOR_LEN or factor.bytes() == bytes(FACTOR_LEN):
        factor.close(); raise CardError("card holds no wallet factor")
    return factor, auth

def factory_reset_card(transport):
    """Return a provisioned card to factory keys and wipe the factor.
    Refuses PERMANENT cards — their master/write keys were discarded by design."""
    transport.wait_for_card()
    card = _connect(transport)
    uid_hex = card.uid().hex()
    auth = load_auth(uid_hex)
    if auth.get("permanent") or "master_key" not in auth or "write_key" not in auth:
        raise CardError("this card was provisioned PERMANENTLY (no factory-key rollback saved) — it cannot be reset")
    master, write_key, read_key = (bytes.fromhex(auth[k]) for k in ("master_key", "write_key", "read_key"))
    try:
        # Wipe the factor (Write access = key3), then roll all keys back to factory.
        card.auth_ev2(KEY_WRITE, write_key)
        card.write_full(CARD_FILE, FACTOR_OFFSET, bytes(FACTOR_LEN))
        card.auth_ev2(KEY_APP_MASTER, master)
        card.change_key_diff(KEY_READ, FACTORY_KEY, read_key, key_version=0)
        card.change_key_diff(KEY_WRITE, FACTORY_KEY, write_key, key_version=0)
        card.change_key_same(KEY_APP_MASTER, FACTORY_KEY, key_version=0)
    except (Exception, KeyboardInterrupt) as e:
        raise CardWriteError(f"the reset of card {uid_hex} did not finish ({_one_line(e)})", e) from e
    return uid_hex

def family_of(factor_bytes):
    import hashlib
    return hashlib.sha256(b"xcoin-mmm-family" + factor_bytes).hexdigest()[:16]

# --- selftest ----------------------------------------------------------------

def _selftest():
    global AUTH_DIR
    disable_core_dumps()
    import tempfile
    saved_dir = AUTH_DIR
    with tempfile.TemporaryDirectory() as d:
        AUTH_DIR = Path(d)
        try:
            sim = SimNTAG424()
            def mk(): return SimTransport(sim)
            with SecureBuffer(secrets.token_bytes(FACTOR_LEN)) as factor:
                fam = family_of(factor.bytes())
                rec = provision_card(mk(), factor, fam, label="selftest")
                got, _ = read_factor(mk())
                assert got.bytes() == factor.bytes(), "unlock read mismatch"; got.close()
                # the rotated read key means the FACTORY read key no longer works
                card = _connect(mk())
                try: card.auth_ev2(KEY_READ, FACTORY_KEY); raise AssertionError("factory read key still works")
                except CardError: pass
                # the kept read key is READ-ONLY — it must NOT be able to write the factor
                card = _connect(mk()); card.auth_ev2(KEY_READ, bytes.fromhex(rec["read_key"]))
                try: card.write_full(CARD_FILE, 0, bytes(32)); raise AssertionError("read-only key wrote")
                except CardError: pass
                # a resettable card CAN be returned to factory
                assert factory_reset_card(mk()) == rec["uid"]
            # a PERMANENT card refuses reset
            sim2 = SimNTAG424()
            def mk2(): return SimTransport(sim2)
            with SecureBuffer(secrets.token_bytes(FACTOR_LEN)) as f2:
                rec2 = provision_card(mk2(), f2, family_of(f2.bytes()))
                make_permanent(rec2["uid"])
                got2, _ = read_factor(mk2()); assert got2.bytes() == f2.bytes(); got2.close()
                try: factory_reset_card(mk2()); raise AssertionError("permanent card was reset")
                except CardError: pass
            print(f"selftest OK — Case1/Case2 ChangeKey, FULL read/write, access control, "
                  f"permanent seal + reset-refusal (family {fam})")
        finally:
            AUTH_DIR = saved_dir

if __name__ == "__main__":
    if "--selftest" in sys.argv: _selftest()
    else: print("usage: card_seed.py --selftest", file=sys.stderr); sys.exit(2)

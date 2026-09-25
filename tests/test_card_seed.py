#!/usr/bin/env python3
"""Card-bound wallet tests — all against the simulated NTAG 424 DNA, no hardware.

Covers the .mmm v2 format, the full provision -> read_seed -> decrypt loop, the
two-factor property (disk alone / card alone are useless), wrong-card rejection,
duplicate-card backup, and the invariant that a card wallet never reveals its seed.
"""

import io, json, os, sys, tempfile, types, unittest
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    import card_seed as cs
except ModuleNotFoundError as e:
    # direct run: clean skip line; unittest discover: a recorded skip, not an error
    if __name__ == '__main__':
        print(f'SKIP: card tests need the optional {e.name} module (pip install cryptography pyscard)')
        raise SystemExit(0)
    raise unittest.SkipTest(f'card tests need the optional {e.name} module') from None
import wallet_cli as w

class FakeReaderTransport(cs.SimTransport):
    """SimTransport but with the wait/close interface the wallet drives."""
    def wait_for_card(self, timeout=30, prompt=False): pass

def fresh_factory_card():
    return cs.SimNTAG424()

class CardHarness(unittest.TestCase):
    """Routes card_seed's PCSCTransport to an in-memory factory card, and pins
    ~/.xcoin auth dir to a temp dir."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        os.environ.pop("XCOIN_WALLET_PASSPHRASE", None)
        self.card = fresh_factory_card()
        self._real_pcsc = cs.PCSCTransport
        self._real_authdir = cs.AUTH_DIR
        cs.AUTH_DIR = Path(self.tmp.name)
        harness = self
        def make_transport(): return FakeReaderTransport(harness.card)
        cs.PCSCTransport = make_transport
        self.addCleanup(self._restore)
    def _restore(self):
        cs.PCSCTransport = self._real_pcsc
        cs.AUTH_DIR = self._real_authdir
    def use_card(self, card): self.card = card

class TestMmm2Format(unittest.TestCase):
    def test_roundtrip(self):
        seed = "ab" * 32
        factor = os.urandom(32); fam = cs.family_of(factor)
        blob = w.mmm2_encode(seed, factor, fam)
        self.assertTrue(blob.startswith(w.MMM2_MAGIC))
        self.assertEqual(w.mmm2_family(blob), fam)
        self.assertNotIn(bytes.fromhex(seed), blob)
        self.assertEqual(w.mmm2_decode(blob, factor), seed)
    def test_wrong_card_factor_fails(self):
        blob = w.mmm2_encode("cd" * 32, os.urandom(32), "0" * 16)
        with self.assertRaisesRegex(w.WalletError, "wrong card"):
            w.mmm2_decode(blob, os.urandom(32))
    def test_passphrase_second_factor(self):
        seed, factor = "ef" * 32, os.urandom(32)
        blob = w.mmm2_encode(seed, factor, cs.family_of(factor), "pw")
        self.assertEqual(w.mmm2_decode(blob, factor, "pw"), seed)
        with self.assertRaises(w.WalletError):
            w.mmm2_decode(blob, factor, "wrong")
    def test_tamper_detected(self):
        factor = os.urandom(32)
        blob = bytearray(w.mmm2_encode("ab" * 32, factor, cs.family_of(factor)))
        blob[60] ^= 1
        with self.assertRaises(w.WalletError):
            w.mmm2_decode(bytes(blob), factor)

class TestCardProvisioning(CardHarness):
    def test_provision_read_roundtrip(self):
        factor = cs.SecureBuffer(os.urandom(32))
        fam = cs.family_of(factor.bytes())
        t = cs.PCSCTransport()
        rec = cs.provision_card(t, factor, fam, label="primary")  # saves auth itself
        # factory keys are gone now; a fresh factory card would NOT read
        t2 = cs.PCSCTransport()
        got, auth = cs.read_factor(t2)
        try:
            self.assertEqual(got.bytes(), factor.bytes())
            self.assertEqual(auth["uid"], rec["uid"])
        finally:
            got.close(); factor.close()
    def test_unprovisioned_card_has_no_auth(self):
        t = cs.PCSCTransport()
        with self.assertRaisesRegex(cs.CardError, "not provisioned"):
            cs.read_factor(t)
    def test_factory_reset_wipes(self):
        factor = cs.SecureBuffer(os.urandom(32))
        rec = cs.provision_card(cs.PCSCTransport(), factor, cs.family_of(factor.bytes()))
        uid = cs.factory_reset_card(cs.PCSCTransport())
        self.assertEqual(uid, rec["uid"])
        # factor field on the card is zeroed
        self.assertEqual(self.card.files[cs.CARD_FILE][:32], bytearray(32))
        factor.close()

class TestCardWalletCLI(CardHarness):
    def run_cli(self, wallet, *argv, card=None):
        if card is not None: self.use_card(card)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(wallet), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()

    def test_new_card_then_unlock(self):
        wallet = Path(self.tmp.name) / "wallet001.mmm"
        rc, out = self.run_cli(wallet, "card-provision", "--offline")
        self.assertEqual(rc, 0)
        self.assertTrue(w.is_card_wallet(wallet))
        # seed was never printed
        blob = wallet.read_bytes()
        self.assertTrue(blob.startswith(w.MMM2_MAGIC))
        # unlock: read_seed must tap the (same) provisioned card and return a valid seed
        seed = w.read_seed(wallet)
        self.assertTrue(w._valid_seed(seed))
        # and it must be stable (same card -> same seed)
        self.assertEqual(seed, w.read_seed(wallet))

    def test_disk_alone_is_useless(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        blob = wallet.read_bytes()
        # a random factor (attacker without the card) cannot decrypt
        with self.assertRaises(w.WalletError):
            w.mmm2_decode(blob, os.urandom(32))

    def test_wrong_card_rejected(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        # provision a DIFFERENT card (different factor/family) and try to unlock
        other = fresh_factory_card()
        self.use_card(other)
        other_factor = cs.SecureBuffer(os.urandom(32))
        rec = cs.provision_card(cs.PCSCTransport(), other_factor, cs.family_of(other_factor.bytes()))
        other_factor.close()
        with self.assertRaisesRegex(w.WalletError, "family mismatch"):
            w.read_seed(wallet)

    def test_seed_reveal_refused(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "seed", "--yes")
        self.assertEqual(rc, 1)
        self.assertNotIn("Seed:", out)
        rc, out = self.run_cli(wallet, "--json", "seed", "--yes")
        self.assertEqual(rc, 1)

    def test_encrypt_refused_on_card_wallet(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "encrypt")
        self.assertEqual(rc, 1)

    def test_backup_card_duplicate_unlocks(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        primary_seed = w.read_seed(wallet)
        # card-backup taps the primary (read factor), then a factory card.
        # Simulate the two taps by swapping the active card at the input() point.
        backup_card = fresh_factory_card()
        import builtins
        real_input = builtins.input
        def fake_input(prompt=""):
            self.use_card(backup_card)   # step 2: place the factory card
            return ""
        builtins.input = fake_input
        try:
            rc, out = self.run_cli(wallet, "card-backup")
        finally:
            builtins.input = real_input
        self.assertEqual(rc, 0)
        # the backup card must now unlock the SAME wallet to the SAME seed
        self.use_card(backup_card)
        self.assertEqual(w.read_seed(wallet), primary_seed)

    def test_card_list_and_test(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "--json", "card-list")
        rows = json.loads(out)
        self.assertEqual(len(rows), 1)
        rc, out = self.run_cli(wallet, "--json", "card-test")
        self.assertTrue(json.loads(out)["ok"])

class TestPermanentCards(CardHarness):
    def run_cli(self, wallet, *argv, card=None):
        if card is not None: self.use_card(card)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(wallet), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()

    def test_default_is_permanent(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        rc, out = self.run_cli(wallet, "card-provision", "--offline")
        self.assertEqual(rc, 0)
        rec = json.loads(list(Path(self.tmp.name).glob("card-*.auth"))[0].read_text())
        self.assertTrue(rec["permanent"])
        self.assertNotIn("master_key", rec)   # master discarded (no reset/re-key)
        self.assertNotIn("write_key", rec)    # write key discarded (factor immutable)
        self.assertIn("read_key", rec)        # read-only key kept (needed to unlock)
        # still unlocks
        self.assertTrue(w._valid_seed(w.read_seed(wallet)))

    def test_permanent_card_cannot_be_reset(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        self.run_cli(wallet, "card-provision", "--offline")
        rc, out = self.run_cli(wallet, "card-reset", "--yes")
        self.assertEqual(rc, 1)
        with self.assertRaisesRegex(cs.CardError, "PERMANENTLY"):
            cs.factory_reset_card(cs.PCSCTransport())

    def test_resettable_opt_out_keeps_keys(self):
        wallet = Path(self.tmp.name) / "w.mmm"
        rc, out = self.run_cli(wallet, "card-provision", "--offline", "--resettable")
        self.assertEqual(rc, 0)
        rec = json.loads(list(Path(self.tmp.name).glob("card-*.auth"))[0].read_text())
        self.assertFalse(rec["permanent"])
        self.assertIn("master_key", rec); self.assertIn("write_key", rec); self.assertIn("read_key", rec)
        # and CAN be reset
        uid = cs.factory_reset_card(cs.PCSCTransport())
        self.assertEqual(uid, rec["uid"])

    def test_make_permanent_helper(self):
        factor = cs.SecureBuffer(os.urandom(32))
        rec = cs.provision_card(cs.PCSCTransport(), factor, cs.family_of(factor.bytes()))
        factor.close()
        self.assertIn("master_key", json.loads(cs.auth_path(rec["uid"]).read_text()))
        cs.make_permanent(rec["uid"])
        sealed = json.loads(cs.auth_path(rec["uid"]).read_text())
        self.assertTrue(sealed["permanent"])
        self.assertNotIn("master_key", sealed); self.assertNotIn("write_key", sealed)
        self.assertIn("read_key", sealed)

class TestSecureBuffer(unittest.TestCase):
    def test_zeroized_on_close(self):
        b = cs.SecureBuffer(b"secretseed")
        self.assertEqual(b.bytes(), b"secretseed")
        b.close()
        self.assertEqual(b.bytes(), b"")
    def test_context_manager(self):
        with cs.SecureBuffer(b"x" * 32) as b:
            self.assertEqual(len(b.bytes()), 32)

# --- card wait: a fake pyscard (no reader, no hardware) -----------------------
SC = types.SimpleNamespace(SCARD_S_SUCCESS=0, SCARD_E_TIMEOUT=0x8010000A, SCARD_SCOPE_USER=0,
                           SCARD_STATE_UNAWARE=0, SCARD_STATE_CHANGED=0x2, SCARD_STATE_UNKNOWN=0x4,
                           SCARD_STATE_EMPTY=0x10, SCARD_STATE_PRESENT=0x20, SCARD_STATE_EXCLUSIVE=0x80,
                           SCARD_STATE_MUTE=0x200)
EMPTY, PRESENT = SC.SCARD_STATE_EMPTY, SC.SCARD_STATE_PRESENT
PICC, SAM = "ACS ACR1252 Dual Reader PICC", "ACS ACR1252 Dual Reader SAM"

class FakePCSC:
    """pyscard stand-in. `script` holds what each SCardGetStatusChange call reports:
    None = the call times out (the fake clock advances by its timeout), else
    {reader: state}. Every call, connect and context is recorded."""
    class NoCard(Exception): pass
    def __init__(self, names, script, connects=None):
        self.names, self.script, self.connects = names, list(script), list(connects or [])
        self.calls, self.connected, self.contexts, self.now = [], [], 0, 1000.0
    def install(self, test):
        f = self
        class Conn:
            def __init__(c, name): c.name = name
            def connect(c):
                f.connected.append(c.name)
                err = f.connects.pop(0) if f.connects else None
                if err: raise err
            def transmit(c, apdu): return [], 0x90, 0x00
            def disconnect(c): pass
        class Reader:
            def __init__(r, name): r.name = name
            def __str__(r): return r.name
            def createConnection(r): return Conn(r.name)
        def status_change(ctx, timeout_ms, states):
            f.calls.append((timeout_ms, list(states)))
            step = f.script.pop(0) if f.script else None
            if step is None:
                f.now += timeout_ms / 1000
                return SC.SCARD_E_TIMEOUT, [(n, s, []) for n, s in states]
            return SC.SCARD_S_SUCCESS, [(n, step.get(n, EMPTY) | SC.SCARD_STATE_CHANGED, []) for n, _ in states]
        def establish(scope): f.contexts += 1; return 0, 77
        def release(ctx): f.contexts -= 1; return 0
        scard = types.ModuleType("smartcard.scard"); scard.__dict__.update(vars(SC))
        scard.SCardEstablishContext, scard.SCardReleaseContext, scard.SCardGetStatusChange = establish, release, status_change
        scard.SCardGetErrorMessage = lambda hr: f"error {hr:#x}"
        system = types.ModuleType("smartcard.System"); system.readers = lambda: [Reader(n) for n in f.names]
        exc = types.ModuleType("smartcard.Exceptions"); exc.NoCardException = FakePCSC.NoCard
        pkg = types.ModuleType("smartcard"); pkg.scard, pkg.System, pkg.Exceptions = scard, system, exc
        mods = {"smartcard": pkg, "smartcard.scard": scard, "smartcard.System": system, "smartcard.Exceptions": exc}
        p = mock.patch.dict(sys.modules, mods); p.start(); test.addCleanup(p.stop)
        clock = types.SimpleNamespace(monotonic=lambda: f.now, sleep=lambda s: setattr(f, "now", f.now + s))
        p = mock.patch.object(cs, "time", clock); p.start(); test.addCleanup(p.stop)
        return f

class TestCardWait(unittest.TestCase):
    """PCSCTransport.wait_for_card waits with SCardGetStatusChange on the PICC
    interface(s) and connects once per arrival: never an SCardConnect poll."""
    def setUp(self):
        for k in ("XCOIN_CARD_TIMEOUT",): self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
    def wait(self, fake, **kw):
        t = cs.PCSCTransport()
        with redirect_stderr(io.StringIO()): t.wait_for_card(**kw)
        return t
    def test_card_appears_after_polls_then_one_connect(self):
        fake = FakePCSC([SAM, PICC], [{PICC: EMPTY}, None, None, None, {PICC: PRESENT}]).install(self)
        t = self.wait(fake)
        self.assertEqual(fake.connected, [PICC])                          # exactly one SCardConnect
        self.assertEqual(t.conn.name, PICC)
        self.assertEqual(len(fake.calls), 5)
        self.assertTrue(all(0 < ms <= 1000 for ms, _ in fake.calls))
        self.assertEqual({n for _, st in fake.calls for n, _ in st}, {PICC})  # the SAM slot is never watched
        self.assertEqual(fake.calls[0][1], [(PICC, SC.SCARD_STATE_UNAWARE)])
        # every later call hands back the last known state, so a real reader BLOCKS until a change
        self.assertTrue(all(st == [(PICC, EMPTY)] for _, st in fake.calls[1:]))
        self.assertEqual(fake.contexts, 0)                                # context released
    def test_timeout_never_connects(self):
        os.environ["XCOIN_CARD_TIMEOUT"] = "7"
        fake = FakePCSC([PICC], [{PICC: EMPTY}]).install(self)
        with self.assertRaisesRegex(cs.CardError, "no card presented in time"):
            self.wait(fake)
        self.assertEqual(fake.connected, [])
        self.assertLessEqual(len(fake.calls), 9)                         # ~1 blocking call per second of budget
        self.assertEqual(fake.contexts, 0)
    def test_card_already_on_the_reader(self):
        fake = FakePCSC([PICC], [{PICC: PRESENT}]).install(self)
        self.wait(fake, timeout=5)
        self.assertEqual((fake.connected, len(fake.calls)), ([PICC], 1))
    def test_no_picc_interface_falls_back_to_all_readers(self):
        other = "Generic USB Smart Card Reader"
        fake = FakePCSC([other, "Second Reader"], [{"Second Reader": PRESENT}]).install(self)
        self.wait(fake, timeout=5)
        self.assertEqual([n for n, _ in fake.calls[0][1]], [other, "Second Reader"])
        self.assertEqual(fake.connected, ["Second Reader"])
    def test_card_left_before_connect_waits_for_the_next_arrival(self):
        fake = FakePCSC([PICC], [{PICC: PRESENT}, None, {PICC: EMPTY}, {PICC: PRESENT}],
                        connects=[FakePCSC.NoCard("removed")]).install(self)
        self.wait(fake, timeout=10)
        self.assertEqual(fake.connected, [PICC, PICC])                    # one connect per arrival
        self.assertEqual(fake.calls[1][1], [(PICC, PRESENT)])              # then blocked on the known state
    def test_still_present_after_failed_connect_is_not_retried(self):
        fake = FakePCSC([PICC], [{PICC: PRESENT}, {PICC: PRESENT}],
                        connects=[RuntimeError("unresponsive card")]).install(self)
        with self.assertRaisesRegex(cs.CardError, "no card presented in time .*unresponsive card"):
            self.wait(fake, timeout=5)
        self.assertEqual(fake.connected, [PICC])
    def test_mute_card_is_skipped(self):
        fake = FakePCSC([PICC], [{PICC: PRESENT | SC.SCARD_STATE_MUTE}, {PICC: PRESENT}]).install(self)
        self.wait(fake, timeout=5)
        self.assertEqual(fake.connected, [PICC])
        self.assertEqual(len(fake.calls), 2)
    def test_reader_unplugged(self):
        fake = FakePCSC([PICC], [{PICC: SC.SCARD_STATE_UNKNOWN}]).install(self)
        with self.assertRaisesRegex(cs.CardError, "went away"):
            self.wait(fake, timeout=5)
    def test_no_reader(self):
        FakePCSC([], []).install(self)
        with self.assertRaisesRegex(cs.CardError, "no PC/SC reader"):
            cs.PCSCTransport().wait_for_card()
    def test_card_timeout_budget(self):
        self.assertEqual(cs.card_timeout(), 60)
        for v, want in (("90", 90), ("1", 5), ("999", 300), ("soon", 60), ("", 60)):
            os.environ["XCOIN_CARD_TIMEOUT"] = v
            self.assertEqual(cs.card_timeout(), want, v)

class TestUnlockEvents(CardHarness):
    """XCOIN_EVENTS=1: a card unlock announces the wait and the unlocked seed on stderr."""
    def setUp(self):
        super().setUp()
        for k in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT"): self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
        self.wallet = Path(self.tmp.name) / "w.mmm"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(w.main(["--file", str(self.wallet), "--config", "/nonexistent", "card-provision", "--offline"]), 0)
    def unlock_events(self):
        err = io.StringIO()
        with redirect_stderr(err): w.read_seed(self.wallet)
        return [l for l in err.getvalue().splitlines() if l.startswith("XCOIN-EVENT")]
    def test_card_wait_then_card_ok(self):
        os.environ["XCOIN_EVENTS"] = "1"
        self.assertEqual(self.unlock_events(), ["XCOIN-EVENT card-wait 60", "XCOIN-EVENT card-ok"])
        os.environ["XCOIN_CARD_TIMEOUT"] = "90"
        self.assertEqual(self.unlock_events()[0], "XCOIN-EVENT card-wait 90")
    def test_silent_without_the_variable(self):
        self.assertEqual(self.unlock_events(), [])
        os.environ["XCOIN_EVENTS"] = "0"
        self.assertEqual(self.unlock_events(), [])
    def test_wrong_card_waits_but_never_ok(self):
        os.environ["XCOIN_EVENTS"] = "1"
        other = fresh_factory_card(); self.use_card(other)
        f = cs.SecureBuffer(os.urandom(32)); cs.provision_card(cs.PCSCTransport(), f, cs.family_of(f.bytes())); f.close()
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaisesRegex(w.WalletError, "family mismatch"):
            w.read_seed(self.wallet)
        self.assertEqual([l for l in err.getvalue().splitlines() if l.startswith("XCOIN-EVENT")], ["XCOIN-EVENT card-wait 60"])

class TestCardSplitSend(CardHarness):
    """A split send from a card wallet: ONE tap unlocks the seed that signs every transaction."""
    def setUp(self):
        super().setUp()
        for k in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT"): self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
        self.wallet = Path(self.tmp.name) / "w.mmm"
        with redirect_stdout(io.StringIO()):
            w.main(["--file", str(self.wallet), "--config", "/nonexistent", "card-provision", "--offline"])
        self.taps = 0
        harness, real = self, cs.PCSCTransport
        class Counting(FakeReaderTransport):
            def wait_for_card(s, timeout=None, prompt=False): harness.taps += 1
        cs.PCSCTransport = lambda: Counting(harness.card)
        seed = w.read_seed(self.wallet); self.taps = 0
        if not w.keytool_path(): self.skipTest("native keytool not built")
        spk = w.derive_offline(seed, 0)["scriptPubKey"]
        coins = [{"txid": f"{i:064x}", "vout": 0, "amount": Decimal(14), "scriptPubKey": spk, "height": 10,
                  "coinbase": False, "confirmations": 191} for i in range(240)]
        self.signed, self.sent = [], []
        answers = {"scantxoutset": lambda p: {"success": True, "height": 200, "unspents": [dict(c) for c in coins]},
                   "getblockchaininfo": lambda p: {"chain": "test"}, "validateaddress": lambda p: {"isvalid": True},
                   "getmempoolinfo": lambda p: {"minrelaytxfee": Decimal("0.00001")},
                   "estimatesmartfee": lambda p: {"feerate": Decimal("0.00001")},
                   "createrawtransaction": lambda p: json.dumps(p),
                   "testmempoolaccept": lambda p: [{"allowed": True}],
                   "decoderawtransaction": lambda p: {"txid": p[0][:64], "vsize": 99691},
                   "sendrawtransaction": lambda p: self.sent.append(p[0][:64]) or p[0][:64]}
        class RPC:
            def __init__(s, args): s.conf = {}
            def call(s, method, params=None, timeout=60): return answers[method](params)
        real_rpc, real_sign = w.RPC, w.sign_offline
        w.RPC = RPC
        def sign(seed_, raw, prev):
            self.assertEqual(seed_, seed); self.signed.append(raw)
            import hashlib; return hashlib.sha256(raw.encode()).hexdigest() * 40
        w.sign_offline = sign
        self.addCleanup(setattr, w, "RPC", real_rpc); self.addCleanup(setattr, w, "sign_offline", real_sign)
        grace = mock.patch.object(w, "BROADCAST_GRACE", 0); grace.start(); self.addCleanup(grace.stop)
    def test_one_tap_signs_every_transaction(self):
        os.environ["XCOIN_EVENTS"] = "1"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", "--json", "send",
                         "txa1rdest", "3333", "--split", "--yes"])
        self.assertEqual(rc, 0, err.getvalue())
        d = json.loads(out.getvalue())
        self.assertEqual((self.taps, len(self.signed), d["transactions"], d["txids"]), (1, 4, 4, self.sent))
        ev = [l.split()[1:] for l in err.getvalue().splitlines() if l.startswith("XCOIN-EVENT")]
        self.assertEqual(ev, [["card-wait", "60"], ["card-ok"]] + [["signing", str(i), "4"] for i in range(1, 5)] + [["broadcast-begin", "4"]]
                         + [["broadcast", str(i), "4", t] for i, t in enumerate(self.sent, 1)] + [["done"]])

if __name__ == "__main__":
    unittest.main(verbosity=2)

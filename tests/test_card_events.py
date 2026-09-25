#!/usr/bin/env python3
"""XCOIN_EVENTS=1 in every card flow (new --card, card-backup, card-test, card-reset):
card-wait <budget> before each NFC wait, card-ok after each successful one. The card
module is a fake whose every wait prints WAIT on stderr, so one stderr capture shows
the events and the waits in order. No card_seed, cryptography or reader needed."""

import hashlib, io, json, os, sys, tempfile, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wallet_cli as w

class FakeCards:
    """The card_seed calls the wallet makes, against one remembered card."""
    FACTOR_LEN = 32
    class SecureBuffer:
        def __init__(self, data=b""): self.buf = bytes(data)
        def bytes(self): return self.buf
        def hex(self): return self.buf.hex()
        def close(self): self.buf = b""
    def __init__(self, auth_dir):
        self.auth_dir, self.factor, self.fail, self.opened, self.closed = Path(auth_dir), None, None, 0, 0
        cards = self
        class Transport:
            def __init__(t): cards.opened += 1
            def wait_for_card(t, timeout=None, prompt=True):
                print("WAIT", file=sys.stderr)
                if cards.fail: raise w.WalletError(cards.fail)
            def close(t): cards.closed += 1
        self.PCSCTransport = Transport
    def card_timeout(self): return 42
    def disable_core_dumps(self): pass
    def family_of(self, factor): return hashlib.sha256(factor).digest()[:8].hex()
    def auth_path(self, uid): return self.auth_dir / f"card-{uid}.auth"
    def make_permanent(self, uid): pass
    def provision_card(self, transport, factor, family, label=""):
        transport.wait_for_card(); self.factor = factor.bytes(); return {"uid": "04a1b2c3d4e5f6"}
    def read_factor(self, transport, store=None):
        transport.wait_for_card(); return self.SecureBuffer(self.factor), {"uid": "04a1b2c3d4e5f6", "label": "primary"}
    def factory_reset_card(self, transport):
        transport.wait_for_card(); return "04a1b2c3d4e5f6"

class TestCardFlowEvents(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        for k in ("XCOIN_EVENTS", "XCOIN_WALLET_PASSPHRASE"): self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
        self.cards = FakeCards(self.tmp.name)
        for p in (mock.patch.object(w, "_card_module", lambda: self.cards), mock.patch.object(w, "PASSPHRASE_FROM_FD", None)):
            p.start(); self.addCleanup(p.stop)
        self.wallet = Path(self.tmp.name) / "card.mmm"
    def run_cli(self, *argv, events=True):
        if events: os.environ["XCOIN_EVENTS"] = "1"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", "--json", *argv])
        steps = [l.removeprefix("XCOIN-EVENT ") for l in err.getvalue().splitlines() if l == "WAIT" or l.startswith("XCOIN-EVENT ")]
        return rc, out.getvalue(), err.getvalue(), steps
    def create(self):
        rc, out, err, steps = self.run_cli("new", "--card", "--offline")
        self.assertEqual(rc, 0, err)
        return json.loads(out), steps
    def test_new_card_announces_its_tap(self):
        d, steps = self.create()
        self.assertEqual(steps, ["card-wait 42", "WAIT", "card-ok"])
        self.assertTrue(w.is_card_wallet(self.wallet)); self.assertEqual(d["card_uid"], "04a1b2c3d4e5f6")
        self.assertEqual((self.cards.opened, self.cards.closed), (1, 1))
    def test_card_backup_announces_both_taps(self):
        self.create()
        with mock.patch("builtins.input", lambda prompt="": ""):
            rc, out, err, steps = self.run_cli("card-backup")
        self.assertEqual(rc, 0, err)
        self.assertEqual(steps, ["card-wait 42", "WAIT", "card-ok", "card-wait 42", "WAIT", "card-ok"])
        self.assertEqual(self.cards.opened, self.cards.closed)
    def test_card_backup_wrong_card_never_ok(self):
        self.create(); self.cards.factor = os.urandom(32)                    # a card of another wallet
        rc, out, err, steps = self.run_cli("card-backup")
        self.assertEqual(rc, 1); self.assertIn("does not belong to this wallet", err)
        self.assertEqual(steps, ["card-wait 42", "WAIT"])
    def test_card_test_announces_its_tap(self):
        self.create()
        rc, out, err, steps = self.run_cli("card-test")
        self.assertEqual((rc, json.loads(out)["ok"]), (0, True))
        self.assertEqual(steps, ["card-wait 42", "WAIT", "card-ok"])
    def test_card_reset_announces_its_tap(self):
        rc, out, err, steps = self.run_cli("card-reset", "--yes")
        self.assertEqual(rc, 0, err)
        self.assertEqual(steps, ["card-wait 42", "WAIT", "card-ok"])
    def test_failed_wait_never_ok_and_closes(self):
        self.create(); self.cards.fail = "no card presented in time"
        for argv in (("card-test",), ("card-reset", "--yes")):
            rc, out, err, steps = self.run_cli(*argv)
            self.assertEqual(rc, 1); self.assertIn("no card presented in time", err)
            self.assertEqual(steps, ["card-wait 42", "WAIT"], argv)
        self.assertEqual(self.cards.opened, self.cards.closed)
    def test_silent_without_the_variable(self):
        rc, out, err, steps = self.run_cli("new", "--card", "--offline", events=False)
        self.assertEqual((rc, steps), (0, ["WAIT"]))

if __name__ == "__main__":
    unittest.main(verbosity=2)

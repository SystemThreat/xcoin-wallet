#!/usr/bin/env python3
"""new --card --one-file (mmm5-card written here: card keys inside the .mmm, no auth file)
and new --no-reveal (the seed is never printed at creation). Simulated cards, no reader."""

import io, json, os, sys, tempfile, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    import card_seed as cs
except ModuleNotFoundError as e:
    if __name__ == '__main__':
        print(f'SKIP: card tests need the optional {e.name} module'); raise SystemExit(0)
    raise unittest.SkipTest(f'card tests need the optional {e.name} module') from None
import wallet_cli as w
from test_card_backup import Reader

PW = "correct horse"

class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        for k in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT", "XCOIN_WALLET_PASSPHRASE"):
            self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
        self.primary = cs.SimNTAG424(); self.reader = Reader(self.primary)
        self.pw = mock.patch.object(w, "PASSPHRASE_FROM_FD", PW)
        for p in (mock.patch.object(cs, "AUTH_DIR", self.dir / "auth"), mock.patch.object(cs, "PCSCTransport", self.reader.transport),
                  mock.patch.object(cs, "pcsc_available", lambda: True), self.pw,
                  mock.patch("builtins.input", self.no_enter), mock.patch("getpass.getpass", self.no_enter)):
            p.start(); self.addCleanup(p.stop)
        self.wallet = self.dir / "one.mmm"
    def no_enter(self, prompt=""): raise AssertionError(f"asked the keyboard: {prompt!r}")
    def cli(self, *argv, json_out=True):
        os.environ["XCOIN_EVENTS"] = "0"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", *(["--json"] if json_out else []), *argv])
        return rc, out.getvalue(), err.getvalue()

class TestOneFile(Base):
    def make(self):
        rc, out, err = self.cli("new", "--card", "--one-file", "--offline")
        self.assertEqual(rc, 0, err); return json.loads(out)
    def test_one_file_holds_the_card_keys_and_no_auth_file(self):
        d = self.make()
        self.assertEqual((d["format"], d["one_file"], d["permanent"]), ("mmm5-card", True, True))
        self.assertEqual(w._wallet_format(self.wallet), ("mmm5-card", True))
        self.assertFalse(list(self.dir.glob("**/card-*.auth")))
        cards = w.mmm5_cards(self.wallet.read_bytes(), PW)
        self.assertEqual([c["uid"] for c in cards], [d["card_uid"]])
        self.assertEqual(cards[0]["state"], "provisioned")
        self.assertNotIn("master_key", cards[0]); self.assertNotIn("write_key", cards[0])   # sealed
        self.assertEqual(oct(self.wallet.stat().st_mode & 0o777), "0o600")
    def test_unlocks_with_card_and_passphrase_and_seed_is_never_shown(self):
        self.make()
        with redirect_stderr(io.StringIO()): seed = w.read_seed(self.wallet)
        self.assertTrue(w._valid_seed(seed))
        rc, out, err = self.cli("seed", "--yes")
        self.assertEqual(rc, 1); self.assertNotIn(seed, out + err); self.assertIn("never revealed", err)
    def test_the_file_moves_without_any_key_file(self):
        self.make()
        moved = self.dir / "elsewhere.mmm"; moved.write_bytes(self.wallet.read_bytes())
        with mock.patch.object(cs, "AUTH_DIR", self.dir / "empty"), redirect_stderr(io.StringIO()):
            self.assertTrue(w._valid_seed(w.read_seed(moved)))
    def test_wrong_passphrase_is_refused_before_the_tap(self):
        self.make()
        with mock.patch.object(w, "PASSPHRASE_FROM_FD", "wrong"), redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(w.WalletError, "wrong passphrase"): w.read_seed(self.wallet)
    def test_needs_a_passphrase(self):
        with mock.patch.object(w, "PASSPHRASE_FROM_FD", ""):
            rc, _, err = self.cli("new", "--card", "--one-file", "--offline")
        self.assertEqual(rc, 1); self.assertIn("needs a passphrase", err); self.assertFalse(self.wallet.exists())
    def test_one_file_without_card_is_refused(self):
        rc, _, err = self.cli("new", "--one-file", "--offline")
        self.assertEqual(rc, 1); self.assertIn("--card", err); self.assertFalse(self.wallet.exists())
    def test_backup_card_keys_go_into_the_same_file(self):
        d = self.make()
        blank = cs.SimNTAG424()
        self.reader.card = self.primary; self.reader.moves = [self.reader.take_off(), self.reader.place(blank)]
        rc, out, err = self.cli("card-backup", "--auto-swap")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["cards"], 2)
        uids = {c["uid"] for c in w.mmm5_cards(self.wallet.read_bytes(), PW)}
        self.assertEqual(uids, {d["card_uid"], blank.uid_bytes.hex()})
        self.assertFalse(list(self.dir.glob("**/card-*.auth")))
        self.reader.card = blank; self.reader.moves = []
        with redirect_stderr(io.StringIO()): self.assertTrue(w._valid_seed(w.read_seed(self.wallet)))
    def test_card_status_offers_backup(self):
        self.make()
        rc, out, _ = self.cli("card-status")
        d = json.loads(out)
        self.assertEqual((rc, d["format"], d["backup_supported"]), (0, "mmm5", True))

class TestNoReveal(Base):
    def test_no_reveal_prints_no_seed(self):
        rc, out, err = self.cli("new", "--offline", "--no-reveal", json_out=False)
        self.assertEqual(rc, 0, err)
        with redirect_stderr(io.StringIO()): seed = w.read_seed(self.wallet)
        self.assertNotIn(seed, out + err); self.assertNotIn("Seed:", out)
        self.assertIn("NOT displayed", out); self.assertIn("xcoin-wallet seed", out)
    def test_default_still_prints_the_seed_once(self):
        rc, out, err = self.cli("new", "--offline", "--no-clear", json_out=False)
        self.assertEqual(rc, 0, err)
        with redirect_stderr(io.StringIO()): seed = w.read_seed(self.wallet)
        self.assertIn(f"Seed: {seed}", out)
    def test_no_reveal_seed_still_retrievable_on_request(self):
        self.cli("new", "--offline", "--no-reveal", json_out=False)
        with redirect_stderr(io.StringIO()): seed = w.read_seed(self.wallet)
        rc, out, _ = self.cli("seed", "--yes", json_out=False)
        self.assertEqual(rc, 0); self.assertIn(seed, out)
    def test_no_passphrase_is_named(self):
        with mock.patch.object(w, "PASSPHRASE_FROM_FD", ""):
            _, out, _ = self.cli("new", "--offline", "--no-reveal", json_out=False)
        self.assertIn("no passphrase", out)

if __name__ == "__main__":
    unittest.main(verbosity=2)

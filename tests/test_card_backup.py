#!/usr/bin/env python3
"""card-backup --auto-swap and card-status. A fake one-slot reader holds simulated
NTAG 424 DNA cards that a scripted user places and takes off, so the real card_seed
code runs (blank check, same-card refusal, seal). No reader, no hardware, no Enter key."""

import io, json, os, subprocess, sys, tempfile, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    import card_seed as cs
except ModuleNotFoundError as e:
    if __name__ == '__main__':
        print(f'SKIP: card tests need the optional {e.name} module (pip install cryptography pyscard)')
        raise SystemExit(0)
    raise unittest.SkipTest(f'card tests need the optional {e.name} module') from None
import wallet_cli as w

REAL_PCSC_AVAILABLE = cs.pcsc_available       # before Harness swaps in its stand-in
DEX_NOTE = "This card wallet was made with dex-wallet-cli, so its backup cards are made there too."
# what card_seed and the reader import: None in sys.modules makes that import fail
NO_PYSCARD = {"smartcard.System": None, "smartcard.scard": None}
NO_CRYPTOGRAPHY = {"cryptography.hazmat.primitives.ciphers": None, "cryptography.hazmat.primitives.cmac": None}

def pyscard_installed():
    try: import smartcard.System, smartcard.scard  # noqa: F401
    except ImportError: return False
    return True

class Reader:
    """One PICC slot and the person at it: a wait that finds the slot in the wrong state
    plays their next move; with none left they walked away. Waits print WAIT / REMOVAL on
    stderr so one capture shows them among the XCOIN-EVENT lines."""
    def __init__(self, card): self.card, self.moves = card, []
    def place(self, card): return lambda: setattr(self, "card", card)
    def take_off(self): return lambda: setattr(self, "card", None)
    def transport(self):
        reader = self
        class Transport:
            def wait_for_card(t, timeout=None, prompt=True):
                print("WAIT", file=sys.stderr)
                if reader.card is None and reader.moves: reader.moves.pop(0)()
                if reader.card is None: raise cs.CardError("no card presented in time")
            def wait_for_removal(t, timeout=None):
                print("REMOVAL", file=sys.stderr)
                if reader.card is not None and reader.moves: reader.moves.pop(0)()
                if reader.card is not None: raise cs.CardError("the card was not taken off the reader in time")
            def transmit(t, apdu):
                if reader.card is None: raise cs.CardError("no card in the field")
                resp, sw1, sw2 = reader.card.transmit(apdu)
                return bytes(resp), sw1, sw2
            def close(t): pass
        return Transport()

class Harness(unittest.TestCase):
    """A card wallet whose sealed primary card lies on the reader."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        for k in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT", "XCOIN_WALLET_PASSPHRASE"):
            self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
        self.primary = cs.SimNTAG424(); self.reader = Reader(self.primary)
        # the fake reader stands in for pyscard, so pyscard counts as present even where it is not installed
        for p in (mock.patch.object(cs, "AUTH_DIR", self.dir), mock.patch.object(cs, "PCSCTransport", self.reader.transport),
                  mock.patch.object(cs, "pcsc_available", lambda: True),
                  mock.patch.object(w, "PASSPHRASE_FROM_FD", None), mock.patch("builtins.input", self.no_enter),
                  mock.patch("getpass.getpass", self.no_enter)):
            p.start(); self.addCleanup(p.stop)
        self.wallet = self.dir / "card.mmm"
        rc, out, err, _ = self.cli("new", "--card", "--offline", events=False)
        self.assertEqual(rc, 0, err)
        self.family = json.loads(out)["family"]
        self.seed = self.unlock()
    def no_enter(self, prompt=""): raise AssertionError(f"asked the keyboard: {prompt!r}")
    def cli(self, *argv, events=True, json_out=True, file=None):
        os.environ["XCOIN_EVENTS"] = "1" if events else "0"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = w.main(["--file", str(file or self.wallet), "--config", "/nonexistent", *(["--json"] if json_out else []), *argv])
        steps = [l.removeprefix("XCOIN-EVENT ") for l in err.getvalue().splitlines()
                 if l in ("WAIT", "REMOVAL") or l.startswith("XCOIN-EVENT ")]
        return rc, out.getvalue(), err.getvalue(), steps
    def unlock(self):
        with redirect_stderr(io.StringIO()): return w.read_seed(self.wallet)
    def auth_files(self): return sorted(p.name for p in self.dir.glob("card-*"))
    def swap_to(self, card): self.reader.card = self.primary; self.reader.moves = [self.reader.take_off(), self.reader.place(card)]

SWAP = ["card-wait 60", "WAIT", "card-ok", "card-swap", "REMOVAL", "card-removed", "card-wait 60", "WAIT"]

class TestAutoSwap(Harness):
    def backup(self, *extra, **kw): return self.cli("card-backup", "--auto-swap", *extra, **kw)
    def test_swap_seen_on_the_reader_then_written_and_sealed(self):
        blank = cs.SimNTAG424(); self.swap_to(blank)
        rc, out, err, steps = self.backup()
        self.assertEqual(rc, 0, err)
        self.assertEqual(steps, SWAP + ["card-provisioning", "card-ok", "done"])
        uid = blank.uid_bytes.hex()
        self.assertEqual(json.loads(out), {"ok": True, "card_uid": uid, "family": self.family, "permanent": True, "cards": 2})
        rec = json.loads(cs.auth_path(uid).read_text())
        self.assertEqual((rec["permanent"], rec["label"], "master_key" in rec, "write_key" in rec), (True, "backup", False, False))
        self.assertEqual(self.unlock(), self.seed)                        # the backup (still on the reader) unlocks
        self.reader.card = self.primary
        self.assertEqual(self.unlock(), self.seed)                        # and so does the primary
    def test_resettable_keeps_rollback_keys(self):
        blank = cs.SimNTAG424(); self.swap_to(blank)
        rc, out, err, steps = self.backup("--resettable", "--label", "safe")
        self.assertEqual(rc, 0, err)
        d = json.loads(out); self.assertEqual((d["permanent"], d["cards"]), (False, 2))
        rec = json.loads(cs.auth_path(blank.uid_bytes.hex()).read_text())
        self.assertEqual((rec["permanent"], rec["label"], "master_key" in rec), (False, "safe", True))
    def test_same_card_placed_again_writes_nothing(self):
        before = (dict(self.primary.keys), bytes(self.primary.files[cs.CARD_FILE]), self.auth_files())
        self.swap_to(self.primary)
        rc, out, err, steps = self.backup()
        self.assertEqual((rc, out), (1, "")); self.assertIn("is the wallet card itself", err); self.assertIn("nothing was written", err)
        self.assertEqual(steps, SWAP)
        self.assertEqual((dict(self.primary.keys), bytes(self.primary.files[cs.CARD_FILE]), self.auth_files()), before)
        self.assertEqual(self.unlock(), self.seed)
    def test_card_not_factory_fresh_writes_nothing(self):
        for key_no in (cs.KEY_APP_MASTER, cs.KEY_READ, cs.KEY_WRITE):
            used = cs.SimNTAG424(); used.keys[key_no] = os.urandom(16)
            keys, before = dict(used.keys), self.auth_files()
            self.swap_to(used)
            rc, out, err, steps = self.backup()
            self.assertEqual(rc, 1, key_no); self.assertIn("is not blank", err); self.assertIn("nothing was written", err)
            self.assertEqual(steps, SWAP)
            self.assertEqual((used.keys, used.files[cs.CARD_FILE], self.auth_files()), (keys, bytearray(128), before))
    def test_card_of_a_wallet_elsewhere_writes_nothing(self):
        other = cs.SimNTAG424(); self.reader.card = other
        with tempfile.TemporaryDirectory() as elsewhere, mock.patch.object(cs, "AUTH_DIR", Path(elsewhere)), redirect_stderr(io.StringIO()):
            f = cs.SecureBuffer(os.urandom(32)); cs.provision_card(self.reader.transport(), f, cs.family_of(f.bytes())); f.close()
        data, before = bytes(other.files[cs.CARD_FILE]), self.auth_files()
        self.swap_to(other)
        rc, out, err, steps = self.backup()
        self.assertEqual(rc, 1); self.assertIn("is not blank", err)
        self.assertEqual((bytes(other.files[cs.CARD_FILE]), self.auth_files()), (data, before))
    def test_card_of_another_wallet_here_writes_nothing(self):
        other = cs.SimNTAG424(); self.reader.card = other
        with redirect_stderr(io.StringIO()):
            f = cs.SecureBuffer(os.urandom(32)); cs.provision_card(self.reader.transport(), f, cs.family_of(f.bytes())); f.close()
        data, before = bytes(other.files[cs.CARD_FILE]), self.auth_files()
        self.swap_to(other)
        rc, out, err, steps = self.backup()
        self.assertEqual(rc, 1); self.assertIn("already provisioned", err)
        self.assertEqual((bytes(other.files[cs.CARD_FILE]), self.auth_files(), steps), (data, before, SWAP))
    def test_wallet_card_never_taken_off(self):
        before = self.auth_files()
        rc, out, err, steps = self.backup()
        self.assertEqual(rc, 1); self.assertIn("not taken off the reader in time", err)
        self.assertEqual(steps, ["card-wait 60", "WAIT", "card-ok", "card-swap", "REMOVAL"])
        self.assertEqual(self.auth_files(), before)
    def test_no_blank_card_placed(self):
        before = self.auth_files()
        self.reader.moves = [self.reader.take_off()]
        rc, out, err, steps = self.backup()
        self.assertEqual(rc, 1); self.assertIn("no card presented in time", err)
        self.assertEqual((steps, self.auth_files()), (SWAP, before))
    def test_card_of_another_wallet_first_never_swaps(self):
        other = cs.SimNTAG424(); self.reader.card = other
        with redirect_stderr(io.StringIO()):
            f = cs.SecureBuffer(os.urandom(32)); cs.provision_card(self.reader.transport(), f, cs.family_of(f.bytes())); f.close()
        rc, out, err, steps = self.backup()
        self.assertEqual(rc, 1); self.assertIn("does not belong to this wallet", err)
        self.assertEqual(steps, ["card-wait 60", "WAIT"])
    def test_each_wait_gets_the_card_budget(self):
        os.environ["XCOIN_CARD_TIMEOUT"] = "90"
        budgets = []
        real = self.reader.transport
        def transport():
            t = real(); inner = t.wait_for_removal
            t.wait_for_removal = lambda timeout=None: (budgets.append(timeout), inner(timeout))
            return t
        self.swap_to(cs.SimNTAG424())
        with mock.patch.object(cs, "PCSCTransport", transport):
            os.environ["XCOIN_EVENTS"] = "1"; out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", "--json", "card-backup", "--auto-swap"])
        self.assertEqual(rc, 0, err.getvalue())
        self.assertEqual([l for l in err.getvalue().splitlines() if "card-wait" in l], ["XCOIN-EVENT card-wait 90"] * 2)
        self.assertEqual(budgets, [None])                                 # None = PCSCTransport's own card_timeout()
    def test_silent_without_events_and_human_output(self):
        self.swap_to(cs.SimNTAG424())
        rc, out, err, steps = self.backup(events=False, json_out=False)
        self.assertEqual((rc, steps), (0, ["WAIT", "REMOVAL", "WAIT"]), err)
        self.assertIn("Backup card ready", out); self.assertIn("Sealed permanently", out)
        self.assertIn("take the wallet card off the reader", err)
    def test_json_flag_after_the_subcommand(self):
        self.swap_to(cs.SimNTAG424())
        rc, out, err, steps = self.cli("card-backup", "--auto-swap", "--json", json_out=False)
        self.assertEqual(rc, 0, err); self.assertTrue(json.loads(out)["ok"])

class TestInteractiveBackupUnchanged(Harness):
    def enter_places(self, card):
        prompts = []
        def enter(prompt=""): prompts.append(prompt); self.reader.card = card; return ""
        return prompts, mock.patch("builtins.input", enter)
    def test_enter_key_flow_events_and_json(self):
        blank = cs.SimNTAG424(); prompts, enter = self.enter_places(blank)
        with enter: rc, out, err, steps = self.cli("card-backup")
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(prompts), 1); self.assertIn("press Enter", prompts[0])
        self.assertEqual(steps, ["card-wait 60", "WAIT", "card-ok", "card-wait 60", "WAIT", "card-ok"])
        d = json.loads(out)
        self.assertEqual(sorted(d), ["auth_file", "backup_card_uid", "family", "permanent"])
        self.assertEqual((d["backup_card_uid"], d["permanent"]), (blank.uid_bytes.hex(), True))
        self.assertEqual(self.unlock(), self.seed)
    def test_used_card_now_refused_clearly(self):
        used = cs.SimNTAG424(); used.keys[cs.KEY_APP_MASTER] = os.urandom(16)
        before = self.auth_files(); prompts, enter = self.enter_places(used)
        with enter: rc, out, err, steps = self.cli("card-backup")
        self.assertEqual(rc, 1); self.assertIn("is not blank", err)
        self.assertEqual((used.files[cs.CARD_FILE], self.auth_files()), (bytearray(128), before))

class TestCardStatus(Harness):
    """No tap and no passphrase: the reader and the keyboard both fail the test if touched."""
    def status(self, *argv, file=None, json_out=True):
        with mock.patch.object(cs, "PCSCTransport", lambda: self.fail("card-status touched the reader")):
            rc, out, err, _ = self.cli("card-status", *argv, file=file, json_out=json_out)
        return rc, out, err
    def status_json(self, file=None):
        rc, out, err = self.status(file=file)
        self.assertEqual(rc, 0, err)
        return json.loads(out)
    def test_primary_only_then_after_a_backup(self):
        rc, out, err = self.status()
        d = json.loads(out)
        self.assertNotIn("read_key", out)
        self.assertEqual({k: d[k] for k in ("card", "format", "family", "count", "backup_supported")},
                         {"card": True, "format": "mmm2", "family": self.family, "count": 1, "backup_supported": True})
        self.assertEqual(sorted(d["cards"][0]), ["created", "label", "permanent", "uid"])
        self.assertEqual((d["cards"][0]["uid"], d["cards"][0]["label"], d["cards"][0]["permanent"]),
                         (self.primary.uid_bytes.hex(), "primary", True))
        self.assertIn("card-backup", d["note"])
        self.swap_to(cs.SimNTAG424())
        self.assertEqual(self.cli("card-backup", "--auto-swap")[0], 0)
        d = self.status_json()
        self.assertEqual((d["count"], sorted(c["label"] for c in d["cards"])), (2, ["backup", "primary"]))
        self.assertEqual(d["note"], "2 cards unlock this wallet")
    def test_counts_only_provisioned_cards_of_this_family(self):
        put = lambda uid, **rec: (self.dir / f"card-{uid}.auth").write_text(json.dumps({"uid": uid, **rec}))
        put("04000000000001", family="0123456789abcdef", state="provisioned")      # another wallet
        put("04000000000002", family=self.family, state="factor_written")          # fault before key rotation
        put("04000000000003", family=self.family, label="old", created="2026-01-01")  # pre-state record
        (self.dir / "card-04000000000004.auth").write_text("{not json")
        (self.dir / "card-04000000000005.auth.removed").write_text(json.dumps({"uid": "5", "family": self.family}))
        d = self.status_json()
        self.assertEqual(sorted(c["uid"] for c in d["cards"]), sorted(["04000000000003", self.primary.uid_bytes.hex()]))
        self.assertEqual(d["count"], 2)
    def test_no_key_file_on_this_mac(self):
        # cards set up on another Mac: no backup card can be made here, and the note says why
        for f in self.dir.glob("card-*.auth"): f.unlink()
        d = self.status_json()
        self.assertEqual((d["count"], d["cards"], d["backup_supported"]), (0, [], False))
        self.assertIn("cannot be unlocked", d["note"])
        self.assertIn("its cards were set up on another Mac, so it cannot be unlocked here and a backup card can only be made there", d["note"])
        rc, out, err = self.status(json_out=False)
        self.assertEqual(rc, 0); self.assertIn("set up on another Mac", out)
    def test_without_the_card_stack_reads_the_home_store(self):
        home = self.dir / "home"; (home / ".xcoin").mkdir(parents=True)
        for f in self.dir.glob("card-*.auth"): f.rename(home / ".xcoin" / f.name)
        with mock.patch.object(w, "_card_module", side_effect=w.WalletError("card support unavailable")), \
             mock.patch.object(w.Path, "home", staticmethod(lambda: home)), mock.patch.dict(sys.modules, {**NO_PYSCARD, **NO_CRYPTOGRAPHY}):
            d = self.status_json()
            self.assertEqual(d["count"], 1)
            # the key file is here but the card libraries are not: no backup card from this Mac
            self.assertFalse(d["backup_supported"])
            self.assertIn("pyscard and cryptography", d["note"]); self.assertIn("no backup card can be made on this Mac", d["note"])
            self.assertNotIn("another Mac", d["note"])
            for f in (home / ".xcoin").glob("card-*.auth"): f.unlink()
            d = self.status_json()                                       # neither: both reasons
            self.assertEqual((d["count"], d["backup_supported"]), (0, False))
            self.assertIn("another Mac", d["note"]); self.assertIn("pyscard and cryptography", d["note"])
    def test_without_the_card_stack_names_only_what_is_missing(self):
        """card_seed did not load: the note names the modules that are really missing, each checked
        on its own, not always both."""
        with mock.patch.object(w, "_card_module", side_effect=w.WalletError("card support unavailable")), \
             mock.patch.object(w.Path, "home", staticmethod(lambda: self.dir)):
            def note(blocked):
                (self.dir / ".xcoin").mkdir(exist_ok=True)
                for f in self.dir.glob("card-*.auth"): f.rename(self.dir / ".xcoin" / f.name)
                with mock.patch.dict(sys.modules, blocked): d = self.status_json()
                self.assertEqual((d["count"], d["backup_supported"]), (1, False))
                return d["note"]
            n = note(NO_PYSCARD)                                         # card_seed itself failed too, and pyscard is missing
            self.assertIn("(the pyscard Python module)", n); self.assertNotIn("cryptography", n)
            n = note({**NO_PYSCARD, **NO_CRYPTOGRAPHY})
            self.assertIn("(the pyscard and cryptography Python modules)", n)
            if not pyscard_installed(): self.skipTest("pyscard is not installed here")
            n = note({})                                                 # both modules load: card_seed itself is what failed
            self.assertEqual(n, "The card software could not be loaded for the Python this wallet runs with, "
                                "so no backup card can be made on this Mac.")
            n = note(NO_CRYPTOGRAPHY)
            self.assertEqual(n, "The card software this needs (the cryptography Python module) is not installed for the Python "
                                "this wallet runs with, so no backup card can be made on this Mac.")
    def test_without_cryptography_in_a_real_process(self):
        """A child process in which `import cryptography` fails (pyscard still there), nothing patched:
        card-status blames cryptography alone."""
        code = r'''
import io, sys
sys.path[:0] = [sys.argv[1]]
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
d = Path(sys.argv[2])
if sys.argv[3] == "make":                     # the first run makes the card wallet, card software whole
    import card_seed as cs, wallet_cli as w
    cs.AUTH_DIR = d / ".xcoin"
    card = cs.SimNTAG424()
    class T:
        def wait_for_card(t, timeout=None, prompt=True): pass
        def close(t): pass
        def transmit(t, apdu): r, a, b = card.transmit(apdu); return bytes(r), a, b
    cs.PCSCTransport = T
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        sys.exit(w.main(["--file", str(d / "w.mmm"), "new", "--card", "--offline"]))
class Block:                                  # cryptography missing: any cryptography import fails
    def find_spec(self, name, path=None, target=None):
        if name == "cryptography" or name.startswith("cryptography."): raise ModuleNotFoundError(f"No module named {name!r}", name=name)
sys.meta_path.insert(0, Block())
import wallet_cli as w
sys.exit(w.main(["--file", str(d / "w.mmm"), "--json", "card-status"]))
'''
        repo = str(Path(__file__).resolve().parent.parent)
        with tempfile.TemporaryDirectory() as d:
            env = {**{k: v for k, v in os.environ.items() if k not in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT")}, "HOME": d}
            run = lambda step: subprocess.run([sys.executable, "-c", code, repo, d, step], stdin=subprocess.DEVNULL,
                                              capture_output=True, text=True, timeout=120, env=env)
            p = run("make"); self.assertEqual(p.returncode, 0, p.stderr)
            p = run("status"); self.assertEqual(p.returncode, 0, p.stderr)
            got = json.loads(p.stdout)
            self.assertEqual((got["count"], got["backup_supported"]), (1, False))
            self.assertIn("cryptography Python module", got["note"]); self.assertNotIn("card-backup", got["note"])
            if pyscard_installed(): self.assertNotIn("pyscard", got["note"])
            else: self.assertIn("the pyscard and cryptography Python modules", got["note"])
    def test_without_pyscard_no_backup_card_is_offered(self):
        """card_seed loads with cryptography alone; without pyscard no card can be written here."""
        with mock.patch.object(cs, "pcsc_available", lambda: False):
            d = self.status_json()
            self.assertEqual((d["count"], d["backup_supported"]), (1, False))
            self.assertEqual(d["note"], "The card software this needs (the pyscard Python module) is not installed for the Python "
                                        "this wallet runs with, so no backup card can be made on this Mac.")
            for f in self.dir.glob("card-*.auth"): f.unlink()
            d = self.status_json()                                       # both reasons
            self.assertEqual((d["count"], d["backup_supported"]), (0, False))
            self.assertIn("another Mac", d["note"]); self.assertIn("the pyscard Python module", d["note"])
    def test_pcsc_available_is_the_real_import(self):
        with mock.patch.dict(sys.modules, {"smartcard": None, "smartcard.System": None, "smartcard.scard": None}):
            self.assertFalse(REAL_PCSC_AVAILABLE())
        try: import smartcard.System, smartcard.scard  # noqa: F401
        except ImportError: self.skipTest("pyscard is not installed here")
        self.assertTrue(REAL_PCSC_AVAILABLE())
    def test_without_pyscard_in_a_real_process(self):
        """A child process in which `import smartcard` fails (cryptography still there), nothing patched:
        card-status says no backup card, and card-backup stops with nothing written."""
        code = r'''
import io, json, sys
sys.path[:0] = [sys.argv[1]]
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
import card_seed as cs, wallet_cli as w
d = Path(sys.argv[2]); cs.AUTH_DIR = d
card = cs.SimNTAG424()
class T:
    def wait_for_card(t, timeout=None, prompt=True): pass
    def close(t): pass
    def transmit(t, apdu): r, a, b = card.transmit(apdu); return bytes(r), a, b
real, cs.PCSCTransport = cs.PCSCTransport, T
if not (d / "w.mmm").exists():                # the first run makes the card wallet
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        assert w.main(["--file", str(d / "w.mmm"), "new", "--card", "--offline"]) == 0
cs.PCSCTransport = real
class Block:                                  # pyscard missing: any smartcard import fails
    def find_spec(self, name, path=None, target=None):
        if name == "smartcard" or name.startswith("smartcard."): raise ModuleNotFoundError(f"No module named {name!r}", name=name)
for k in [k for k in sys.modules if k == "smartcard" or k.startswith("smartcard.")]: del sys.modules[k]
sys.meta_path.insert(0, Block())
sys.exit(w.main(["--file", str(d / "w.mmm"), "--json", *sys.argv[3:]]))
'''
        env = {k: v for k, v in os.environ.items() if k not in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT")}
        repo = str(Path(__file__).resolve().parent.parent)
        with tempfile.TemporaryDirectory() as d:
            run = lambda *argv: subprocess.run([sys.executable, "-c", code, repo, d, *argv], stdin=subprocess.DEVNULL,
                                               capture_output=True, text=True, timeout=120, env=env)
            p = run("card-status")
            self.assertEqual(p.returncode, 0, p.stderr)
            d_ = json.loads(p.stdout)
            self.assertEqual((d_["count"], d_["backup_supported"]), (1, False))
            self.assertIn("the pyscard Python module", d_["note"]); self.assertNotIn("card-backup", d_["note"])
            p = run("card-backup", "--auto-swap")
            self.assertEqual((p.returncode, p.stdout), (1, ""), p.stderr)
            self.assertNotIn("Traceback", p.stderr)
            self.assertIn("error: pyscard not installed", p.stderr); self.assertIn("nothing was written", p.stderr)
    def test_dex_era_mmm5(self):
        fam = bytes.fromhex("a1b2c3d4e5f60718"); a, b = w.MMM5A + os.urandom(90), w.MMM5B + os.urandom(140)
        p = self.dir / "dex.mmm"; p.write_bytes(w.MMM5_MAGIC + bytes([w.KIND_CARD]) + fam + len(a).to_bytes(2, "big") + a + b)
        d = self.status_json(file=p)
        self.assertEqual({k: d[k] for k in ("card", "format", "family", "cards", "count", "backup_supported")},
                         {"card": True, "format": "mmm5", "family": fam.hex(), "cards": [], "count": None, "backup_supported": False})
        self.assertEqual(d["note"], DEX_NOTE)                            # MMM shows it word for word as the badge
    def test_other_dex_card_kinds(self):
        fam = bytes.fromhex("0f0e0d0c0b0a0908")
        for name, blob, fmt in (("v3.mmm", w.MMM3_MAGIC + fam + os.urandom(120), "mmm3"),
                                ("v4.mmm", w.MMM4_MAGIC + bytes([w.KIND_CARD]) + fam + os.urandom(150), "mmm4")):
            p = self.dir / name; p.write_bytes(blob)
            d = self.status_json(file=p)
            self.assertEqual((d["card"], d["format"], d["family"], d["count"], d["backup_supported"]), (True, fmt, fam.hex(), None, False), name)
            self.assertEqual(d["note"], DEX_NOTE, name)
    def test_non_card_wallets(self):
        for name, blob, fmt in (("pw.mmm", w.mmm_encode("ab" * 32, ""), "mmm1"), ("wallet.seed", b"cd" * 32 + b"\n", "seed")):
            p = self.dir / name; p.write_bytes(blob)
            d = self.status_json(file=p)
            self.assertEqual({k: d[k] for k in ("card", "format", "family", "cards", "count", "backup_supported")},
                             {"card": False, "format": fmt, "family": None, "cards": [], "count": None, "backup_supported": False}, name)
    def test_missing_wallet(self):
        rc, out, err = self.status(file=self.dir / "nope.mmm")
        self.assertEqual((rc, out), (1, "")); self.assertIn("no wallet at", err)
    def test_json_after_the_subcommand_and_human_text(self):
        rc, out, err = self.status("--json", json_out=False)
        self.assertEqual((rc, json.loads(out)["count"]), (0, 1))
        rc, out, err = self.status(json_out=False)
        self.assertEqual(rc, 0)
        self.assertIn(self.primary.uid_bytes.hex(), out); self.assertIn("permanent", out); self.assertIn("card-backup", out)

if __name__ == "__main__":
    unittest.main(verbosity=2)

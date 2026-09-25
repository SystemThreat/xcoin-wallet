#!/usr/bin/env python3
"""Card and reader faults: the card-provisioning commit point (grace pause, SIGTERM and SIGPIPE
held off during the write, a dead parent writes nothing), card-status when no backup card can be
made here, card-retry after the reader resets the card mid-read (never mid-write), and one plain
`error:` line with no traceback for every pyscard exception and CardError.

Simulated NTAG 424 DNA cards on the fake one-slot reader of test_card_backup, and the fake
pyscard of test_card_seed. No reader, no hardware."""

import io, json, os, signal, subprocess, sys, tempfile, time, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent))
try:
    import card_seed as cs
except ModuleNotFoundError as e:
    if __name__ == '__main__':
        print(f'SKIP: card tests need the optional {e.name} module (pip install cryptography pyscard)')
        raise SystemExit(0)
    raise unittest.SkipTest(f'card tests need the optional {e.name} module') from None
import wallet_cli as w
import test_card_backup as B
import test_card_seed as S

REAL_PCSC = cs.PCSCTransport                  # before any test swaps in a fake reader

RESET, REMOVED = 0x80100068, 0x80100069     # SCARD_W_RESET_CARD, SCARD_W_REMOVED_CARD
HINT = "If this keeps happening, unplug the card reader, plug it back in, and try again."

# --- stand-ins for every pyscard exception class: same names, bases and modules ---------------
class _WithHresult(Exception):
    """message + hresult, printed the way pyscard prints them"""
    def __init__(self, message="", hresult=-1):
        Exception.__init__(self, message); self.hresult = hresult
    def __str__(self):
        return Exception.__str__(self) + (f": (0x{self.hresult & 0xFFFFFFFF:08X})" if self.hresult != -1 else "")
SmartcardException = type("SmartcardException", (_WithHresult,), {"__module__": "smartcard.Exceptions"})
BaseSCardException = type("BaseSCardException", (_WithHresult,), {"__module__": "smartcard.pcsc.PCSCExceptions"})
FAKE_PYSCARD = {n: type(n, (SmartcardException,), {"__module__": "smartcard.Exceptions"}) for n in (
    "CardConnectionException", "CardRequestException", "CardRequestTimeoutException", "CardServiceException",
    "CardServiceStoppedException", "CardServiceNotFoundException", "InvalidATRMaskLengthException",
    "InvalidReaderException", "ListReadersException", "NoCardException", "NoReadersException")}
FAKE_PYSCARD["SmartcardException"] = SmartcardException
FAKE_PCSC = {n: type(n, (BaseSCardException,), {"__module__": "smartcard.pcsc.PCSCExceptions"}) for n in (
    "AddReaderToGroupException", "EstablishContextException", "ListReadersException", "IntroduceReaderException",
    "ReleaseContextException", "RemoveReaderFromGroupException")}
FAKE_PCSC["BaseSCardException"] = BaseSCardException
CCE = FAKE_PYSCARD["CardConnectionException"]
# pyscard's low-level C extension smartcard.scard raises its own `error`, whose module is plain "scard"
SCARD_ERROR = type("error", (Exception,), {"__module__": "scard"})
# faults from below pyscard (the reader's driver) or an answer that makes no sense: not pyscard classes at all
DRIVER_FAULTS = [("OSError", lambda: OSError(5, "Input/output error"), "the card reader reported an error ([Errno 5] Input/output error)"),
                 ("TimeoutError", TimeoutError, "the card reader did not answer in time (TimeoutError)"),
                 ("ConnectionResetError", lambda: ConnectionResetError(54, "Connection reset by peer"), "the card reader reported an error ("),
                 ("ValueError", lambda: ValueError("Invalid padding bytes."), "the card or the reader gave an answer that could not be used (Invalid padding bytes.)")]
# (name, make, words): make() builds a fresh exception for every injection, since card_io marks the one it sees

def fake_pyscard_errors():
    """One instance of every stand-in class (a CardConnectionException per hresult kind)."""
    out = [(f"Exceptions.{n}", c("Failed to transmit with protocol T1.", 0x8010001D)) for n, c in FAKE_PYSCARD.items()]
    out += [(f"PCSCExceptions.{n}", c("Failed to establish context", 0x8010001D)) for n, c in FAKE_PCSC.items()]
    out += [("CardConnectionException reset", CCE("Failed to transmit with protocol T1. Card was reset.", RESET)),
            ("NoCardException removed", FAKE_PYSCARD["NoCardException"]("Unable to connect", REMOVED)),
            ("scard.error", SCARD_ERROR("Failed to transmit with protocol T1."))]
    return out

def real_pyscard_errors():
    """One instance of every exception class the installed pyscard defines (none: it is not installed)."""
    try:
        import smartcard.Exceptions as SE, smartcard.pcsc.PCSCExceptions as PE, smartcard.scard as SC
    except Exception:
        return []
    out = [("smartcard.scard.error", SC.error("Failed to transmit with protocol T1."))]   # its __module__ is "scard"
    for mod in (SE, PE):
        for name, c in sorted(vars(mod).items()):
            if not (isinstance(c, type) and issubclass(c, BaseException) and c.__module__ == mod.__name__): continue
            for args, kw in ((("Failed to transmit with protocol T1.",), {"hresult": RESET}), ((0x8010001D,), {}),
                             (("x", 0x8010001D), {}), (("x",), {}), ((), {})):
                try: out.append((f"{mod.__name__}.{name}", c(*args, **kw))); break
                except TypeError: continue
            else: raise AssertionError(f"cannot build {name}")
    return out

def card_errors():
    return [("CardError", cs.CardError("card response MAC mismatch — possible tampering")),
            ("ReaderError", cs.ReaderError("the card reader went away")),
            ("CardError timeout", cs.ReaderError("no card presented in time"))]

def error_lines(err): return [l for l in err.splitlines() if l.startswith("error:")]

class Faulty(B.Harness):
    """The Harness card wallet (sealed primary card on the reader). `inject` schedules faults:
    (card, INS, exception, times) raises the exception instead of that APDU on that card; INS
    None = the first APDU of the exchange. Every APDU the reader passes is logged."""
    def setUp(self):
        super().setUp()
        self.faults, self.apdus = [], []
        real = self.reader.transport
        harness = self
        def transport():
            t = real(); inner = t.transmit
            def transmit(apdu):
                apdu = bytes(apdu); ins = apdu[1] if apdu[0] == 0x90 else None
                for f in harness.faults:
                    card, want, exc, left = f
                    if left and harness.reader.card is card and (want is None or want == ins):
                        f[3] -= 1; harness.apdus.append(("fault", ins)); raise exc
                harness.apdus.append(("apdu", ins, harness.reader.card))
                return inner(apdu)
            t.transmit = transmit
            return t
        p = mock.patch.object(cs, "PCSCTransport", transport); p.start(); self.addCleanup(p.stop)
        grace = mock.patch.object(w, "BROADCAST_GRACE", 0); grace.start(); self.addCleanup(grace.stop)
    def inject(self, card, ins, exc, times=1): self.faults.append([card, ins, exc, times])
    def writes_to(self, card): return sum(1 for a in self.apdus if a[0] == "apdu" and a[1] == 0x8D and a[2] is card)

# --- item 3: card-retry ----------------------------------------------------------------------
class TestCardRetry(Faulty):
    def test_reset_mid_read_is_read_again(self):
        self.inject(self.primary, None, CCE("Failed to transmit with protocol T1. Card was reset.", RESET))
        rc, out, err, steps = self.cli("card-test")
        self.assertEqual(rc, 0, err)
        self.assertEqual(steps, ["card-wait 60", "WAIT", "card-retry 1", "WAIT", "card-ok"])
        self.assertEqual(json.loads(out)["uid"], self.primary.uid_bytes.hex())
        self.assertIn("Keep it on the reader: reading it again (1 of 2)", err)
        self.assertNotIn("error:", err)
    def test_reset_in_the_middle_of_the_read_data(self):
        for code, exc in ((RESET, CCE), (REMOVED, FAKE_PYSCARD["NoCardException"]), (REMOVED, FAKE_PYSCARD["CardServiceException"])):
            self.faults, self.apdus = [], []
            self.inject(self.primary, 0xAD, exc("Failed to transmit with protocol T1.", code))    # after the authentication
            rc, out, err, steps = self.cli("card-test")
            self.assertEqual((rc, steps), (0, ["card-wait 60", "WAIT", "card-retry 1", "WAIT", "card-ok"]), (exc, err))
    def test_capped_at_two_retries(self):
        self.inject(self.primary, None, CCE("Failed to transmit with protocol T1. Card was reset.", RESET), times=99)
        rc, out, err, steps = self.cli("card-test")
        self.assertEqual((rc, out), (1, ""))
        self.assertEqual(steps, ["card-wait 60", "WAIT", "card-retry 1", "WAIT", "card-retry 2", "WAIT"])
        self.assertEqual(sum(1 for a in self.apdus if a[0] == "fault"), 3)           # 3 reads in all
        (line,) = error_lines(err)
        self.assertTrue(line.startswith("error: the card could not be read: the reader reset the card or lost contact with it, 3 times"), line)
        self.assertTrue(line.endswith("nothing was changed. " + HINT), line)
        self.assertNotIn("Traceback", err)
    def test_unlock_for_a_send_retries_then_sends_nothing_on_failure(self):
        self.inject(self.primary, None, CCE("Card was reset.", RESET), times=1)
        err = io.StringIO(); os.environ["XCOIN_EVENTS"] = "1"
        with redirect_stderr(err): self.assertEqual(w.read_seed(self.wallet), self.seed)
        self.assertEqual([l for l in err.getvalue().splitlines() if l.startswith("XCOIN-EVENT")],
                         ["XCOIN-EVENT card-wait 60", "XCOIN-EVENT card-retry 1", "XCOIN-EVENT card-ok"])
        self.inject(self.primary, None, CCE("Card was reset.", RESET), times=99)
        rc, out, err, steps = self.cli("--explorer", "http://127.0.0.1:9", "--hrp", "txa", "send", "txa1rdest", "1", "--yes")
        self.assertEqual((rc, out), (1, ""))
        self.assertEqual(steps, ["card-wait 60", "WAIT", "card-retry 1", "WAIT", "card-retry 2", "WAIT"])
        (line,) = error_lines(err)
        self.assertIn("nothing was sent. " + HINT, line)
    def test_wallet_card_of_a_backup_is_read_again(self):
        blank = cs.SimNTAG424(); self.swap_to(blank)
        self.inject(self.primary, None, CCE("Card was reset.", RESET))
        rc, out, err, steps = self.cli("card-backup", "--auto-swap")
        self.assertEqual(rc, 0, err)
        self.assertEqual(steps, ["card-wait 60", "WAIT", "card-retry 1", "WAIT", "card-ok", "card-swap", "REMOVAL", "card-removed",
                                 "card-wait 60", "WAIT", "card-provisioning", "card-ok", "done"])
        self.assertEqual(json.loads(out)["cards"], 2)
    def test_other_faults_are_not_retried(self):
        for exc in (cs.CardError("card response MAC mismatch — possible tampering"), FAKE_PYSCARD["NoReadersException"]("No reader found"),
                    FAKE_PCSC["EstablishContextException"]("Failed to establish context", 0x8010001D)):
            self.faults = []; self.inject(self.primary, None, exc)
            rc, out, err, steps = self.cli("card-test")
            self.assertEqual((rc, steps), (1, ["card-wait 60", "WAIT"]), exc)
            self.assertEqual(len(error_lines(err)), 1)
    def test_reset_during_a_write_is_never_retried(self):
        blank = cs.SimNTAG424(); self.swap_to(blank)
        self.inject(blank, 0x8D, CCE("Failed to transmit with protocol T1. Card was reset.", RESET))
        rc, out, err, steps = self.cli("card-backup", "--auto-swap")
        self.assertEqual((rc, out), (1, ""))
        self.assertNotIn("card-retry", " ".join(steps))
        self.assertEqual(steps[-2:], ["WAIT", "card-provisioning"])
        self.assertEqual(sum(1 for a in self.apdus if a[0] == "fault" and a[1] == 0x8D), 1)   # tried once
        self.assertEqual(self.writes_to(blank), 0)
        (line,) = error_lines(err)
        self.assertTrue(line.startswith("error: writing the backup card did not finish (the reader reset the card or lost contact with it"), line)
        self.assertIn("Do not rely on that card: make another backup with a fresh blank card. " + HINT, line)
        self.assertNotIn("Traceback", err)
    def test_reset_during_a_later_write_step_is_never_retried(self):
        blank = cs.SimNTAG424(); self.swap_to(blank)
        self.inject(blank, 0xC4, CCE("Card was reset.", RESET))                        # a key change, after the factor landed
        rc, out, err, steps = self.cli("card-backup", "--auto-swap")
        self.assertEqual(rc, 1)
        self.assertEqual(self.writes_to(blank), 1)
        self.assertNotIn("card-retry", " ".join(steps))
        self.assertIn("Do not rely on that card", err)
    def test_real_transport_reconnects_through_the_fake_pyscard(self):
        """PCSCTransport itself (status wait, one connect per arrival, transmit, close) over the
        fake pyscard: the retry closes the reset handle and connects afresh."""
        rec = json.loads(cs.auth_path(self.primary.uid_bytes.hex()).read_text())
        fake = S.FakePCSC([S.PICC], [{S.PICC: S.PRESENT}] * 10).install(self)
        card, sent = self.primary, []
        def conn_transmit(apdu):
            sent.append(apdu)
            if len(sent) == 2: raise CCE("Failed to transmit with protocol T1. Card was reset.", RESET)   # mid-read
            return card.transmit(bytes(apdu))
        real_readers = sys.modules["smartcard.System"].readers
        def readers():
            rs = real_readers()
            for r in rs:
                make = r.createConnection
                def create(make=make):
                    c = make(); c.transmit = conn_transmit; return c
                r.createConnection = create
            return rs
        sys.modules["smartcard.System"].readers = readers
        with mock.patch.object(cs, "PCSCTransport", REAL_PCSC):
            rc, out, err, steps = self.cli("card-test")
        self.assertEqual(rc, 0, err)
        self.assertEqual(steps, ["card-wait 60", "card-retry 1", "card-ok"])
        self.assertEqual(fake.connected, [S.PICC, S.PICC])                      # the reset handle was replaced by a new connect
        self.assertEqual((json.loads(out)["uid"], fake.contexts), (rec["uid"], 0))

# --- item 4: one plain error line -------------------------------------------------------------
class TestCleanCardErrors(Faulty):
    """Every pyscard / PC-SC exception class and every CardError, raised by the reader at the
    first APDU of a read, a blank-card check or a write: exit 1, one `error:` line that says
    what was (not) done, the reader hint for reader-level faults, never a traceback."""
    def check(self, rc, out, err, *, want, hint):
        self.assertEqual((rc, out), (1, ""), err)
        self.assertNotIn("Traceback", err)
        (line,) = error_lines(err)
        self.assertIn(want, line)
        self.assertEqual(line.endswith(HINT), hint, line)
        return line
    def matrix(self):
        return fake_pyscard_errors() + real_pyscard_errors()
    def test_every_pyscard_error_while_reading(self):
        errors = self.matrix()
        self.assertGreaterEqual(len(errors), 20)
        self.assertIn("scard.error", [n for n, _ in errors])
        self.assertTrue(all(w.pyscard_error(e) for _, e in errors))
        for name, exc in errors:
            with self.subTest(name):
                self.faults = []; self.inject(self.primary, None, exc, times=99)
                line = self.check(*self.cli("card-test")[:3], want="nothing was changed.", hint=True)
                self.assertTrue(line.startswith("error: the card could not be read: "), line)
                self.faults = []; self.inject(self.primary, None, exc, times=99)
                rc, out, err, _ = self.cli("--explorer", "http://127.0.0.1:9", "--hrp", "txa", "send", "txa1rdest", "1", "--yes")
                self.check(rc, out, err, want="; nothing was sent. ", hint=True)
    def test_every_pyscard_error_while_checking_the_blank_card(self):
        for name, exc in self.matrix():
            with self.subTest(name):
                blank = cs.SimNTAG424(); self.swap_to(blank); self.faults = []
                self.inject(blank, None, exc, times=99)
                rc, out, err, steps = self.cli("card-backup", "--auto-swap")
                self.check(rc, out, err, want="; nothing was written. ", hint=True)
                self.assertNotIn("card-provisioning", steps)
                self.assertTrue(all(k == cs.FACTORY_KEY for k in blank.keys.values()))
                self.assertEqual(bytes(blank.files[cs.CARD_FILE]), bytes(128))
                self.assertFalse(cs.auth_path(blank.uid_bytes.hex()).exists())
    def test_every_pyscard_error_while_writing(self):
        for name, exc in self.matrix():
            with self.subTest(name):
                blank = cs.SimNTAG424(); self.swap_to(blank); self.faults = []
                self.inject(blank, 0x8D, exc, times=99)
                rc, out, err, steps = self.cli("card-backup", "--auto-swap")
                line = self.check(rc, out, err, want="Do not rely on that card: make another backup with a fresh blank card.", hint=True)
                self.assertTrue(line.startswith("error: writing the backup card did not finish ("), line)
                self.assertEqual(steps[-1], "card-provisioning")
    def test_every_card_error(self):
        for name, exc in card_errors():
            reader = isinstance(exc, cs.ReaderError)
            with self.subTest(name):
                self.reader.card = self.primary; self.faults = []; self.inject(self.primary, None, exc)
                line = self.check(*self.cli("card-test")[:3], want=f"error: {exc}; nothing was changed.", hint=reader)
                blank = cs.SimNTAG424(); self.swap_to(blank); self.faults = []
                self.inject(blank, 0x8D, exc)
                rc, out, err, _ = self.cli("card-backup", "--auto-swap")
                self.check(rc, out, err, want=f"error: writing the backup card did not finish ({exc}). Do not rely on that card", hint=reader)
    def test_card_errors_that_already_say_what_was_done(self):
        used = cs.SimNTAG424(); used.keys[cs.KEY_READ] = os.urandom(16); self.swap_to(used)
        rc, out, err, _ = self.cli("card-backup", "--auto-swap")
        line = self.check(rc, out, err, want="is not blank", hint=False)
        self.assertTrue(line.endswith("nothing was written"), line)                  # no second "nothing was ..."
    def test_waits_that_time_out_carry_the_hint(self):
        class Nothing:
            def wait_for_card(t, timeout=None, prompt=True): raise cs.ReaderError("no card presented in time")
            def close(t): pass
        with mock.patch.object(cs, "PCSCTransport", Nothing):
            rc, out, err, _ = self.cli("--explorer", "http://127.0.0.1:9", "--hrp", "txa", "balance")
        self.check(rc, out, err, want="error: no card presented in time; nothing was changed. ", hint=True)
    def test_new_card_and_card_reset_faults(self):
        blank = cs.SimNTAG424(); self.reader.card = blank
        self.inject(blank, 0x8D, CCE("Card was reset.", RESET))
        rc, out, err, _ = self.cli("new", "--card", "--offline", file=self.dir / "second.mmm")
        line = self.check(rc, out, err, want="setting up the new card did not finish (the reader reset the card", hint=True)
        self.assertIn("so no wallet was created. Do not rely on that card.", line)
        self.assertFalse((self.dir / "second.mmm").exists())
        spare = cs.SimNTAG424(); self.reader.card = spare
        with redirect_stderr(io.StringIO()):
            f = cs.SecureBuffer(os.urandom(32)); cs.provision_card(self.reader.transport(), f, cs.family_of(f.bytes())); f.close()
        self.faults = []; self.inject(spare, 0xC4, CCE("Card was reset.", RESET))
        rc, out, err, _ = self.cli("card-reset", "--yes")
        line = self.check(rc, out, err, want="resetting the card did not finish (", hint=True)
        self.assertIn("Its key file was kept", line)
        self.assertTrue(cs.auth_path(spare.uid_bytes.hex()).exists())
    def test_damaged_key_file_is_a_plain_error(self):
        cs.auth_path(self.primary.uid_bytes.hex()).write_text("{not json")
        rc, out, err, _ = self.cli("card-test")
        self.check(rc, out, err, want="cannot be read", hint=False)
    def test_driver_faults_while_reading(self):
        """An OSError, TimeoutError or ValueError from below pyscard during a read: one line, the hint."""
        for name, make, what in DRIVER_FAULTS:
            with self.subTest(name):
                self.reader.card = self.primary; self.faults, self.apdus = [], []; self.inject(self.primary, None, make(), times=99)
                line = self.check(*self.cli("card-test")[:3], want="nothing was changed. " + HINT, hint=True)
                self.assertTrue(line.startswith("error: the card could not be read: " + what), line)
                self.assertEqual(sum(1 for a in self.apdus if a[0] == "fault"), 1)          # not a reset: not read again
                self.faults = []; self.inject(self.primary, None, make(), times=99)
                rc, out, err, steps = self.cli("--explorer", "http://127.0.0.1:9", "--hrp", "txa", "send", "txa1rdest", "1", "--yes")
                self.check(rc, out, err, want="; nothing was sent. " + HINT, hint=True)
                self.assertNotIn("broadcast-begin", steps)
    def test_driver_faults_while_checking_the_blank_card(self):
        for name, make, what in DRIVER_FAULTS:
            with self.subTest(name):
                blank = cs.SimNTAG424(); self.swap_to(blank); self.faults = []
                self.inject(blank, 0x71, make(), times=99)                                      # the factory-key check
                rc, out, err, steps = self.cli("card-backup", "--auto-swap")
                line = self.check(rc, out, err, want="; nothing was written. " + HINT, hint=True)
                self.assertIn(what, line)
                self.assertNotIn("card-provisioning", steps)
                self.assertTrue(all(k == cs.FACTORY_KEY for k in blank.keys.values()))
                self.assertEqual(bytes(blank.files[cs.CARD_FILE]), bytes(128))
                self.assertFalse(cs.auth_path(blank.uid_bytes.hex()).exists())
    def test_driver_faults_before_a_new_card_or_a_reset_writes(self):
        for name, make, what in DRIVER_FAULTS:
            with self.subTest(name):
                blank = cs.SimNTAG424(); self.reader.card = blank; self.faults = []; self.inject(blank, None, make())
                rc, out, err, _ = self.cli("new", "--card", "--offline", file=self.dir / "second.mmm")
                self.check(rc, out, err, want="nothing was written to the card and no wallet was created. " + HINT, hint=True)
                self.assertFalse((self.dir / "second.mmm").exists())
                self.assertTrue(all(k == cs.FACTORY_KEY for k in blank.keys.values()))
                spare = cs.SimNTAG424(); self.reader.card = spare
                with redirect_stderr(io.StringIO()):
                    f = cs.SecureBuffer(os.urandom(32)); cs.provision_card(self.reader.transport(), f, cs.family_of(f.bytes())); f.close()
                keys = dict(spare.keys); self.faults = []; self.inject(spare, None, make())
                rc, out, err, _ = self.cli("card-reset", "--yes")
                self.check(rc, out, err, want="nothing was changed on the card. " + HINT, hint=True)
                self.assertEqual(spare.keys, keys)
                self.assertTrue(cs.auth_path(spare.uid_bytes.hex()).exists())
    def test_driver_fault_while_waiting_for_the_swap(self):
        for name, make, what in DRIVER_FAULTS:
            with self.subTest(name):
                real = cs.PCSCTransport
                def transport():
                    t = real()
                    def removal(timeout=None): raise make()
                    t.wait_for_removal = removal; return t
                self.reader.card = self.primary
                with mock.patch.object(cs, "PCSCTransport", transport):
                    rc, out, err, steps = self.cli("card-backup", "--auto-swap")
                self.check(rc, out, err, want="; nothing was written. " + HINT, hint=True)
                self.assertEqual(steps[-1], "card-swap")
    def test_an_answer_that_makes_no_sense(self):
        """The reader hands back a 5-byte answer to the authentication (the card left the field half
        way): the cipher code raises its own ValueError; still one line, nothing sent."""
        real = cs.PCSCTransport
        def transport():
            t = real(); inner = t.transmit
            def transmit(apdu):
                if bytes(apdu)[:2] == b"\x90\x71": return b"\x01\x02\x03\x04\x05", 0x91, 0xAF
                return inner(apdu)
            t.transmit = transmit; return t
        with mock.patch.object(cs, "PCSCTransport", transport):
            rc, out, err, _ = self.cli("--explorer", "http://127.0.0.1:9", "--hrp", "txa", "send", "txa1rdest", "1", "--yes")
        line = self.check(rc, out, err, want="; nothing was sent. " + HINT, hint=True)
        self.assertTrue(line.startswith("error: the card could not be read: the card or the reader gave an answer that could not be used ("), line)
    def test_driver_faults_during_a_write_keep_the_write_wording(self):
        """Writes turn every fault into "did not finish ... do not rely on that card"; a fault of the
        reader's driver inside it is named like one during a read, and carries the reader hint."""
        for name, make, what in DRIVER_FAULTS:
            with self.subTest(name):
                blank = cs.SimNTAG424(); self.swap_to(blank); self.faults = []
                self.inject(blank, 0x8D, make())
                rc, out, err, steps = self.cli("card-backup", "--auto-swap")
                line = self.check(rc, out, err, want="Do not rely on that card: make another backup with a fresh blank card. " + HINT, hint=True)
                self.assertTrue(line.startswith(f"error: writing the backup card did not finish ({what}"), line)
                self.assertEqual(steps[-1], "card-provisioning")
                self.assertNotIn("reported an error (the card reader", line)                   # named once
    def test_driver_faults_during_a_new_card_or_a_reset_carry_the_hint(self):
        for name, make, what in DRIVER_FAULTS:
            with self.subTest(name):
                blank = cs.SimNTAG424(); self.reader.card = blank; self.faults = []; self.inject(blank, 0x8D, make())
                rc, out, err, steps = self.cli("new", "--card", "--offline", file=self.dir / "second.mmm")
                line = self.check(rc, out, err, want="so no wallet was created. Do not rely on that card. " + HINT, hint=True)
                self.assertTrue(line.startswith(f"error: setting up the new card did not finish ({what}"), line)
                self.assertEqual(steps[-1], "card-provisioning")
                self.assertFalse((self.dir / "second.mmm").exists())
                spare = cs.SimNTAG424(); self.reader.card = spare
                with redirect_stderr(io.StringIO()):
                    f = cs.SecureBuffer(os.urandom(32)); cs.provision_card(self.reader.transport(), f, cs.family_of(f.bytes())); f.close()
                self.faults = []; self.inject(spare, 0xC4, make())                                # during the key roll-back
                rc, out, err, _ = self.cli("card-reset", "--yes")
                line = self.check(rc, out, err, want="Its key file was kept: put the card back on the reader and run card-reset again. " + HINT, hint=True)
                self.assertTrue(line.startswith(f"error: resetting the card did not finish ({what}"), line)
                self.assertTrue(cs.auth_path(spare.uid_bytes.hex()).exists())
    def test_a_key_file_that_cannot_be_saved_is_not_called_a_reader_fault(self):
        """The disk, not the reader: a write's key-file step names itself, with no unplug hint."""
        full = OSError(28, "No space left on device")
        for step in ("save_auth", "_update_auth"):
            with self.subTest(step):
                blank = cs.SimNTAG424(); self.swap_to(blank); self.faults = []
                with mock.patch.object(cs, step, side_effect=full):
                    rc, out, err, steps = self.cli("card-backup", "--auto-swap")
                line = self.check(rc, out, err, want="Do not rely on that card: make another backup with a fresh blank card.", hint=False)
                self.assertEqual(line, f"error: writing the backup card did not finish (the key file for card {blank.uid_bytes.hex()} "
                                       "could not be saved on this Mac: [Errno 28] No space left on device). "
                                       "Do not rely on that card: make another backup with a fresh blank card.")
                self.assertEqual(steps[-1], "card-provisioning")
    def test_the_cause_of_a_write_fault_is_classified_like_a_read_fault(self):
        for cause, what, hint in ((OSError(5, "Input/output error"), "the card reader reported an error ([Errno 5] Input/output error)", True),
                                  (TimeoutError(), "the card reader did not answer in time (TimeoutError)", True),
                                  (CCE("Card was reset.", RESET), "the reader reset the card or lost contact with it", True),
                                  (cs.CardError("card response MAC mismatch"), "card response MAC mismatch", False),
                                  (cs.ReaderError("the card reader went away"), "the card reader went away", True),
                                  (KeyboardInterrupt(), "it was interrupted", False)):
            with self.subTest(type(cause).__name__):
                line = w.card_error_line(cs.CardWriteError("the write to card 04 did not finish (x)", cause), "card-backup")
                self.assertTrue(line.startswith(f"writing the backup card did not finish ({what}"), line)
                self.assertEqual(line.endswith(HINT), hint, line)
    def test_a_closed_pipe_is_not_called_a_card_fault(self):
        """card_io marks faults of the card exchange only: our own output failing is not the card."""
        with self.assertRaises(BrokenPipeError) as got:
            with w.card_io(): raise BrokenPipeError(32, "Broken pipe")
        self.assertIsNone(w.card_error_line(got.exception, "send"))
        for exc in (w.WalletError("this card does not belong to this wallet"), cs.CardError("x"), SCARD_ERROR("x")):
            with self.assertRaises(type(exc)) as got:
                with w.card_io(): raise exc
            self.assertFalse(getattr(got.exception, "card_fault", False), exc)
        self.assertIsNone(w.card_error_line(OSError(5, "Input/output error"), "send"))   # unmarked: not a card fault
    def test_no_traceback_from_a_real_process(self):
        """The same faults in a child process, whose real stderr is read: one line, no traceback."""
        code = r'''
import io, json, os, sys
sys.path[:0] = sys.argv[1:3]
from contextlib import redirect_stdout, redirect_stderr
import card_seed as cs, wallet_cli as w, test_card_faults as F
from pathlib import Path
d = Path(sys.argv[3]); cs.AUTH_DIR = d
card, blank, kind = cs.SimNTAG424(), cs.SimNTAG424(), sys.argv[4]
st = {"card": card}
backup = "card-backup" in sys.argv                  # the fault hits the blank card's check, not the wallet card's read
class T:
    def wait_for_card(t, timeout=None, prompt=True): pass
    def wait_for_removal(t, timeout=None): st["card"] = blank
    def close(t): pass
    def transmit(t, apdu):
        if T.armed and (st["card"] is blank or not backup):
            if kind == "reset": raise F.CCE("Failed to transmit with protocol T1. Card was reset.", F.RESET)
            if kind == "context": raise F.FAKE_PCSC["EstablishContextException"]("Failed to establish context", 0x8010001D)
            if kind == "card": raise cs.CardError("card response MAC mismatch — possible tampering")
            if kind == "scard":
                try: import smartcard.scard as SC; raise SC.error("Failed to transmit with protocol T1.")
                except ImportError: raise F.SCARD_ERROR("Failed to transmit with protocol T1.")
            if kind == "oserror": raise OSError(5, "Input/output error")
            if kind == "timeout": raise TimeoutError()
            if kind == "value": raise ValueError("Invalid padding bytes.")
        r, a, b = st["card"].transmit(apdu); return bytes(r), a, b
T.armed = False
cs.PCSCTransport = T
with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
    assert w.main(["--file", str(d / "w.mmm"), "new", "--card", "--offline"]) == 0
T.armed = True
sys.exit(w.main(["--file", str(d / "w.mmm"), "--json", *sys.argv[5:]]))
'''
        env = {k: v for k, v in os.environ.items() if k not in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT")}
        for kind, hint in (("reset", True), ("context", True), ("card", False), ("scard", True), ("oserror", True),
                           ("timeout", True), ("value", True)):
            for command in (["card-test"], ["--explorer", "http://127.0.0.1:9", "--hrp", "txa", "balance"],
                            ["--explorer", "http://127.0.0.1:9", "--hrp", "txa", "send", "txa1rdest", "1", "--yes"],
                            ["card-backup", "--auto-swap"]):
                with self.subTest(kind=kind, command=command[-1]), tempfile.TemporaryDirectory() as d:
                    p = subprocess.run([sys.executable, "-c", code, str(HERE.parent), str(HERE), d, kind, *command],
                                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, env=env)
                    self.assertEqual((p.returncode, p.stdout), (1, ""), p.stderr)
                    self.assertNotIn("Traceback", p.stderr)
                    lines = p.stderr.strip().splitlines()
                    self.assertEqual(len(error_lines(p.stderr)), 1, p.stderr)
                    self.assertTrue(lines[-1].startswith("error: "), p.stderr)
                    self.assertEqual(lines[-1].endswith(HINT), hint, p.stderr)
                    done = {"card-test": "nothing was changed", "balance": "nothing was changed", "send": "nothing was sent",
                            "card-backup": "nothing was written"}[next(c for c in command if c in ("card-test", "balance", "send", "card-backup"))]
                    self.assertIn(done, lines[-1])

# --- item 1: the card-provisioning commit point ---------------------------------------------
class TestProvisioningCommit(Faulty):
    def test_pause_before_the_first_write_and_signals_held_off_during_it(self):
        blank = cs.SimNTAG424(); self.swap_to(blank)
        line, before = [], signal.getsignal(signal.SIGTERM)
        class Tee(io.StringIO):
            def write(s, text):
                for l in text.splitlines():
                    if l.startswith("XCOIN-EVENT"): line.append(("event", l.split(" ", 1)[1], signal.getsignal(signal.SIGTERM)))
                return super().write(text)
        real = cs.PCSCTransport
        def transport():
            t = real(); inner = t.transmit
            def transmit(apdu):
                if self.reader.card is blank:
                    line.append(("apdu", bytes(apdu)[1], signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGPIPE)))
                return inner(apdu)
            t.transmit = transmit; return t
        os.environ["XCOIN_EVENTS"] = "1"
        with mock.patch.object(cs, "PCSCTransport", transport), mock.patch.object(w, "BROADCAST_GRACE", 0.5), \
             mock.patch.object(w.time, "sleep", lambda s: line.append(("sleep", s, signal.getsignal(signal.SIGTERM)))), \
             redirect_stdout(io.StringIO()), redirect_stderr(Tee()):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", "--json", "card-backup", "--auto-swap"])
        self.assertEqual(rc, 0)
        at = next(i for i, k in enumerate(line) if k[:2] == ("event", "card-provisioning"))
        # the blank-card checks came first; then the event, the pause, and only then the first write
        self.assertTrue(any(k[0] == "apdu" for k in line[:at]))
        self.assertEqual(line[at + 1][:2], ("sleep", 0.5))
        writes = [k for k in line[at + 2:] if k[0] == "apdu"]
        self.assertEqual([k[1] for k in writes[:3]], [0x71, 0xAF, 0x8D])              # authenticate with the write key, write
        self.assertEqual(sum(1 for k in line[:at] if k[0] == "apdu" and k[1] == 0x8D), 0)
        # a cancel already on its way still lands (default SIGTERM) until the pause is over ...
        self.assertEqual((line[at][2], line[at + 1][2]), (before, before))
        # ... from the first write to the sealed key file nothing stops it
        self.assertTrue(all(k[2] == signal.SIG_IGN and k[3] == signal.SIG_IGN for k in writes), writes)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)                      # and SIGTERM stops the CLI again
        rec = json.loads(cs.auth_path(blank.uid_bytes.hex()).read_text())
        self.assertEqual((rec["state"], rec["permanent"]), ("provisioned", True))
    def test_no_pause_without_events_but_the_write_is_still_held(self):
        blank = cs.SimNTAG424(); self.swap_to(blank)
        slept, held, before = [], [], signal.getsignal(signal.SIGTERM)
        real = cs.PCSCTransport
        def transport():
            t = real(); inner = t.transmit
            def transmit(apdu):
                if self.reader.card is blank and bytes(apdu)[1] == 0x8D: held.append(signal.getsignal(signal.SIGTERM))
                return inner(apdu)
            t.transmit = transmit; return t
        with mock.patch.object(cs, "PCSCTransport", transport), mock.patch.object(w, "BROADCAST_GRACE", 0.5), \
             mock.patch.object(w.time, "sleep", slept.append):
            rc, out, err, steps = self.cli("card-backup", "--auto-swap", events=False)
        self.assertEqual((rc, slept, held), (0, [], [signal.SIG_IGN]), err)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
    def test_signal_restored_after_a_failed_write(self):
        blank = cs.SimNTAG424(); self.swap_to(blank); before = signal.getsignal(signal.SIGTERM)
        self.inject(blank, 0x8D, CCE("Card was reset.", RESET))
        self.assertEqual(self.cli("card-backup", "--auto-swap")[0], 1)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
    # new --card: its card is written the way a backup card is, and its wallet file belongs to the write
    def new_card_timeline(self, blank, events=True):
        """new --card on `blank`, with every step it takes logged in order, each with the SIGTERM
        (and for APDUs the SIGPIPE) disposition in force at that moment."""
        line, wallet = [], self.dir / "second.mmm"
        term = lambda: signal.getsignal(signal.SIGTERM)
        class Tee(io.StringIO):
            def write(s, text):
                for l in text.splitlines():
                    if l.startswith("XCOIN-EVENT"): line.append(("event", l.split(" ", 1)[1], term()))
                return super().write(text)
        real, real_sleep = cs.PCSCTransport, time.sleep
        def transport():
            t = real(); inner = t.transmit
            def transmit(apdu):
                if self.reader.card is blank: line.append(("apdu", bytes(apdu)[1], term(), signal.getsignal(signal.SIGPIPE)))
                return inner(apdu)
            t.transmit = transmit; return t
        def sleep(sec):                                   # the CLI's own pause only (subprocess polls with time.sleep too)
            if sys._getframe(1).f_globals.get("__name__") != "wallet_cli": return real_sleep(sec)
            line.append(("sleep", sec, term()))
        def step(name, fn):
            def run(*a, **kw): line.append((name, None, term())); return fn(*a, **kw)
            return run
        os.environ["XCOIN_EVENTS"] = "1" if events else "0"
        with mock.patch.object(cs, "PCSCTransport", transport), mock.patch.object(w, "BROADCAST_GRACE", 0.5), \
             mock.patch.object(w.time, "sleep", sleep), mock.patch.object(w, "new_passphrase", step("passphrase", w.new_passphrase)), \
             mock.patch.object(w, "mmm2_encode", step("wallet-file", w.mmm2_encode)), \
             mock.patch.object(cs, "make_permanent", step("seal", cs.make_permanent)), \
             redirect_stdout(io.StringIO()) as out, redirect_stderr(Tee()) as err:
            rc = w.main(["--file", str(wallet), "--config", "/nonexistent", "--json", "new", "--card", "--offline"])
        return rc, line, wallet, out.getvalue(), err.getvalue()
    def test_new_card_pauses_before_the_first_write_and_holds_signals_until_the_wallet_is_written(self):
        blank = cs.SimNTAG424(); self.reader.card = blank; before = signal.getsignal(signal.SIGTERM)
        rc, line, wallet, out, err = self.new_card_timeline(blank)
        self.assertEqual(rc, 0, err)
        names = [k[1] if k[0] == "event" else k[0] for k in line]
        at = names.index("card-provisioning")
        # the passphrase is asked before the card is touched; then the blank-card checks, the event, the pause
        self.assertEqual(names[0], "passphrase")
        self.assertTrue(any(k[0] == "apdu" for k in line[:at]))
        self.assertEqual(sum(1 for k in line[:at] if k[0] == "apdu" and k[1] == 0x8D), 0)
        self.assertEqual(line[at + 1][:2], ("sleep", 0.5))
        self.assertEqual([k[1] for k in line[at + 2:at + 5]], [0x71, 0xAF, 0x8D])            # authenticate with the write key, write
        # a cancel already on its way still lands (default SIGTERM) until the pause is over ...
        self.assertEqual((line[at][2], line[at + 1][2]), (before, before))
        # ... from the first write through card-ok, the wallet file and the seal nothing stops it
        rest = line[at + 2:]
        self.assertEqual([n for n in names[at + 2:] if n != "apdu"], ["card-ok", "wallet-file", "seal"])
        self.assertTrue(all(k[2] == signal.SIG_IGN for k in rest), rest)
        self.assertTrue(all(k[3] == signal.SIG_IGN for k in rest if k[0] == "apdu"), rest)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)                      # and SIGTERM stops the CLI again
        d = json.loads(out)
        rec = json.loads(cs.auth_path(blank.uid_bytes.hex()).read_text())
        self.assertEqual((rec["state"], rec["permanent"], d["permanent"], d["card_uid"]), ("provisioned", True, True, blank.uid_bytes.hex()))
        self.assertEqual(w.mmm2_family(wallet.read_bytes()), d["family"])
    def test_new_card_without_events_has_no_pause_but_the_write_is_still_held(self):
        blank = cs.SimNTAG424(); self.reader.card = blank; before = signal.getsignal(signal.SIGTERM)
        rc, line, wallet, out, err = self.new_card_timeline(blank, events=False)
        self.assertEqual(rc, 0, err)
        self.assertFalse(any(k[0] in ("sleep", "event") for k in line), line)
        held = [k for k in line if k[0] in ("wallet-file", "seal") or (k[0] == "apdu" and k[1] == 0x8D)]
        self.assertEqual(len(held), 3); self.assertTrue(all(k[2] == signal.SIG_IGN for k in held), held)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
        self.assertTrue(wallet.exists())
    def test_new_card_refused_before_the_write_never_commits(self):
        used = cs.SimNTAG424(); used.keys[cs.KEY_READ] = os.urandom(16); self.reader.card = used
        before = signal.getsignal(signal.SIGTERM)
        rc, line, wallet, out, err = self.new_card_timeline(used)
        self.assertEqual(rc, 1); self.assertIn("is not blank", err)
        self.assertFalse(any(k[0] in ("sleep", "event") and k[1] == "card-provisioning" for k in line))
        self.assertFalse(wallet.exists()); self.assertEqual(signal.getsignal(signal.SIGTERM), before)
    def test_new_card_signal_restored_after_a_failed_write(self):
        blank = cs.SimNTAG424(); self.reader.card = blank; before = signal.getsignal(signal.SIGTERM)
        self.inject(blank, 0x8D, CCE("Card was reset.", RESET))
        rc, out, err, steps = self.cli("new", "--card", "--offline", file=self.dir / "second.mmm")
        self.assertEqual((rc, steps[-1]), (1, "card-provisioning"), err)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)
        self.assertFalse((self.dir / "second.mmm").exists())

class TestProvisioningProcess(unittest.TestCase):
    """card-backup --auto-swap as a real child process on real pipes, with simulated cards whose
    state the child saves after every APDU. The parent plays MMM: it reads the events, and
    sends SIGTERM or closes its pipes at chosen moments."""
    CHILD = r'''
import contextlib, io, json, os, signal, sys, time
tmp, mode, sigpipe = sys.argv[1:4]; sys.path[:0] = sys.argv[4:6]
import card_seed as cs, wallet_cli as w
from pathlib import Path
d = Path(tmp); cs.AUTH_DIR = d
primary, blank = cs.SimNTAG424(), cs.SimNTAG424()
st = {"card": primary, "waits": 0}
def save():
    (d / "blank.tmp").write_text(json.dumps({"uid": blank.uid_bytes.hex(), "file": bytes(blank.files[cs.CARD_FILE]).hex(),
                                              "keys": {str(k): v.hex() for k, v in blank.keys.items()}}))
    os.replace(d / "blank.tmp", d / "blank.json")
def wait_file(name):
    end = time.monotonic() + 20
    while not (d / name).exists() and time.monotonic() < end: time.sleep(0.005)
class T:
    def wait_for_card(t, timeout=None, prompt=True):
        st["waits"] += 1
        if st["waits"] == 3:                   # 1: new --card, 2: the wallet card, 3: the blank card
            if mode == "dead-parent": wait_file("closed")
            st["card"] = blank
    def wait_for_removal(t, timeout=None): st["card"] = None
    def close(t): pass
    def transmit(t, apdu):
        card = st["card"]
        r, a, b = card.transmit(apdu)
        if card is blank:
            save(); ins = bytes(apdu)[1]
            if (mode, ins) in (("term-at-write", 0x8D), ("term-at-keychange", 0xC4)) and not (d / "at").exists():
                (d / "at").touch(); wait_file("signalled"); time.sleep(0.05)
            if mode == "slow": time.sleep(0.03)
        return bytes(r), a, b
cs.PCSCTransport = T
save()
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    assert w.main(["--file", str(d / "w.mmm"), "new", "--card", "--offline"]) == 0
os.environ["XCOIN_EVENTS"] = "1"
if sigpipe == "default": signal.signal(signal.SIGPIPE, signal.SIG_DFL)   # as if not Python's own SIG_IGN (new --card set it aside)
sys.exit(w.main(["--file", str(d / "w.mmm"), *sys.argv[6:], "card-backup", "--auto-swap"]))
'''
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
    def start(self, mode, *argv, sigpipe="python"):
        for f in self.d.glob("*"):
            if f.is_file(): f.unlink()
        env = {k: v for k, v in os.environ.items() if k not in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT")}
        return subprocess.Popen([sys.executable, "-c", self.CHILD, str(self.d), mode, sigpipe, str(HERE.parent), str(HERE), *argv],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    def blank(self):
        b = json.loads((self.d / "blank.json").read_text())
        factory = all(v == bytes(16).hex() for v in b["keys"].values())
        rec = self.d / f"card-{b['uid']}.auth"
        return b, factory, (json.loads(rec.read_text()) if rec.exists() else None)
    def assert_whole(self, rc):
        """Never half written: untouched (factory keys, empty file, no key file) or finished and sealed."""
        b, factory, rec = self.blank()
        untouched = factory and b["file"] == bytes(128).hex() and rec is None
        finished = (not factory and b["file"] != bytes(128).hex() and rec is not None
                    and (rec["state"], rec["permanent"]) == ("provisioned", True))
        self.assertTrue(untouched or finished, (rc, b, rec))
        return untouched
    def test_sigterm_right_after_the_event_lands_in_the_pause(self):
        """MMM's cancel crossed the event line: it lands in the grace pause, before any write."""
        p = self.start("slow")
        for line in p.stderr:
            if line.startswith(b"XCOIN-EVENT card-provisioning"): p.send_signal(signal.SIGTERM); break
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, -signal.SIGTERM, err)
        self.assertTrue(self.assert_whole(p.returncode))                                # untouched
    def test_sigterm_during_the_write_is_held_off(self):
        """A SIGTERM once the factor is on the card, or once the key file says factor_written:
        the CLI finishes the card and seals it."""
        for mode in ("term-at-write", "term-at-keychange"):
            with self.subTest(mode):
                p = self.start(mode, "--json")
                end = time.monotonic() + 60
                while not (self.d / "at").exists() and p.poll() is None and time.monotonic() < end: time.sleep(0.005)
                self.assertTrue((self.d / "at").exists(), p.stderr.read() if p.poll() is not None else "no write")
                if mode == "term-at-keychange":
                    b = json.loads((self.d / "blank.json").read_text())
                    self.assertEqual(json.loads((self.d / f"card-{b['uid']}.auth").read_text())["state"], "factor_written")
                p.send_signal(signal.SIGTERM); (self.d / "signalled").touch()
                out, err = p.communicate(timeout=60)
                self.assertEqual(p.returncode, 0, err)
                self.assertFalse(self.assert_whole(p.returncode))                        # finished and sealed
                self.assertEqual(json.loads(out)["cards"], 2)
                self.assertIn(b"XCOIN-EVENT card-ok", err); self.assertIn(b"XCOIN-EVENT done", err)
    def test_parent_gone_before_card_provisioning_writes_nothing(self):
        """MMM died while the blank card was awaited: nobody would see the card being written,
        so the strict card-provisioning write stops the run before the card is touched."""
        for argv in (("--json",), ()):
            for sigpipe in ("python", "default"):
                with self.subTest(argv=argv, sigpipe=sigpipe):
                    p = self.start("dead-parent", *argv, sigpipe=sigpipe)
                    waits = 0
                    for line in p.stderr:
                        if line.startswith(b"XCOIN-EVENT card-wait"): waits += 1
                        if waits == 2: break                                            # the blank card's wait
                    p.stdout.close(); p.stderr.close(); (self.d / "closed").touch()
                    rc = p.wait(timeout=60)
                    self.assertNotEqual(rc, 0)
                    self.assertTrue(self.assert_whole(rc))                              # untouched, no key file for it
                    self.assertEqual(len(list(self.d.glob("card-*.auth"))), 1)          # the wallet card's only

class TestNewCardProcess(unittest.TestCase):
    """new --card as a real child process on real pipes (the way MMM runs it: --offline, events on),
    with a simulated blank card whose state the child saves after every APDU. The parent plays MMM."""
    CHILD = r'''
import contextlib, io, json, os, signal, sys, time
tmp, mode, sigpipe = sys.argv[1:4]; sys.path[:0] = sys.argv[4:6]
if sigpipe == "default": signal.signal(signal.SIGPIPE, signal.SIG_DFL)   # as if not Python's own SIG_IGN
import card_seed as cs, wallet_cli as w
from pathlib import Path
d = Path(tmp); cs.AUTH_DIR = d
blank = cs.SimNTAG424()
def save():
    (d / "blank.tmp").write_text(json.dumps({"uid": blank.uid_bytes.hex(), "file": bytes(blank.files[cs.CARD_FILE]).hex(),
                                              "keys": {str(k): v.hex() for k, v in blank.keys.items()}}))
    os.replace(d / "blank.tmp", d / "blank.json")
def wait_file(name):
    end = time.monotonic() + 20
    while not (d / name).exists() and time.monotonic() < end: time.sleep(0.005)
def hold():                                    # the parent signals here, then the child goes on
    (d / "at").touch(); wait_file("signalled"); time.sleep(0.05)
class T:
    def wait_for_card(t, timeout=None, prompt=True):
        if mode == "dead-parent": wait_file("closed")
    def close(t): pass
    def transmit(t, apdu):
        r, a, b = blank.transmit(apdu)
        save(); ins = bytes(apdu)[1]
        if (mode, ins) in (("term-at-write", 0x8D), ("term-at-keychange", 0xC4)) and not (d / "at").exists(): hold()
        if mode == "slow": time.sleep(0.03)
        return bytes(r), a, b
cs.PCSCTransport = T
if mode == "term-before-wallet-file":         # the card is done, its wallet file not written yet
    encode = w.mmm2_encode
    def mmm2_encode(*a):
        hold(); return encode(*a)
    w.mmm2_encode = mmm2_encode
save()
os.environ["XCOIN_EVENTS"] = "1"
sys.exit(w.main(["--file", str(d / "w.mmm"), "--json", "new", "--card", "--offline"]))
'''
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
    def start(self, mode, sigpipe="python"):
        for f in self.d.glob("*"):
            if f.is_file(): f.unlink()
        env = {k: v for k, v in os.environ.items() if k not in ("XCOIN_EVENTS", "XCOIN_CARD_TIMEOUT")}
        return subprocess.Popen([sys.executable, "-c", self.CHILD, str(self.d), mode, sigpipe, str(HERE.parent), str(HERE)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    def assert_whole(self, rc):
        """Never half set up: untouched (factory keys, empty file, no key file, no wallet) or a
        finished, sealed card with the wallet file it unlocks."""
        b = json.loads((self.d / "blank.json").read_text())
        factory = all(v == bytes(16).hex() for v in b["keys"].values())
        rec = self.d / f"card-{b['uid']}.auth"; rec = json.loads(rec.read_text()) if rec.exists() else None
        wallet = self.d / "w.mmm"
        untouched = factory and b["file"] == bytes(128).hex() and rec is None and not wallet.exists()
        finished = (not factory and rec is not None and (rec["state"], rec["permanent"]) == ("provisioned", True)
                    and wallet.exists() and w.mmm2_family(wallet.read_bytes()) == rec["family"])
        self.assertTrue(untouched or finished, (rc, b, rec, wallet.exists()))
        return untouched
    def test_sigterm_right_after_the_event_lands_in_the_pause(self):
        """MMM's cancel (or card timeout) crossed the card-provisioning line: it lands in the pause."""
        p = self.start("slow")
        for line in p.stderr:
            if line.startswith(b"XCOIN-EVENT card-provisioning"): p.send_signal(signal.SIGTERM); break
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, -signal.SIGTERM, err)
        self.assertTrue(self.assert_whole(p.returncode))                                # untouched, no wallet
    def test_sigterm_during_the_write_is_held_off(self):
        """A SIGTERM once the factor is on the card, once the key file says factor_written, or once
        the card is done but its wallet file is not written yet: the CLI finishes the wallet."""
        for mode in ("term-at-write", "term-at-keychange", "term-before-wallet-file"):
            with self.subTest(mode):
                p = self.start(mode)
                end = time.monotonic() + 60
                while not (self.d / "at").exists() and p.poll() is None and time.monotonic() < end: time.sleep(0.005)
                self.assertTrue((self.d / "at").exists(), p.stderr.read() if p.poll() is not None else "no write")
                p.send_signal(signal.SIGTERM); (self.d / "signalled").touch()
                out, err = p.communicate(timeout=60)
                self.assertEqual(p.returncode, 0, err)
                self.assertFalse(self.assert_whole(p.returncode))                        # finished, sealed, wallet written
                self.assertEqual(json.loads(out)["file"], str(self.d / "w.mmm"))
                self.assertIn(b"XCOIN-EVENT card-provisioning", err); self.assertIn(b"XCOIN-EVENT card-ok", err)
    def test_parent_gone_before_card_provisioning_writes_nothing(self):
        """MMM died while the blank card was awaited: the strict card-provisioning write stops the
        run before the card is touched, and no wallet file is made."""
        for sigpipe in ("python", "default"):
            with self.subTest(sigpipe=sigpipe):
                p = self.start("dead-parent", sigpipe=sigpipe)
                for line in p.stderr:
                    if line.startswith(b"XCOIN-EVENT card-wait"): break
                p.stdout.close(); p.stderr.close(); (self.d / "closed").touch()
                rc = p.wait(timeout=60)
                self.assertNotEqual(rc, 0)
                self.assertTrue(self.assert_whole(rc))
    def test_parent_gone_during_the_write_still_finishes_the_wallet(self):
        """MMM died after card-provisioning: output to it is dropped, and the card and its wallet
        file are still finished (a half set up card is worse than none)."""
        for sigpipe in ("python", "default"):
            with self.subTest(sigpipe=sigpipe):
                p = self.start("slow", sigpipe=sigpipe)
                for line in p.stderr:
                    if line.startswith(b"XCOIN-EVENT card-provisioning"): break
                p.stdout.close(); p.stderr.close()
                rc = p.wait(timeout=60)
                self.assertEqual(rc, 0)
                self.assertFalse(self.assert_whole(rc))

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Unit tests for wallet_cli.py — all offline, RPC is faked, nothing is broadcast."""

import hashlib, hmac, io, json, os, sys, tempfile, types, unittest
from unittest import mock
from contextlib import redirect_stdout
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wallet_cli as w

SEED = "ab" * 32
DEST = "tnx1z0hjuu6xulyaav5wf540aelngdm5fnz4nmu2f6j739cqnk066gqrqk0mggt"
OWN = "tnx1z6syxfhjfyp0djgp0r28c7stvp7fsrfx2zv553l8t8cv4hdrxekksxhc9cd"
SPK = "5220" + "11" * 32

def utxo(txid, vout, amount, height, tip, coinbase=False, spk=SPK):
    return {"txid": txid, "vout": vout, "amount": Decimal(amount), "scriptPubKey": spk,
            "height": height, "coinbase": coinbase, "confirmations": tip - height + 1}

_OWN = {}
def own(index=0, hrp="xpa"):
    """What the real keytool derives for SEED at `index` (two-leaf + carried forms).
    Scans are tagged by script, so CLI-flow fixtures must pay these scripts."""
    if (index, hrp) not in _OWN: _OWN[(index, hrp)] = w.derive_offline(SEED, index, hrp)
    return _OWN[(index, hrp)]

class FakeRPC:
    """Replays canned responses and records every call."""
    responses = {}
    calls = []
    def __init__(self, args): self.conf = {"fallbackfee": "0.0001"}
    def call(self, method, params=None, timeout=60):
        FakeRPC.calls.append((method, params))
        if method not in FakeRPC.responses: raise w.WalletError(f"RPC {method}: not faked")
        r = FakeRPC.responses[method]
        return r(params) if callable(r) else r

class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        os.environ.pop("XCOIN_WALLET_PASSPHRASE", None)
        self.wallet = Path(self.tmp.name) / "wallet.seed"
        self.wallet.write_text(SEED + "\n"); os.chmod(self.wallet, 0o600)
        FakeRPC.responses = {}; FakeRPC.calls = []
        self._real_rpc = w.RPC; w.RPC = FakeRPC
        self.addCleanup(lambda: setattr(w, "RPC", self._real_rpc))
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()
    def called(self, method):
        return [p for m, p in FakeRPC.calls if m == method]

class TestMoney(unittest.TestCase):
    def test_money_valid(self):
        self.assertEqual(w.money("1.5"), Decimal("1.50000000"))
        self.assertEqual(w.money(50), Decimal("50.00000000"))
    def test_money_invalid(self):
        for bad in ("abc", "", "1..2"):
            with self.assertRaises(w.WalletError): w.money(bad)
    def test_ceil_sat(self):
        self.assertEqual(w.money_ceil_sat(Decimal("0.000000011")), Decimal("0.00000002"))

class TestSizes(unittest.TestCase):
    def test_witness_constants(self):
        # two-leaf ML-DSA spend: count + pubkey + sig + leaf script + 65-byte control block
        self.assertEqual(w.WITNESS_PER_INPUT, 1 + 3 + 1952 + 3 + 3309 + 1 + 34 + 1 + 65)
        self.assertEqual(w.WITNESS_PER_INPUT, w.WITNESS_V3_TWO_LEAF)
        # the carried (single-leaf) spend differs only by the 32-byte sibling hash
        self.assertEqual(w.WITNESS_V3_CARRIED, 1 + 3 + 1952 + 3 + 3309 + 1 + 34 + 1 + 33)
        self.assertEqual(w.WITNESS_V3_TWO_LEAF - w.WITNESS_V3_CARRIED, 32)
    def test_matches_observed_signed_tx(self):
        # The real witness-v3 testnet spend of 2026-09-24 (txid 88665c29db54…), a
        # SINGLE-LEAF (carried-form) spend, was exactly 5,433 bytes / 1,429 vB for
        # 1-in/1-out; the node agreed. Base 94 bytes + marker/flag 2 + witness.
        self.assertEqual(94 + 2 + w.WITNESS_V3_CARRIED, 5433)
        self.assertEqual((94 * 4 + 2 + w.WITNESS_V3_CARRIED + 3) // 4, 1429)
        # Every input is now budgeted as a two-leaf spend: 32 witness bytes more per input.
        total, vsize = w.estimate_sizes(1, 1)
        self.assertEqual(total, 5433 + 32)
        self.assertEqual(vsize, (94 * 4 + 5339 + 32 + 3) // 4)
        self.assertEqual(vsize, 1437)
        total, vsize = w.estimate_sizes(1, 2)
        self.assertEqual(total, 5476 + 32)
        self.assertEqual(vsize, (137 * 4 + 5339 + 32 + 3) // 4)
        total, vsize = w.estimate_sizes(3, 2)
        self.assertEqual(total, 4 + 1 + 41 * 3 + 1 + 43 * 2 + 4 + 2 + 3 * w.WITNESS_V3_TWO_LEAF)
    def test_fee_scales_with_inputs(self):
        rate = Decimal("0.0001")
        self.assertGreater(w.fee_for(2, 2, rate), w.fee_for(1, 2, rate))
    def test_fee_is_satoshi_rounded_up(self):
        fee = w.fee_for(1, 2, Decimal("0.0001"))
        self.assertEqual(fee, fee.quantize(Decimal("0.00000001")))
        self.assertGreaterEqual(fee, Decimal("0.0001") * w.estimate_sizes(1, 2)[1] / 1000)

class TestClassify(unittest.TestCase):
    def test_split(self):
        tip = 35
        result = {"height": tip, "unspents": [
            utxo("aa", 0, "50", 34, tip, coinbase=True),          # 2 confs -> immature
            utxo("bb", 0, "50", 35, tip, coinbase=True),          # 1 conf  -> immature
            utxo("cc", 1, "3",  10, tip, coinbase=False),         # plain   -> mature
        ]}
        mature, immature = w.classify_utxos(result)
        self.assertEqual([u["txid"] for u in mature], ["cc"])
        self.assertEqual(sorted(u["blocks_to_maturity"] for u in immature), [998, 999])
    def test_old_coinbase_is_mature(self):
        result = {"height": 1200, "unspents": [utxo("aa", 0, "50", 100, 1200, coinbase=True)]}
        mature, immature = w.classify_utxos(result)
        self.assertEqual(len(mature), 1); self.assertEqual(immature, [])

class TestSelection(unittest.TestCase):
    RATE = Decimal("0.0001")
    def coins(self, *amounts):
        return [utxo(f"t{i}", 0, a, 10, 200) for i, a in enumerate(amounts)]
    def test_largest_first_minimizes_inputs(self):
        sel, fee, change = w.select_coins(self.coins("1", "2", "50"), Decimal("3"), feerate=self.RATE)
        self.assertEqual(len(sel), 1)
        self.assertEqual(sel[0]["amount"], Decimal("50"))
        self.assertEqual(change, Decimal("50") - Decimal("3") - fee)
    def test_multi_input_fee_growth(self):
        sel, fee, change = w.select_coins(self.coins("2", "2", "2"), Decimal("5"), feerate=self.RATE)
        self.assertEqual(len(sel), 3)
        self.assertEqual(fee, w.fee_for(3, 2, self.RATE))
        self.assertEqual(change, Decimal("6") - Decimal("5") - fee)
    def test_dust_change_folded_into_fee(self):
        fee1 = w.fee_for(1, 2, self.RATE)
        total = Decimal("5") + fee1 + Decimal("0.000001")   # leaves sub-dust change
        sel, fee, change = w.select_coins(self.coins(str(total)), Decimal("5"), feerate=self.RATE)
        self.assertEqual(change, 0)
        self.assertEqual(fee, fee1 + Decimal("0.000001"))
    def test_fixed_fee(self):
        sel, fee, change = w.select_coins(self.coins("10"), Decimal("1"), fixed_fee=Decimal("0.001"))
        self.assertEqual(fee, Decimal("0.001"))
        self.assertEqual(change, Decimal("8.999"))
    def test_insufficient(self):
        with self.assertRaisesRegex(w.WalletError, "insufficient"):
            w.select_coins(self.coins("1"), Decimal("5"), feerate=self.RATE)
    def test_exact_no_change(self):
        fee = Decimal("0.001")
        sel, got_fee, change = w.select_coins(self.coins("5.001"), Decimal("5"), fixed_fee=fee)
        self.assertEqual(change, 0); self.assertEqual(got_fee, fee)

class TestBalanceAndUtxos(Base):
    def scan_result(self):
        spk = own(1)["scriptPubKey"]
        return {"success": True, "height": 35, "total_amount": Decimal("100"),
                "unspents": [utxo("aa", 0, "50", 34, 35, coinbase=True, spk=spk),
                             utxo("bb", 0, "50", 35, 35, coinbase=True, spk=spk)]}
    def setUpRPC(self):
        FakeRPC.responses = {
            "scantxoutset": self.scan_result(),
        }
    def test_balance_reports_immature(self):
        self.setUpRPC()
        rc, out = self.run_cli("balance", "--index", "1")
        self.assertEqual(rc, 0)
        self.assertIn("Spendable:     0.00000000 XCF", out)
        self.assertIn("immature", out.lower())
        self.assertIn("100.00000000 XCF", out)
    def test_balance_json(self):
        self.setUpRPC()
        rc, out = self.run_cli("--json", "balance", "--index", "1")
        data = json.loads(out)
        self.assertEqual(data["spendable"], "0.00000000")
        self.assertEqual(data["immature"], "100.00000000")
        self.assertEqual(data["immature_utxos"], 2)
    def test_utxos_marks_immature(self):
        self.setUpRPC()
        rc, out = self.run_cli("utxos", "--index", "1")
        self.assertEqual(out.count("IMMATURE"), 2)
        self.assertIn("spendable: 0.00000000 XCF", out)
    def test_utxos_json(self):
        self.setUpRPC()
        rc, out = self.run_cli("--json", "utxos", "--index", "1")
        rows = json.loads(out)
        self.assertTrue(all(r["spendable"] is False for r in rows))
        self.assertTrue(all(r["blocks_to_maturity"] > 0 for r in rows))

class TestSend(Base):
    def setUp(self):
        super().setUp()
        # Default signing is now OFFLINE (native keytool). Fake it so send-flow
        # tests don't shell out; record the args it was called with.
        self.offline_calls = []
        def fake_offline(seed, raw, prev):
            self.offline_calls.append((seed, raw, prev)); return "aa" * 5408
        real = w.sign_offline; w.sign_offline = fake_offline
        self.addCleanup(lambda: setattr(w, "sign_offline", real))
    def setUpRPC(self, unspents, accept=True):
        # fixtures built with the default v2 SPK stand for "an output of this key":
        # re-point them at the key's two-leaf script (a scan only returns our scripts)
        for u in unspents:
            if u["scriptPubKey"] == SPK: u["scriptPubKey"] = own(0)["scriptPubKey"]
        FakeRPC.responses = {
            "scantxoutset": {"success": True, "height": 200, "unspents": unspents},
            "getblockchaininfo": {"chain": "test"},
            "validateaddress": {"isvalid": True},
            "getmempoolinfo": {"minrelaytxfee": Decimal("0.000001"), "mempoolminfee": Decimal("0.000001")},
            "estimatesmartfee": {"errors": ["no data"]},
            "createrawtransaction": "00rawtx00",
            "decoderawtransaction": {"txid": "deadbeef", "vsize": 1455},
            "testmempoolaccept": [{"allowed": accept, "reject-reason": None if accept else "bad-txns-premature-spend-of-coinbase"}],
            "sendrawtransaction": "deadbeef",
        }
    def test_dry_run_does_not_broadcast(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)])
        rc, out = self.run_cli("send", DEST, "1.0", "--yes", "--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("NOT broadcast", out)
        self.assertIn("would be accepted", out)
        self.assertEqual(self.called("sendrawtransaction"), [])
    def test_amounts_serialized_as_strings(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)])
        self.run_cli("send", DEST, "1.0", "--yes", "--dry-run")
        (inputs, outputs), = self.called("createrawtransaction")
        self.assertEqual(outputs[0][DEST], "1.00000000")
        for o in outputs:
            for v in o.values(): self.assertIsInstance(v, str)
        # default path signs OFFLINE — the seed goes to the keytool, not the node
        self.assertEqual(self.called("pqsignrawtransaction"), [])
        (seed, raw, prev), = self.offline_calls
        self.assertEqual(seed, SEED)
        self.assertEqual(prev[0]["keyindex"], 0)
        self.assertIsInstance(prev[0]["amount"], Decimal)
    def test_immature_only_fails_with_hint(self):
        self.setUpRPC([utxo("aa", 0, "50", 199, 200, coinbase=True)])
        rc, out = self.run_cli("send", DEST, "1.0", "--yes", "--dry-run")
        self.assertEqual(rc, 1)
        self.assertEqual(self.called("createrawtransaction"), [])
    def test_immature_excluded_from_selection(self):
        self.setUpRPC([utxo("aa", 0, "50", 199, 200, coinbase=True),
                       utxo("bb", 0, "50", 10, 200)])
        rc, out = self.run_cli("send", DEST, "1.0", "--yes", "--dry-run")
        self.assertEqual(rc, 0)
        (inputs, _), = self.called("createrawtransaction")
        self.assertEqual([i["txid"] for i in inputs], ["bb"])
        self.assertIn("Excluded", out)
    def test_max_fee_guard(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)])
        rc, out = self.run_cli("send", DEST, "1.0", "--fee", "0.5", "--yes", "--dry-run")
        self.assertEqual(rc, 1)
        self.assertEqual(self.called("createrawtransaction"), [])
    def test_broadcast_blocked_when_mempool_rejects(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)], accept=False)
        rc, out = self.run_cli("send", DEST, "1.0", "--yes")
        self.assertEqual(rc, 1)
        self.assertEqual(self.called("sendrawtransaction"), [])
    def test_real_send_calls_broadcast_when_accepted(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)])
        rc, out = self.run_cli("send", DEST, "1.0", "--yes")
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.called("sendrawtransaction")), 1)
        self.assertIn("deadbeef", out)
    def test_json_send_requires_yes(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)])
        rc, out = self.run_cli("--json", "send", DEST, "1.0", "--dry-run")
        self.assertEqual(rc, 1)
    def test_json_dry_run_output(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)])
        rc, out = self.run_cli("--json", "send", DEST, "1.0", "--yes", "--dry-run")
        data = json.loads(out)
        self.assertEqual(data["txid"], "deadbeef")
        self.assertFalse(data["broadcast"])
        self.assertTrue(data["mempool_accept"])
    def test_auto_fee_uses_fallbackfee(self):
        self.setUpRPC([utxo("aa", 0, "50", 10, 200)])
        rc, out = self.run_cli("send", DEST, "1.0", "--yes", "--dry-run")
        self.assertIn("fallbackfee", out)
        expected = w.fee_for(1, 2, Decimal("0.0001"))
        self.assertIn(f"{expected:f} XCF", out)

class TestHistory(Base):
    def setUpRPC(self):
        # History matches outputs by the DERIVED script, so the fixture must use
        # what the real keytool derives today (witness v3), not a pinned v2 hex —
        # that pin is exactly how these tests went stale when the chain moved.
        spk = w.derive_offline(SEED, 1)["scriptPubKey"]
        carried = w.derive_offline(SEED, 1)["carried_scriptPubKey"]
        blocks = {
            "h10": {"time": 1788000000, "tx": [
                {"txid": "cb1", "vin": [{"coinbase": "00"}],
                 "vout": [{"n": 0, "value": Decimal("50"), "scriptPubKey": {"hex": spk}}]}]},
            "h11": {"time": 1788000600, "tx": [
                {"txid": "sp1", "vin": [{"txid": "cb1", "vout": 0}],
                 "vout": [{"n": 0, "value": Decimal("49"), "scriptPubKey": {"hex": "5220" + "22" * 32}},
                          {"n": 1, "value": Decimal("0.9"), "scriptPubKey": {"hex": spk}}]}]},
            "h12": {"time": 1788001200, "tx": [          # a payment to the carried single-leaf form
                {"txid": "cr1", "vin": [{"txid": "ff" * 32, "vout": 0}],
                 "vout": [{"n": 0, "value": Decimal("2"), "scriptPubKey": {"hex": carried}}]}]},
        }
        FakeRPC.responses = {
            "getblockcount": 12,
            "getblockhash": lambda p: f"h{p[0]}",
            "getblock": lambda p: blocks.get(p[0], {"time": 0, "tx": []}),
            "getrawmempool": ["mp1"],
            "getrawtransaction": lambda p: {"txid": "mp1", "vin": [{"txid": "sp1", "vout": 1}],
                                            "vout": [{"n": 0, "value": Decimal("0.5"),
                                                      "scriptPubKey": {"hex": "5220" + "33" * 32}}]},
        }
    def test_history_events(self):
        self.setUpRPC()
        rc, out = self.run_cli("--json", "history", "--index", "1")
        data = json.loads(out)
        nets = {e["txid"]: e["net"] for e in data["events"]}
        self.assertEqual(nets["cb1"], "50.00000000")
        self.assertEqual(nets["sp1"], "-49.10000000")   # spent 50, got 0.9 change
        self.assertEqual(nets["mp1"], "-0.90000000")    # unconfirmed spend of the change
        self.assertEqual(nets["cr1"], "2.00000000")     # the carried form is this key's too
        self.assertEqual(data["carried_address"], w.derive_offline(SEED, 1)["carried_address"])
        cb = next(e for e in data["events"] if e["txid"] == "cb1")
        self.assertTrue(cb["coinbase"])
    def test_history_human(self):
        self.setUpRPC()
        rc, out = self.run_cli("history", "--index", "1")
        self.assertIn("coinbase", out)
        self.assertIn("immature", out)
        self.assertIn("mempool", out)

class TestSeedFiles(Base):
    def test_new_refuses_overwrite(self):
        rc, out = self.run_cli("new", "--offline")
        self.assertEqual(rc, 1)
    def test_new_creates_encrypted_with_0600(self):
        target = Path(self.tmp.name) / "fresh.mmm"
        rc, out = self.run_cli_target(target, "new", "--offline")
        self.assertEqual(rc, 0)
        self.assertTrue(target.exists())
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
        self.assertTrue(target.read_bytes().startswith(w.MMM_MAGIC))
        self.assertEqual(len(w.read_seed(target)), 64)
    def test_restore_rejects_bad_seed(self):
        target = Path(self.tmp.name) / "r.mmm"
        rc, _ = self.run_cli_target(target, "restore", "zz" * 32)
        self.assertEqual(rc, 1); self.assertFalse(target.exists())
    def test_restore_writes_mmm_format(self):
        target = Path(self.tmp.name) / "r.mmm"
        rc, _ = self.run_cli_target(target, "restore", "cd" * 32)
        self.assertEqual(rc, 0)
        self.assertTrue(target.read_bytes().startswith(w.MMM_MAGIC))
        self.assertEqual(w.read_seed(target), "cd" * 32)
    def test_backup_copies(self):
        dst = Path(self.tmp.name) / "backups"
        dst.mkdir()
        rc, out = self.run_cli("backup", str(dst))
        self.assertEqual(rc, 0)
        copies = list(dst.glob("*.seed"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_text(), self.wallet.read_text())
        self.assertTrue(self.wallet.exists())
    def test_reset_requires_yes(self):
        rc, _ = self.run_cli("reset", "--backup", self.tmp.name)
        self.assertEqual(rc, 1); self.assertTrue(self.wallet.exists())
    def test_reset_moves_never_deletes(self):
        dst = Path(self.tmp.name) / "moved.seed"
        rc, _ = self.run_cli("reset", "--backup", str(dst), "--yes")
        self.assertEqual(rc, 0)
        self.assertFalse(self.wallet.exists())
        self.assertEqual(dst.read_text().strip(), SEED)
    def test_read_seed_rejects_garbage(self):
        bad = Path(self.tmp.name) / "bad.seed"; bad.write_text("nothex")
        with self.assertRaises(w.WalletError): w.read_seed(bad)
    def run_cli_target(self, target, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(target), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()

class TestSeedReveal(Base):
    def setUp(self):
        super().setUp()
        self.copied, self.scheduled, self.cleared = [], [], []
        self.clip = ""
        for name, fn in (("clipboard_copy", lambda t: self.copied.append(t)),
                         ("clipboard_paste", lambda: self.clip),
                         ("clipboard_clear", lambda: self.cleared.append(True)),
                         ("schedule_clipboard_clear", lambda s, t: self.scheduled.append(s))):
            real = getattr(w, name); setattr(w, name, fn)
            self.addCleanup(setattr, w, name, real)
    def test_seed_refuses_non_interactive(self):
        rc, out = self.run_cli("seed")
        self.assertEqual(rc, 1); self.assertNotIn(SEED, out)
    def test_seed_yes_prints(self):
        rc, out = self.run_cli("seed", "--yes")
        self.assertEqual(rc, 0); self.assertIn(SEED, out)
    def test_seed_json_requires_yes(self):
        rc, out = self.run_cli("--json", "seed")
        self.assertEqual(rc, 1); self.assertNotIn(SEED, out)
    def test_seed_json_yes(self):
        rc, out = self.run_cli("--json", "seed", "--yes")
        self.assertEqual(json.loads(out)["seed"], SEED)
    def test_seed_copy(self):
        rc, out = self.run_cli("seed", "--copy", "--yes")
        self.assertEqual(rc, 0)
        self.assertEqual(self.copied, [SEED])
        self.assertEqual(self.scheduled, [60])
        self.assertNotIn(SEED, out)          # --copy never prints the seed
    def test_seed_copy_no_timeout(self):
        rc, out = self.run_cli("seed", "--copy", "--timeout", "0", "--yes")
        self.assertEqual(self.scheduled, [])
        self.assertIn("NOT auto-clear", out)
    def test_restore_paste(self):
        self.clip = "  " + "cd" * 32 + "\n"
        target = Path(self.tmp.name) / "p.seed"
        rc, out = self.run_cli_target(target, "restore", "--paste")
        self.assertEqual(rc, 0)
        self.assertEqual(w.read_seed(target), "cd" * 32)
        self.assertEqual(self.cleared, [True])   # clipboard cleared after import
    def test_restore_paste_garbage(self):
        self.clip = "not a seed"
        target = Path(self.tmp.name) / "p.seed"
        rc, _ = self.run_cli_target(target, "restore", "--paste")
        self.assertEqual(rc, 1); self.assertFalse(target.exists())
    def test_restore_from_file(self):
        src = Path(self.tmp.name) / "transfer.seed"; src.write_text("ef" * 32 + "\n")
        target = Path(self.tmp.name) / "f.seed"
        rc, _ = self.run_cli_target(target, "restore", "--from-file", str(src))
        self.assertEqual(rc, 0)
        self.assertEqual(w.read_seed(target), "ef" * 32)
    def test_restore_one_source_only(self):
        target = Path(self.tmp.name) / "x.seed"
        rc, _ = self.run_cli_target(target, "restore", "cd" * 32, "--paste")
        self.assertEqual(rc, 1); self.assertFalse(target.exists())
    def run_cli_target(self, target, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(target), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()

class TestMmmFormat(Base):
    def test_roundtrip_no_passphrase(self):
        blob = w.mmm_encode(SEED, "")
        self.assertTrue(blob.startswith(w.MMM_MAGIC))
        self.assertNotIn(bytes.fromhex(SEED), blob)      # seed bytes never stored raw
        self.assertEqual(w.mmm_decode(blob, ""), SEED)
    def test_roundtrip_with_passphrase(self):
        blob = w.mmm_encode(SEED, "hunter2")
        self.assertEqual(w.mmm_decode(blob, "hunter2"), SEED)
        with self.assertRaisesRegex(w.WalletError, "wrong passphrase"):
            w.mmm_decode(blob, "wrong")
    def test_tamper_detected(self):
        blob = bytearray(w.mmm_encode(SEED, ""))
        blob[45] ^= 0x01                                  # flip a ciphertext bit
        with self.assertRaises(w.WalletError):
            w.mmm_decode(bytes(blob), "")
    def test_truncated_rejected(self):
        with self.assertRaises(w.WalletError):
            w.mmm_decode(w.MMM_MAGIC + b"short", "")
    def test_read_seed_uses_passphrase_from_fd(self):
        target = Path(self.tmp.name) / "locked.mmm"
        target.write_bytes(w.mmm_encode(SEED, "pw123"))
        r, wfd = os.pipe(); os.write(wfd, b"pw123\n"); os.close(wfd)
        w.read_passphrase_fd(r)
        self.addCleanup(setattr, w, "PASSPHRASE_FROM_FD", None)
        self.assertEqual(w.read_seed(target), SEED)
    def test_environment_passphrase_is_refused(self):
        os.environ["XCOIN_WALLET_PASSPHRASE"] = "pw123"
        self.addCleanup(os.environ.pop, "XCOIN_WALLET_PASSPHRASE", None)
        err = io.StringIO()
        from contextlib import redirect_stderr
        with redirect_stderr(err):
            rc = w.main(["--file", str(Path(self.tmp.name) / "x.mmm"), "address"])
        self.assertEqual(rc, 2)
        self.assertIn("not accepted", err.getvalue())
    def test_read_seed_locked_non_interactive_fails(self):
        target = Path(self.tmp.name) / "locked.mmm"
        target.write_bytes(w.mmm_encode(SEED, "pw123"))
        with self.assertRaisesRegex(w.WalletError, "passphrase"):
            w.read_seed(target)
    def passphrase_fd(self, pw):
        r, wfd = os.pipe(); os.write(wfd, pw.encode() + b"\n"); os.close(wfd)
        self.addCleanup(setattr, w, "PASSPHRASE_FROM_FD", None)
        return ["--passphrase-fd", str(r)]
    def test_encrypt_migrates_legacy(self):
        rc, out = self.run_cli(*self.passphrase_fd("newpw"), "encrypt")
        self.assertEqual(rc, 0)
        target = self.wallet.with_suffix(".mmm")
        moved = self.wallet.with_name(self.wallet.name + ".plaintext-backup")
        self.assertTrue(target.read_bytes().startswith(w.MMM_MAGIC))
        self.assertFalse(self.wallet.exists())            # moved, never deleted
        self.assertEqual(moved.read_text().strip(), SEED)
        self.assertEqual(w.read_seed(target), SEED)
    def test_encrypt_rekeys_in_place(self):
        target = Path(self.tmp.name) / "w.mmm"
        target.write_bytes(w.mmm_encode(SEED, "old"))
        # read unlocks with "old" (over the pipe), new_passphrase re-keys to "old" too — then
        # verify a rekey to a different passphrase via direct calls:
        rc, _ = self.run_cli_target(target, *self.passphrase_fd("old"), "encrypt")
        self.assertEqual(rc, 0)
        self.assertTrue(target.read_bytes().startswith(w.MMM_MAGIC))
        self.assertEqual(w.read_seed(target), SEED)
    def run_cli_target(self, target, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(target), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()

class TestWriteSeedAtomic(unittest.TestCase):
    """write_seed: the KDF runs before disk, the wallet is complete or absent, never replaced."""
    NO_SCRYPT = AttributeError("module 'hashlib' has no attribute 'scrypt'")
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name); self.target = self.dir / "wallet.mmm"
    def listing(self): return sorted(p.name for p in self.dir.iterdir())
    def test_writes_complete_0600_wallet_leaving_no_temp(self):
        w.write_seed(self.target, SEED, "pw")
        self.assertEqual(self.listing(), ["wallet.mmm"])
        st = os.stat(self.target)
        self.assertEqual((st.st_mode & 0o777, st.st_nlink), (0o600, 1))
        self.assertEqual(w.mmm_decode(self.target.read_bytes(), "pw"), SEED)
    def test_encode_failure_creates_nothing_and_retry_works(self):
        # a Python without hashlib.scrypt, or SIGTERM during the KDF
        with mock.patch.object(w, "mmm_encode", side_effect=self.NO_SCRYPT):
            with self.assertRaises(AttributeError): w.write_seed(self.target, SEED)
        self.assertEqual(self.listing(), [])
        w.write_seed(self.target, SEED)
        self.assertEqual(w.read_seed(self.target), SEED)
    def test_write_failure_leaves_no_file(self):
        with mock.patch.object(w.os, "fsync", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError): w.write_seed(self.target, SEED)
        self.assertEqual(self.listing(), [])
    def test_existing_wallet_is_never_replaced(self):
        self.target.write_bytes(b"precious"); os.chmod(self.target, 0o600)
        with self.assertRaises(FileExistsError): w.write_seed(self.target, SEED)
        self.assertEqual(self.target.read_bytes(), b"precious")
        self.assertEqual(self.listing(), ["wallet.mmm"])
    def test_no_hard_links_falls_back_to_exclusive_create(self):
        with mock.patch.object(w.os, "link", side_effect=OSError(45, "Operation not supported")):
            w.write_seed(self.target, SEED)
            self.assertEqual(self.listing(), ["wallet.mmm"])
            self.assertEqual(os.stat(self.target).st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): w.write_seed(self.target, "cd" * 32)
            with mock.patch.object(w.os, "fsync", side_effect=OSError(28, "No space left on device")):
                with self.assertRaises(OSError): w.write_seed(self.dir / "other.mmm", SEED)
        self.assertEqual(self.listing(), ["wallet.mmm"])
        self.assertEqual(w.read_seed(self.target), SEED)
    def test_cli_new_after_failed_encode_is_retryable(self):
        argv = ["--file", str(self.target), "--config", "/nonexistent", "new", "--offline"]
        with mock.patch.object(w, "mmm_encode", side_effect=self.NO_SCRYPT), redirect_stdout(io.StringIO()):
            with self.assertRaises(AttributeError): w.main(argv)
        self.assertEqual(self.listing(), [])
        with redirect_stdout(io.StringIO()): self.assertEqual(w.main(argv), 0)
        self.assertEqual(self.listing(), ["wallet.mmm"])

class TestConf(unittest.TestCase):
    def test_parse_conf_ignores_sections_and_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write("testnet=1\n# comment\n[test]\nrpcport=19332\nrpcuser=u\n")
            path = f.name
        conf = w.parse_conf(path)
        os.unlink(path)
        self.assertEqual(conf["rpcport"], "19332")
        self.assertEqual(conf["rpcuser"], "u")
        self.assertNotIn("[test]", conf)

if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestSignMessage(unittest.TestCase):
    """`signmessage` signs a one-line message with the key at --index through the
    native keytool (FIPS 204 ML-DSA-65). NerdMiner login depends on the JSON shape:
    address, pubkey, sig, message_hex. The signer is named by its forum identity
    (xid1…) by default; --as address names the witness v3 payment address. Runs only
    when the keytool is built."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.wallet = Path(self.tmp.name) / "wallet.seed"; self.wallet.write_text(SEED + "\n")
        if not w.keytool_path(): self.skipTest("native keytool not built")
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()
    def test_template_names_the_signer_and_verifies(self):
        rc, out = self.run_cli("signmessage", "--template", "MineDifferent login v1 | id=abc | address={address} | exp=1", "--index", "101")
        self.assertEqual(rc, 0)
        d = json.loads(out.strip().splitlines()[-1])
        self.assertEqual(d["index"], 101)
        info = w.derive_offline(SEED, 101)
        # signs AS THE IDENTITY: {address} and the "address" field are the xid1… handle
        self.assertEqual(d["address"], info["identity"])
        self.assertTrue(d["address"].startswith("xid1"))
        self.assertEqual(d["identity"], info["identity"])
        self.assertEqual(d["witness_address"], info["address"])
        self.assertTrue(d["witness_address"].startswith("xpa1r"))
        msg = bytes.fromhex(d["message_hex"]).decode()
        self.assertEqual(msg, f"MineDifferent login v1 | id=abc | address={info['identity']} | exp=1")
        self.assertEqual(len(bytes.fromhex(d["pubkey"])), 1952)
        self.assertEqual(len(bytes.fromhex(d["sig"])), 3309)
        # the keytool's own verifier agrees (the forum verifies the same FIPS 204 signature)
        import subprocess
        v = subprocess.run([str(w.keytool_path()), "_verify"], input=f"{d['pubkey']}\n{d['message_hex']}\n{d['sig']}\n".encode(), capture_output=True)
        self.assertEqual(v.stdout.decode().strip(), "OK")
        bad = subprocess.run([str(w.keytool_path()), "_verify"], input=f"{d['pubkey']}\n{d['message_hex']}ff\n{d['sig']}\n".encode(), capture_output=True)
        self.assertEqual(bad.stdout.decode().strip(), "FAIL")
    def test_locked_wallet_signs_with_passphrase_over_a_pipe(self):
        locked = Path(self.tmp.name) / "locked.mmm"; locked.write_bytes(w.mmm_encode(SEED, "pw123"))
        r, wfd = os.pipe(); os.write(wfd, b"pw123\n"); os.close(wfd)
        self.addCleanup(setattr, w, "PASSPHRASE_FROM_FD", None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(locked), "--config", "/nonexistent", "--passphrase-fd", str(r), "signmessage", "--message", "MineDifferent login v1 | challenge: test-vector-0001 | a message well over sixty-five bytes", "--index", "3"])
        self.assertEqual(rc, 0)
        d = json.loads(buf.getvalue().strip().splitlines()[-1])
        self.assertEqual(bytes.fromhex(d["message_hex"]), b"MineDifferent login v1 | challenge: test-vector-0001 | a message well over sixty-five bytes")
        info = w.derive_offline(SEED, 3)
        self.assertEqual(d["address"], info["identity"])
        self.assertEqual(d["witness_address"], info["address"])
    def test_passphrase_fd_after_the_subcommand_is_accepted(self):
        # An older NerdMiner appends --passphrase-fd after 'signmessage'; the wallet lifts it out.
        locked = Path(self.tmp.name) / "locked2.mmm"; locked.write_bytes(w.mmm_encode(SEED, "pw123"))
        r, wfd = os.pipe(); os.write(wfd, b"pw123\n"); os.close(wfd)
        self.addCleanup(setattr, w, "PASSPHRASE_FROM_FD", None)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(locked), "--config", "/nonexistent", "signmessage", "--message", "MineDifferent login v1 | challenge: test-vector-0001 | a message well over sixty-five bytes", "--index", "3", "--passphrase-fd", str(r)])
        self.assertEqual(rc, 0)
        self.assertEqual(bytes.fromhex(json.loads(buf.getvalue().strip().splitlines()[-1])["message_hex"]), b"MineDifferent login v1 | challenge: test-vector-0001 | a message well over sixty-five bytes")
    def test_multiline_forum_challenge_signs(self):
        # NerdMiner's template is four lines: prefix, challenge, address, expires.
        rc, out = self.run_cli("signmessage", "--template", "MineDifferent login v1\nchallenge: abc\naddress: {address}\nexpires: 1", "--index", "101")
        self.assertEqual(rc, 0)
        d = json.loads(out.strip().splitlines()[-1])
        msg = bytes.fromhex(d["message_hex"]).decode()
        self.assertEqual(msg.splitlines()[2], "address: " + d["address"])
        self.assertTrue(msg.splitlines()[2].startswith("address: xid1"))
        self.assertEqual(len(msg.splitlines()), 4)
    def test_as_address_names_the_payment_form(self):
        # --as address: {address} and the "address" field are the witness v3
        # payment address; identity is still reported.
        rc, out = self.run_cli("signmessage", "--template", "MineDifferent login v1 | id=abc | address={address} | exp=1", "--index", "101", "--as", "address")
        self.assertEqual(rc, 0)
        d = json.loads(out.strip().splitlines()[-1])
        info = w.derive_offline(SEED, 101)
        self.assertEqual(d["address"], info["address"])
        self.assertTrue(d["address"].startswith("xpa1r"))
        self.assertEqual(d["witness_address"], d["address"])
        self.assertEqual(d["identity"], info["identity"])
        msg = bytes.fromhex(d["message_hex"]).decode()
        self.assertEqual(msg, f"MineDifferent login v1 | id=abc | address={info['address']} | exp=1")
        self.assertNotIn("xid1", msg)
        import subprocess
        v = subprocess.run([str(w.keytool_path()), "_verify"], input=f"{d['pubkey']}\n{d['message_hex']}\n{d['sig']}\n".encode(), capture_output=True)
        self.assertEqual(v.stdout.decode().strip(), "OK")
    def test_as_rejects_other_values(self):
        with self.assertRaises(SystemExit):
            self.run_cli("signmessage", "--message", "x", "--as", "pubkey")


# --- tiny bech32m (BIP-350) decoder, test-only: the CLI never decodes, the keytool encodes
B32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _b32_polymod(values):
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1: chk ^= gen[i]
    return chk
def _b32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
def _convertbits(data, frombits, tobits, pad):
    acc = bits = 0; ret = []; maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v; bits += frombits
        while bits >= tobits:
            bits -= tobits; ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("bad padding")
    return ret
def bech32m_decode(s):
    """→ (hrp, data5) after a strict bech32m checksum check; lowercase only."""
    if s != s.lower() or not (8 <= len(s) <= 90): raise ValueError("bad case or length")
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s): raise ValueError("no separator")
    hrp, data = s[:pos], [B32_CHARSET.index(c) for c in s[pos + 1:]]
    if _b32_polymod(_b32_hrp_expand(hrp) + data) != 0x2bc830a3: raise ValueError("bad bech32m checksum")
    return hrp, data[:-6]
def decode_identity(s):
    """The forum identity rule: HRP xid, bech32m, NO witness version, exactly 32 bytes."""
    hrp, data = bech32m_decode(s)
    if hrp != "xid": raise ValueError("not an xid")
    prog = bytes(_convertbits(data, 5, 8, False))
    if len(prog) != 32: raise ValueError("identity program must be 32 bytes")
    return prog
def _tagged(tag, msg):
    th = hashlib.sha256(tag).digest()
    return hashlib.sha256(th + th + msg).digest()
def _compact(n):
    return bytes([n]) if n < 0xfd else b"\xfd" + n.to_bytes(2, "little")
def v3_leaf_hash(version, script):
    """TaggedHash("XCoinLeaf", version || compact(len) || script), independent of the keytool."""
    return _tagged(b"XCoinLeaf", bytes([version]) + _compact(len(script)) + script)
def v3_branch_hash(a, b):
    return _tagged(b"XCoinBranch", (a + b) if a < b else (b + a))
def decode_witness(s):
    """A node's rule: version byte first, then the program (BIP-350 padding rules)."""
    hrp, data = bech32m_decode(s)
    return hrp, data[0], bytes(_convertbits(data[1:], 5, 8, False))


class TestIdentity(unittest.TestCase):
    """The forum identity xid1…: bech32m over SHA-256(pubkey) under HRP "xid" with no
    witness version byte, 62 chars. Every command that names a key agrees on it and
    it is not decodable as an address. Runs only when the keytool is built."""
    # index 101 of the test seed: the reference vector shared with the keytool and the forum's JS
    XID_101 = "xid1wexam97j7pmgl45w4xy5jnv8j7jydua38uk4f4pcn6rje23783wq5u0gjr"
    # the two-leaf address {ML-DSA 0xc0, SLH-DSA 0xc2}: equal to dex-wallet-cli's `derive --index 101`
    XPA1R_101 = "xpa1rc7y8qn4325gp2leq9kr8ywq749fk0kppa0dyyzddxs44ldfhzh9qkndd5r"
    V3PROG_101 = "c788704eb15510157f202d8672381ea95367d821ebda4209ad342b5fb53715ca"
    # the carried single-leaf form: what this tool printed as the address before the two-leaf upgrade
    CARRIED_101 = "xpa1rvmwnky8e5nc7zpdndydws88npq400j4a9cxe7nyh35fw9nekpk8snyc8zr"
    # carried program = single-leaf Merkle root of PUSH32(SHA-256(pk)) OP_CHECKSIG
    CARRIED_PROG_101 = "66dd3b10f9a4f1e105b3691ae81cf3082af7cabd2e0d9f4c978d12e2cf360d8f"
    PROG_101 = "764ddd97d2f0768fd68ea989494d8797a446f3b13f2d54d4389e872caa3e3c5c"
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.wallet = Path(self.tmp.name) / "wallet.seed"; self.wallet.write_text(SEED + "\n")
        if not w.keytool_path(): self.skipTest("native keytool not built")
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", *argv])
        return rc, buf.getvalue()
    def signed(self, index):
        rc, out = self.run_cli("signmessage", "--message", "MineDifferent login v1 | challenge: test-vector-0001 | a message well over sixty-five bytes", "--index", str(index))
        self.assertEqual(rc, 0)
        return json.loads(out.strip().splitlines()[-1])
    def test_xid_form_and_round_trip(self):
        import hashlib
        info = w.derive_offline(SEED, 101)
        xid = info["identity"]
        self.assertEqual(len(xid), 62)                      # "xid1" + 52 data + 6 checksum
        self.assertTrue(xid.startswith("xid1"))
        self.assertEqual(xid, xid.lower())
        d = self.signed(101)
        pubkey = bytes.fromhex(d["pubkey"])
        self.assertEqual(len(pubkey), 1952)
        prog = decode_identity(xid)                          # strict: HRP xid, bech32m, 32 bytes, no version
        self.assertEqual(prog, hashlib.sha256(pubkey).digest())
        self.assertEqual(prog.hex(), info["pubkey_sha256"])
        # the address is the two-leaf tree over the same key's ML-DSA leaf
        hrp, ver, addr_prog = decode_witness(info["address"])
        self.assertEqual((hrp, ver), ("xpa", 3))
        self.assertEqual(addr_prog.hex(), info["program"])
        self.assertEqual(info["scriptPubKey"], "5320" + info["program"])
        # the carried form commits to the key directly: its program is the
        # single-leaf Merkle root over PUSH32(SHA-256(pubkey)) OP_CHECKSIG
        hrp, ver, carried_prog = decode_witness(info["carried_address"])
        self.assertEqual((hrp, ver), ("xpa", 3))
        self.assertEqual(carried_prog.hex(), info["carried_program"])
        self.assertEqual(info["carried_scriptPubKey"], "5320" + info["carried_program"])
        self.assertEqual(carried_prog, v3_leaf_hash(0xc0, b"\x20" + hashlib.sha256(pubkey).digest() + b"\xac"))
        self.assertNotEqual(info["program"], info["carried_program"])
    def test_reference_vector(self):
        info = w.derive_offline(SEED, 101)
        self.assertEqual(info["identity"], self.XID_101)
        self.assertEqual(info["address"], self.XPA1R_101)
        self.assertEqual(info["program"], self.V3PROG_101)
        self.assertEqual(info["scriptPubKey"], "5320" + self.V3PROG_101)
        self.assertEqual(info["carried_address"], self.CARRIED_101)
        self.assertEqual(info["carried_program"], self.CARRIED_PROG_101)
        self.assertEqual(info["carried_scriptPubKey"], "5320" + self.CARRIED_PROG_101)
        self.assertEqual(info["pubkey_sha256"], self.PROG_101)
        self.assertEqual(decode_identity(self.XID_101).hex(), self.PROG_101)
        # the identity is unchanged by the two-leaf upgrade; txa carries the same programs
        t = w.derive_offline(SEED, 101, "txa")
        self.assertEqual((t["identity"], t["program"], t["carried_program"]), (self.XID_101, self.V3PROG_101, self.CARRIED_PROG_101))
        self.assertTrue(t["address"].startswith("txa1r")); self.assertTrue(t["carried_address"].startswith("txa1r"))
    def test_address_carried_flag_and_json(self):
        rc, out = self.run_cli("address", "--index", "101")
        self.assertEqual(out.strip(), self.XPA1R_101)
        rc, out = self.run_cli("address", "--index", "101", "--carried")
        self.assertEqual(rc, 0); self.assertEqual(out.strip(), self.CARRIED_101)
        rc, out = self.run_cli("receive", "--index", "101", "--carried", "--verbose")
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], self.CARRIED_101)
        self.assertIn("scriptPubKey: 5320" + self.CARRIED_PROG_101, lines)
        self.assertIn("address: " + self.XPA1R_101, lines)
        rc, out = self.run_cli("address", "--index", "101", "--verbose")
        self.assertIn("carried address (single-leaf, same key): " + self.CARRIED_101, out.splitlines())
        rc, out = self.run_cli("--json", "address", "--index", "101")
        j = json.loads(out)
        self.assertEqual((j["address"], j["carried_address"], j["identity"]), (self.XPA1R_101, self.CARRIED_101, self.XID_101))
        self.assertEqual(j["scriptPubKey"], "5320" + self.V3PROG_101)
        self.assertEqual(j["carried_scriptPubKey"], "5320" + self.CARRIED_PROG_101)
    def test_same_key_same_xid_everywhere(self):
        d = self.signed(101)
        info = w.derive_offline(SEED, 101)                   # the keytool's _address
        self.assertEqual(d["identity"], info["identity"])    # the keytool's _signmsg
        self.assertEqual(d["address"], info["identity"])
        for argv in (("identity", "--index", "101"), ("address", "--identity", "--index", "101"), ("receive", "--identity", "--index", "101")):
            rc, out = self.run_cli(*argv)
            self.assertEqual(rc, 0); self.assertEqual(out.strip(), info["identity"])
        rc, out = self.run_cli("--json", "identity", "--index", "101")
        self.assertEqual(rc, 0)
        j = json.loads(out)
        self.assertEqual((j["identity"], j["address"], j["index"]), (info["identity"], info["address"], 101))
        rc, out = self.run_cli("--json", "address", "--index", "101")
        self.assertEqual(json.loads(out)["identity"], info["identity"])
        # a different key has a different identity
        self.assertNotEqual(w.derive_offline(SEED, 0)["identity"], info["identity"])
    def test_identity_verbose_shows_the_address(self):
        rc, out = self.run_cli("identity", "--index", "101", "--verbose")
        self.assertEqual(rc, 0)
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], self.XID_101)
        self.assertIn("index: 101", lines)
        self.assertIn("address: " + self.XPA1R_101, lines)
    def test_addresses_list_both_with_identity(self):
        rc, out = self.run_cli("addresses", "--start", "100", "--count", "2", "--identity")
        self.assertEqual(rc, 0)
        rows = [l.split() for l in out.strip().splitlines()]
        self.assertEqual([r[0] for r in rows], ["100", "101"])
        self.assertEqual(rows[1][1:], [self.XPA1R_101, self.XID_101])
        for r in rows:
            self.assertTrue(r[1].startswith("xpa1r")); self.assertTrue(r[2].startswith("xid1"))
        rc, out = self.run_cli("addresses", "--start", "101", "--count", "1")
        self.assertEqual(out.split(), ["101", self.XPA1R_101])       # default: one two-leaf address per line
        rc, out = self.run_cli("addresses", "--start", "101", "--count", "1", "--carried")
        self.assertEqual(out.split(), ["101", self.XPA1R_101, self.CARRIED_101])
        rc, out = self.run_cli("--json", "addresses", "--start", "101", "--count", "1", "--identity")
        self.assertEqual(json.loads(out), [{"index": 101, "address": self.XPA1R_101, "carried_address": self.CARRIED_101, "identity": self.XID_101}])
        rc, out = self.run_cli("--json", "addresses", "--start", "101", "--count", "1")
        self.assertEqual(json.loads(out), [{"index": 101, "address": self.XPA1R_101, "carried_address": self.CARRIED_101}])
    def test_identity_is_not_an_address(self):
        # No chain HRP, and read as <version><program> the 52 data chars leave 7 stray
        # bits (BIP-350 forbids that), so an address parser refuses the string outright.
        xid = w.derive_offline(SEED, 101)["identity"]
        hrp, data = bech32m_decode(xid)
        self.assertEqual(hrp, "xid"); self.assertNotIn(hrp, ("xpa", "txa", "nxrt"))
        with self.assertRaises(ValueError): decode_witness(xid)
        # and a witness address is not an identity
        with self.assertRaises(ValueError): decode_identity(w.derive_offline(SEED, 101)["address"])
        # a flipped character fails the checksum
        bad = xid[:-1] + ("p" if xid[-1] != "p" else "q")
        with self.assertRaises(ValueError): decode_identity(bad)
    def test_derive_offline_requires_the_identity(self):
        import subprocess
        real = subprocess.run
        class Old:
            returncode = 0; stderr = b""
            stdout = json.dumps({"address": self.XPA1R_101, "scriptPubKey": "5220" + self.PROG_101, "index": 101}).encode()
        subprocess.run = lambda *a, **k: Old()
        self.addCleanup(setattr, subprocess, "run", real)
        with self.assertRaises(w.WalletError) as cm: w.derive_offline(SEED, 101)
        self.assertIn("rebuild", str(cm.exception))
    def test_derive_offline_refuses_a_single_leaf_keytool(self):
        # A keytool built before the two-leaf upgrade answers with the single-leaf tree
        # as "address" and no carried_* fields; it must never be mistaken for the new one.
        import subprocess
        real = subprocess.run
        class Old:
            returncode = 0; stderr = b""
            stdout = json.dumps({"address": self.CARRIED_101, "identity": self.XID_101, "scriptPubKey": "5320" + self.CARRIED_PROG_101,
                                 "program": self.CARRIED_PROG_101, "pubkey_sha256": self.PROG_101, "index": 101}).encode()
        subprocess.run = lambda *a, **k: Old()
        self.addCleanup(setattr, subprocess, "run", real)
        with self.assertRaises(w.WalletError) as cm: w.derive_offline(SEED, 101)
        self.assertIn("predates two-leaf", str(cm.exception))


class TestV3Vectors(unittest.TestCase):
    """The native keytool must replay the node's golden vectors (leaf/branch/
    control/tag) and the sighash regression lock validated by the mined spends
    of 2026-09-24. Runs only when the keytool is built."""
    def test_vectors_replay(self):
        tool = w.keytool_path()
        if not tool: self.skipTest("native keytool not built")
        import subprocess
        r = subprocess.run([str(tool), "_v3vectors"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("FAIL", r.stdout)
        self.assertIn("sighash-in1", r.stdout)


# --- dex-wallet-era ENCODERS, test-local (ported from dex-wallet-cli/wallet_cli.py's
# _seal/wallet_payload/mmm4_encode/mmm5_encode) so v4/v5 fixtures need no dex checkout
# and no hardware. The SLH derivation is copied too, locking the constants independently
# of wallet_cli's own slh_seed().
def _dex_scrypt(secret, salt):
    dk = hashlib.scrypt(secret, salt=salt, n=1 << 15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=64)
    return dk[:32], dk[32:]

def _seal(secret, prefix, payload):
    salt, nonce = os.urandom(16), os.urandom(16)
    enc_key, mac_key = _dex_scrypt(secret, salt)
    stream = hashlib.shake_256(enc_key + nonce).digest(len(payload))
    body = prefix + salt + nonce + bytes(a ^ b for a, b in zip(payload, stream))
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()

def _slh_seed(seed_hex, index):
    master = hashlib.shake_256(bytes.fromhex(seed_hex) + b"NEX-PQ-MASTER").digest(32)
    child = hashlib.shake_256(master + index.to_bytes(4, "little") + b"NEX-PQ-CHILD").digest(32)
    return hashlib.shake_256(child + b"xcoin/hd/slh-dsa-sha2-128s/seed").digest(48)

def wallet_payload(seed_hex, slh=None):
    seed = bytes.fromhex(seed_hex)
    return bytes([4, len(seed)]) + seed + (_slh_seed(seed_hex, 0) if slh is None else slh)

def mmm4_encode(seed_hex, secret_bytes, kind, family_hex=None, slh=None):
    prefix = b"XCOINMMM4\n" + bytes([kind]) + (bytes.fromhex(family_hex) if family_hex else b"")
    return _seal(secret_bytes, prefix, wallet_payload(seed_hex, slh))

def mmm5_encode(family_hex, cards, passphrase, seed_hex, factor_bytes):
    a = _seal(passphrase.encode(), b"XCOINMMM5A", json.dumps(cards, separators=(",", ":")).encode())
    b = _seal(factor_bytes + passphrase.encode(), b"XCOINMMM5B", wallet_payload(seed_hex))
    return b"XCOINMMM5\n" + bytes([2]) + bytes.fromhex(family_hex) + len(a).to_bytes(2, "big") + a + b


class DexFormatBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.addCleanup(setattr, w, "PASSPHRASE_FROM_FD", None)
    def use_passphrase(self, pw):
        w.PASSPHRASE_FROM_FD = pw
    def no_prompt(self):
        real = w.can_prompt; w.can_prompt = lambda: False
        self.addCleanup(setattr, w, "can_prompt", real)
    def write(self, name, blob):
        p = Path(self.tmp.name) / name; p.write_bytes(blob); os.chmod(p, 0o600); return p


class TestMmm4Format(DexFormatBase):
    """XCOINMMM4 (dex-wallet-era) opens read-only: passphrase kind unlocks through
    read_seed; the stored SLH seed is integrity-checked; card kinds are refused
    honestly (dex's `new` only ever wrote passphrase-kind v4 — cards went to v5)."""
    def test_roundtrip_with_passphrase(self):
        blob = mmm4_encode(SEED, b"pw123", 1)
        self.assertNotIn(bytes.fromhex(SEED), blob)          # seed bytes never stored raw
        self.assertEqual(w.mmm4_decode(blob, b"pw123"), SEED)
        p = self.write("v4.mmm", blob)
        self.use_passphrase("pw123"); self.no_prompt()
        self.assertEqual(w.read_seed(p), SEED)
    def test_empty_passphrase_unlocks_without_prompting(self):
        p = self.write("v4open.mmm", mmm4_encode(SEED, b"", 1))
        self.no_prompt()
        self.assertEqual(w.read_seed(p), SEED)
    def test_wrong_passphrase_is_honest(self):
        blob = mmm4_encode(SEED, b"pw123", 1)
        with self.assertRaisesRegex(w.WalletError, "wrong passphrase"):
            w.mmm4_decode(blob, b"nope")
        p = self.write("v4.mmm", blob)
        self.use_passphrase("nope"); self.no_prompt()
        with self.assertRaisesRegex(w.WalletError, "passphrase"):
            w.read_seed(p)
    def test_tamper_detected(self):
        blob = bytearray(mmm4_encode(SEED, b"pw123", 1))
        blob[50] ^= 0x01                                      # flip a ciphertext bit
        with self.assertRaises(w.WalletError):
            w.mmm4_decode(bytes(blob), b"pw123")
    def test_slh_integrity_check(self):
        # A properly sealed payload whose STORED slh_seed is corrupt must be refused
        # as derivation drift — and read_seed must surface it, not eat it as one more
        # wrong passphrase.
        bad_slh = bytearray(_slh_seed(SEED, 0)); bad_slh[0] ^= 0x01
        blob = mmm4_encode(SEED, b"pw123", 1, slh=bytes(bad_slh))
        with self.assertRaisesRegex(w.WalletError, "drift"):
            w.mmm4_decode(blob, b"pw123")
        p = self.write("v4drift.mmm", blob)
        self.use_passphrase("pw123"); self.no_prompt()
        with self.assertRaisesRegex(w.WalletError, "drift"):
            w.read_seed(p)
    def test_card_kinds_refused_honestly(self):
        for kind in (2, 3):
            p = self.write(f"v4k{kind}.mmm", mmm4_encode(SEED, b"\x11" * 32, kind, family_hex="ab" * 8))
            with self.assertRaisesRegex(w.WalletError, "unsupported kind"):
                w.read_seed(p)


FACTOR = bytes(range(32))
FAMILY = hashlib.sha256(b"xcoin-mmm-family" + FACTOR).hexdigest()[:16]
UID = "04a1b2c3d4e580"
CARDS = [{"uid": UID, "family": FAMILY, "label": "primary", "read_key_no": 2, "read_key": "00" * 16}]


class TestMmm5Format(DexFormatBase):
    """XCOINMMM5 (dex-wallet-era one-file card wallet) opens read-only: passphrase
    opens the card records, then the tap supplies the factor. The card layer is
    monkeypatched — no hardware; Mmm5CardStore.load is still exercised for real."""
    def make_wallet(self, pw="pw123"):
        blob = mmm5_encode(FAMILY, CARDS, pw, SEED, FACTOR)
        return self.write("wallet003.mmm", blob), blob
    def patch_card(self, factor):
        taps = []
        class FakeFactor:
            def __init__(s, b): s._b = b
            def bytes(s): return s._b
            def close(s): s._b = b""
        def read_factor(transport, store=None):
            taps.append(store.load(UID))                      # the real Mmm5CardStore
            return FakeFactor(factor), taps[-1]
        fake = types.SimpleNamespace(
            disable_core_dumps=lambda: None,
            PCSCTransport=lambda: types.SimpleNamespace(close=lambda: None),
            read_factor=read_factor,
            family_of=lambda b: hashlib.sha256(b"xcoin-mmm-family" + b).hexdigest()[:16])
        real = w._card_module; w._card_module = lambda: fake
        self.addCleanup(setattr, w, "_card_module", real)
        return taps
    def test_unlock_with_card_and_passphrase(self):
        from contextlib import redirect_stderr
        p, _ = self.make_wallet()
        taps = self.patch_card(FACTOR)
        self.use_passphrase("pw123"); self.no_prompt()
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(w.read_seed(p), SEED)
        self.assertEqual(len(taps), 1)
        self.assertEqual(taps[0]["uid"], UID)
        self.assertIn("Tap your wallet card", err.getvalue())  # prompt on stderr, stdout stays JSON-clean
    def test_wrong_passphrase_fails_before_any_tap(self):
        p, _ = self.make_wallet()
        taps = self.patch_card(FACTOR)
        self.use_passphrase("nope"); self.no_prompt()
        with self.assertRaisesRegex(w.WalletError, "wrong passphrase"):
            w.read_seed(p)
        self.assertEqual(taps, [])
    def test_empty_passphrase_errors_early(self):
        p, _ = self.make_wallet()
        taps = self.patch_card(FACTOR)
        self.use_passphrase(""); self.no_prompt()
        with self.assertRaisesRegex(w.WalletError, "needs its passphrase"):
            w.read_seed(p)
        self.assertEqual(taps, [])
    def test_no_terminal_no_passphrase(self):
        p, _ = self.make_wallet()
        self.patch_card(FACTOR); self.no_prompt()
        with self.assertRaisesRegex(w.WalletError, "no terminal"):
            w.read_seed(p)
    def test_wrong_factor_is_family_mismatch(self):
        from contextlib import redirect_stderr
        p, _ = self.make_wallet()
        self.patch_card(b"\xff" * 32)                         # a different card's factor
        self.use_passphrase("pw123"); self.no_prompt()
        with redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(w.WalletError, "family mismatch"):
                w.read_seed(p)
    def test_wrong_factor_honest_message(self):
        _, blob = self.make_wallet()
        with self.assertRaisesRegex(w.WalletError, r"wrong card \(or passphrase\)"):
            w.mmm5_seed(blob, b"\xff" * 32, "pw123")
    def test_seed_never_revealed_for_card_wallet(self):
        p, _ = self.make_wallet()
        self.assertTrue(w.is_card_wallet(p))


class TestWalletsList(unittest.TestCase):
    """`wallets` lists ~/.xcoin AND ~/.dex-wallet candidates with per-file format
    (sniffed from the magic) and a card flag; the default star keeps the
    default_wallet() precedence (~/.xcoin only). Never prompts."""
    def list_rows(self, fake_home):
        import unittest.mock as mock
        with mock.patch.object(w.Path, "home", staticmethod(lambda: fake_home)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = w.main(["--json", "wallets"])
            self.assertEqual(rc, 0)
            return json.loads(buf.getvalue())
    def test_lists_both_dirs_with_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            d = fake_home / ".xcoin"; d.mkdir()
            (d / "wallet.mmm").write_bytes(w.mmm_encode(SEED, ""))
            (d / "cold.mmm").write_bytes(w.mmm2_encode(SEED, b"\x11" * 32, "ab" * 8))
            (d / "wallet.seed").write_text("ab" * 32)
            x = fake_home / ".dex-wallet"; x.mkdir()
            (x / "wallet.mmm").write_bytes(mmm4_encode(SEED, b"pw", 1))
            (x / "wallet003.mmm").write_bytes(mmm5_encode(FAMILY, CARDS, "pw", SEED, FACTOR))
            rows = self.list_rows(fake_home)
        self.assertEqual([r["name"] for r in rows],
                         ["cold.mmm", "wallet.mmm", "wallet.seed", "wallet.mmm", "wallet003.mmm"])
        self.assertEqual([r["format"] for r in rows], ["mmm2", "mmm1", "seed", "mmm4", "mmm5-card"])
        self.assertEqual([r["card"] for r in rows], [True, False, False, False, True])
        self.assertEqual([r["default"] for r in rows], [False, True, False, False, False])
        self.assertTrue(rows[3]["file"].endswith(".dex-wallet/wallet.mmm"))
    def test_missing_dex_dir_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            d = fake_home / ".xcoin"; d.mkdir()
            (d / "wallet.mmm").write_bytes(w.mmm_encode(SEED, ""))
            rows = self.list_rows(fake_home)
        self.assertEqual([(r["name"], r["format"], r["card"], r["default"]) for r in rows],
                         [("wallet.mmm", "mmm1", False, True)])


class TestTwoLeafAndCarried(Base):
    """Balance/UTXOs/send cover BOTH forms of a key index: the two-leaf script and
    the carried single-leaf script, scanned together; RPC is faked, the keytool
    derives the scripts for real (nothing is signed or broadcast here)."""
    def setUp(self):
        super().setUp()
        self.offline_calls = []
        def fake_offline(seed, raw, prev):
            self.offline_calls.append((seed, raw, prev)); return "aa" * 5408
        real = w.sign_offline; w.sign_offline = fake_offline
        self.addCleanup(lambda: setattr(w, "sign_offline", real))
    def unspents(self, index=0):
        two, carried = own(index)["scriptPubKey"], own(index)["carried_scriptPubKey"]
        return [utxo("t1", 0, "3", 10, 200, spk=two),
                utxo("t2", 1, "0.5", 199, 200, coinbase=True, spk=two),        # immature
                utxo("c1", 0, "2", 10, 200, spk=carried),
                utxo("c2", 3, "7", 150, 200, coinbase=True, spk=carried),       # immature
                utxo("zz", 0, "100", 10, 200, spk="5320" + "99" * 32)]          # not this key's: dropped
    def fake(self, unspents, chain="test"):
        FakeRPC.responses = {
            "scantxoutset": {"success": True, "height": 200, "unspents": unspents},
            "getblockchaininfo": {"chain": chain},
            "validateaddress": {"isvalid": True},
            "getmempoolinfo": {"minrelaytxfee": Decimal("0.000001"), "mempoolminfee": Decimal("0.000001")},
            "estimatesmartfee": {"errors": ["no data"]},
            "createrawtransaction": "00rawtx00",
            "decoderawtransaction": {"txid": "deadbeef", "vsize": 2900},
            "testmempoolaccept": [{"allowed": True}],
            "sendrawtransaction": "deadbeef",
        }
    def test_one_scan_over_both_scripts(self):
        self.fake(self.unspents())
        rc, _ = self.run_cli("--json", "balance")
        self.assertEqual(rc, 0)
        (params,), = [self.called("scantxoutset")]
        self.assertEqual(params[0], "start")
        self.assertEqual(sorted(params[1]), sorted([f"raw({own(0)['scriptPubKey']})", f"raw({own(0)['carried_scriptPubKey']})"]))
    def test_balance_json_merges_forms(self):
        self.fake(self.unspents())
        rc, out = self.run_cli("--json", "balance")
        d = json.loads(out)
        self.assertEqual(d["address"], own(0, "txa")["address"])
        self.assertEqual(d["carried_address"], own(0, "txa")["carried_address"])
        self.assertEqual((d["spendable"], d["immature"], d["total"]), ("5.00000000", "7.50000000", "12.50000000"))
        self.assertEqual((d["utxos"], d["immature_utxos"]), (4, 2))
        two, car = d["forms"]["two_leaf"], d["forms"]["carried"]
        self.assertEqual((two["spendable"], two["immature"], two["total"], two["utxos"]), ("3.00000000", "0.50000000", "3.50000000", 2))
        self.assertEqual((car["spendable"], car["immature"], car["total"], car["utxos"]), ("2.00000000", "7.00000000", "9.00000000", 2))
        self.assertEqual((two["address"], car["address"]), (d["address"], d["carried_address"]))
    def test_balance_human_shows_carried_line(self):
        self.fake(self.unspents())
        rc, out = self.run_cli("balance")
        self.assertIn("Total:         12.50000000 XCF", out)
        self.assertIn("carried:     9.00000000 XCF in 2 UTXOs on " + own(0, "txa")["carried_address"], out)
        self.assertIn("two-leaf:    3.50000000 XCF in 2 UTXOs", out)
    def test_balance_without_carried_is_unchanged(self):
        self.fake([u for u in self.unspents() if u["txid"].startswith("t")])
        rc, out = self.run_cli("balance")
        self.assertNotIn("carried:", out)
        rc, out = self.run_cli("--json", "balance")
        d = json.loads(out)
        self.assertEqual(d["forms"]["carried"]["utxos"], 0)
        self.assertEqual(d["total"], "3.50000000")
    def test_utxos_tag_each_kind(self):
        self.fake(self.unspents())
        rc, out = self.run_cli("--json", "utxos")
        rows = {r["txid"]: r for r in json.loads(out)}
        self.assertEqual(sorted(rows), ["c1", "c2", "t1", "t2"])
        self.assertEqual({t: r["kind"] for t, r in rows.items()}, {"t1": "two_leaf", "t2": "two_leaf", "c1": "carried", "c2": "carried"})
        self.assertEqual({t for t, r in rows.items() if r["spendable"]}, {"t1", "c1"})
        rc, out = self.run_cli("utxos")
        self.assertEqual(sum(1 for l in out.splitlines() if " carried" in l), 2)
    def test_send_selects_a_mix_with_the_right_prevout_scripts(self):
        self.fake(self.unspents())
        rc, out = self.run_cli("--json", "send", DEST, "4", "--yes", "--dry-run")
        self.assertEqual(rc, 0, out)
        d = json.loads(out)
        self.assertEqual((d["inputs"], d["carried_inputs"]), (2, 1))
        (inputs, outputs), = self.called("createrawtransaction")
        self.assertEqual([i["txid"] for i in inputs], ["t1", "c1"])        # largest mature first, both forms
        (seed, raw, prev), = self.offline_calls
        spk = {p["txid"]: p["scriptPubKey"] for p in prev}
        self.assertEqual(spk, {"t1": own(0)["scriptPubKey"], "c1": own(0)["carried_scriptPubKey"]})
        self.assertEqual({p["keyindex"] for p in prev}, {0})
        # change goes to the TWO-LEAF address, never the carried one
        self.assertEqual(len(outputs), 2)
        self.assertEqual(list(outputs[1]), [own(0, "txa")["address"]])
        self.assertNotIn(own(0, "txa")["carried_address"], json.dumps(outputs))
        # the fee budgets every input as a two-leaf ML-DSA spend
        fee = w.fee_for(2, 2, Decimal("0.0001"))
        self.assertEqual(d["fee"], w.fmt8(fee))
        self.assertEqual(Decimal(outputs[1][own(0, "txa")["address"]]), Decimal("5") - Decimal("4") - fee)
    def test_send_can_spend_only_carried(self):
        carried = own(0)["carried_scriptPubKey"]
        self.fake([utxo("c9", 0, "10", 10, 200, spk=carried)])
        rc, out = self.run_cli("--json", "send", DEST, "1", "--yes", "--dry-run")
        self.assertEqual(rc, 0, out)
        (seed, raw, prev), = self.offline_calls
        self.assertEqual([p["scriptPubKey"] for p in prev], [carried])
        (inputs, outputs), = self.called("createrawtransaction")
        self.assertEqual(list(outputs[1]), [own(0, "txa")["address"]])
    def test_explorer_backend_scans_both_addresses(self):
        # --explorer: the scantxoutset shim turns each raw(5320<root>) back into its
        # address and asks /api/utxos for both forms; UTXOs are tagged by script.
        info = own(0, "txa")
        paths = []
        def fake_get(rpc, path, timeout=60):
            paths.append(path)
            if path == "/api/utxos/" + info["address"]:
                return {"height": 200, "total_amount": Decimal("3"), "utxos": [
                    {"txid": "t1", "vout": 0, "amount": Decimal("3"), "height": 10, "confirmations": 191}]}
            if path == "/api/utxos/" + info["carried_address"]:
                return {"height": 201, "total_amount": Decimal("2"), "utxos": [
                    {"txid": "c1", "vout": 0, "amount": Decimal("2"), "height": 10, "confirmations": 192,
                     "scriptPubKey": info["carried_scriptPubKey"]}]}
            raise AssertionError(path)
        real = w.ExplorerRPC._get; w.ExplorerRPC._get = fake_get
        self.addCleanup(setattr, w.ExplorerRPC, "_get", real)
        rpc = w.ExplorerRPC("https://explorer.invalid", "txa")
        res = rpc.call("scantxoutset", ["start", [f"raw({info['scriptPubKey']})", f"raw({info['carried_scriptPubKey']})"]])
        self.assertEqual(paths, ["/api/utxos/" + info["address"], "/api/utxos/" + info["carried_address"]])
        self.assertEqual((res["height"], res["total_amount"]), (201, Decimal("5")))
        self.assertEqual({u["txid"]: u["scriptPubKey"] for u in res["unspents"]},
                         {"t1": info["scriptPubKey"], "c1": info["carried_scriptPubKey"]})
        with self.assertRaisesRegex(w.WalletError, "witness-v3"):
            rpc.call("scantxoutset", ["start", ["raw(5220" + "11" * 32 + ")"]])
        # and end to end through the CLI
        paths.clear()
        rc, out = self.run_cli("--explorer", "https://explorer.invalid", "--hrp", "txa", "--json", "balance")
        self.assertEqual(rc, 0, out)
        d = json.loads(out)
        self.assertEqual((d["spendable"], d["forms"]["two_leaf"]["spendable"], d["forms"]["carried"]["spendable"]),
                         ("5.00000000", "3.00000000", "2.00000000"))
        self.assertEqual(sorted(paths), sorted(["/api/utxos/" + info["address"], "/api/utxos/" + info["carried_address"]]))


# --- independent parsers for the signing checks (no keytool code reused) ---
def parse_tx(hexstr):
    raw = bytes.fromhex(hexstr); pos = 0
    def take(n):
        nonlocal pos; b = raw[pos:pos + n]; pos += n; return b
    def cpt():
        c = take(1)[0]
        return c if c < 0xfd else int.from_bytes(take({0xfd: 2, 0xfe: 4, 0xff: 8}[c]), "little")
    tx = {"version": int.from_bytes(take(4), "little"), "vin": [], "vout": [], "witness": []}
    segwit = raw[pos] == 0 and raw[pos + 1] == 1
    if segwit: take(2)
    for _ in range(cpt()):
        h = take(32); vout = int.from_bytes(take(4), "little"); ss = take(cpt())
        tx["vin"].append({"hash": h, "vout": vout, "scriptSig": ss, "sequence": int.from_bytes(take(4), "little")})
    for _ in range(cpt()):
        v = int.from_bytes(take(8), "little"); tx["vout"].append((v, take(cpt())))
    if segwit:
        for _ in tx["vin"]: tx["witness"].append([take(cpt()) for _ in range(cpt())])
    tx["locktime"] = int.from_bytes(take(4), "little")
    assert pos == len(raw)
    return tx

def v3_sighash_py(tx, spent, n_in, leafhash):
    """The witness v3 message, SIGHASH_DEFAULT, ML-DSA key_version 0x02, rebuilt from
    the BIP-341 field list; TestTwoLeafSigning pins it to the keytool's regression lock."""
    sha = lambda b: hashlib.sha256(b).digest()
    m = (b"\x00\x00" + tx["version"].to_bytes(4, "little") + tx["locktime"].to_bytes(4, "little")
         + sha(b"".join(i["hash"] + i["vout"].to_bytes(4, "little") for i in tx["vin"]))
         + sha(b"".join(a.to_bytes(8, "little") for a, _ in spent))
         + sha(b"".join(_compact(len(s)) + s for _, s in spent))
         + sha(b"".join(i["sequence"].to_bytes(4, "little") for i in tx["vin"]))
         + sha(b"".join(v.to_bytes(8, "little") + _compact(len(s)) + s for v, s in tx["vout"]))
         + b"\x02" + n_in.to_bytes(4, "little") + leafhash + b"\x02" + b"\xff\xff\xff\xff")
    return _tagged(b"XCoinSighash/v3", _tagged(b"TapSighash", m))


class TestTwoLeafSigning(unittest.TestCase):
    """The real keytool signs FAKE prevouts on the two-leaf and the carried script of
    one key (nothing is broadcast; no chain needed): witness shape, control blocks
    that prove membership in the program's tree, and ML-DSA signatures that verify
    over an independently recomputed sighash."""
    NOKEY = hashlib.sha256(b"xcoin/v3/nokey").digest()
    def setUp(self):
        if not w.keytool_path(): self.skipTest("native keytool not built")
    def verify(self, pk, msg, sig):
        import subprocess
        r = subprocess.run([str(w.keytool_path()), "_verify"], input=f"{pk.hex()}\n{msg.hex()}\n{sig.hex()}\n".encode(), capture_output=True)
        return r.stdout.decode().strip()
    def test_python_sighash_matches_the_regression_lock(self):
        tx = {"version": 2, "locktime": 700, "vin": [
                {"hash": b"\x11" * 32, "vout": 0, "sequence": 0xfffffffd},
                {"hash": b"\x22" * 32, "vout": 1, "sequence": 0xfffffffd}],
              "vout": [(100000, b"\x53\x20" + b"\xaa" * 32), (250000, b"\x53\x20" + b"\xbb" * 32)]}
        spent = [(300000, b"\x53\x20" + b"\xcc" * 32), (60000, b"\x53\x20" + b"\xdd" * 32)]
        self.assertEqual(v3_sighash_py(tx, spent, 0, b"\xee" * 32).hex(), "c12202292bdb20c61dc34f13381c1d589854ab0436ac34fb69ea1162d30fa187")
        self.assertEqual(v3_sighash_py(tx, spent, 1, b"\xff" * 32).hex(), "966b91132bec61fe663d0636ce13b4cc56742c34e9c18e7ebfe0df5e034622dd")
    def test_sign_two_leaf_and_carried_inputs(self):
        info = own(0)
        prev = [{"txid": "a1" * 32, "vout": 0, "scriptPubKey": info["scriptPubKey"], "amount": Decimal("5"), "keyindex": 0},
                {"txid": "b2" * 32, "vout": 7, "scriptPubKey": info["carried_scriptPubKey"], "amount": Decimal("2"), "keyindex": 0}]
        dest = bytes.fromhex(own(1)["scriptPubKey"])
        raw = w.build_unsigned_tx(prev, [(dest, 699990000)])
        signed = w.sign_offline(SEED, raw, prev)
        tx = parse_tx(signed)
        self.assertEqual(w.parse_signed_tx(signed)["txid"], hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex())
        spent = [(500000000, bytes.fromhex(info["scriptPubKey"])), (200000000, bytes.fromhex(info["carried_scriptPubKey"]))]
        self.assertEqual([[len(x) for x in st] for st in tx["witness"]], [[1952, 3309, 34, 65], [1952, 3309, 34, 33]])
        for i, st in enumerate(tx["witness"]):
            pk, sig, script, control = st
            self.assertEqual(hashlib.sha256(pk).hexdigest(), info["pubkey_sha256"])
            self.assertEqual(script, b"\x20" + hashlib.sha256(pk).digest() + b"\xac")
            leaf = v3_leaf_hash(0xc0, script)
            self.assertEqual(control[:33], b"\xc0" + self.NOKEY)
            if i == 0:   # two-leaf: the sibling (SLH-DSA leaf) hash completes the Merkle proof to the program
                self.assertEqual(v3_branch_hash(leaf, control[33:]).hex(), info["program"])
            else:        # carried: the ML-DSA leaf IS the program
                self.assertEqual(leaf.hex(), info["carried_program"])
            digest = v3_sighash_py(tx, spent, i, leaf)       # tapleaf = the 0xc0 leaf hash in both trees
            self.assertEqual(self.verify(pk, digest, sig), "OK")
            self.assertEqual(self.verify(pk, bytes([digest[0] ^ 1]) + digest[1:], sig), "FAIL")
    def test_wrong_key_index_refused(self):
        info = own(0)
        prev = [{"txid": "a1" * 32, "vout": 0, "scriptPubKey": info["scriptPubKey"], "amount": Decimal("5"), "keyindex": 1}]
        raw = w.build_unsigned_tx(prev, [(bytes.fromhex(info["scriptPubKey"]), 499990000)])
        with self.assertRaisesRegex(w.WalletError, "key at index 1 does not control input 0"):
            w.sign_offline(SEED, raw, prev)
        prev[0].update(keyindex=0, scriptPubKey="5320" + "99" * 32)     # right key, foreign program
        raw = w.build_unsigned_tx(prev, [(bytes.fromhex(info["scriptPubKey"]), 499990000)])
        with self.assertRaisesRegex(w.WalletError, "key at index 0 does not control input 0"):
            w.sign_offline(SEED, raw, prev)


class TestSignMessageFloor(unittest.TestCase):
    """_signmsg refuses messages short enough to be a spend sighash (32 bytes):
    a sign-in challenge must never double as a spend signature."""
    def test_short_message_refused(self):
        tool = w.keytool_path()
        if not tool: self.skipTest("native keytool not built")
        import subprocess
        for msg in (b"\x00" * 32, b"x" * 64):
            r = subprocess.run([str(tool), "_signmsg", "--index", "0"],
                               input=(SEED + "\n" + msg.hex() + "\n").encode(), capture_output=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(b"shorter than 65 bytes", r.stderr)
        r = subprocess.run([str(tool), "_signmsg", "--index", "0"],
                           input=(SEED + "\n" + (b"y" * 65).hex() + "\n").encode(), capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)


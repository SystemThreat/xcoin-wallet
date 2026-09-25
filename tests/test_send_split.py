#!/usr/bin/env python3
"""send --split: the planner, the JSON shape (node RPC and --explorer), partial
broadcast, dry run, and the XCOIN-EVENT progress lines. RPC and signing are faked;
nothing is broadcast anywhere."""

import hashlib, io, json, os, subprocess, sys, unittest, urllib.error
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wallet_cli as w
import test_wallet_cli as T

RATE = Decimal("0.0001")          # FakeRPC's fallbackfee: the rate every node-path test pays
FLOOR = w.DUST_CHANGE
SPLIT_KEYS = {"broadcast", "txid", "txids", "transactions", "amount", "fee", "vsize", "change",
              "inputs", "carried_inputs", "signer", "partial"}

def coins(n, each, spk=T.SPK, kind="two_leaf"):
    return [dict(T.utxo(f"{i:064x}", 0, each, 10, 200, spk=spk), kind=kind) for i in range(n)]

def check_plan(test, plan, amount, pool):
    """Invariants every plan keeps: exact total, floors, weight cap, no coin twice, fee math."""
    used = [(u["txid"], u["vout"]) for s, _, _, _ in plan for u in s]
    test.assertEqual(len(used), len(set(used)))
    test.assertTrue(set(used) <= {(u["txid"], u["vout"]) for u in pool})
    test.assertEqual(sum(p for _, p, _, _ in plan), amount)
    for s, pay, fee, change in plan:
        test.assertLessEqual(w.estimate_sizes(len(s), 2)[1] * 4, w.MAX_STANDARD_TX_WEIGHT)
        test.assertGreaterEqual(pay, FLOOR)
        test.assertTrue(change == 0 or change >= FLOOR, change)
        test.assertEqual(sum(u["amount"] for u in s), pay + fee + change)     # inputs = payment + fee + change
        test.assertGreaterEqual(fee, w.fee_for(len(s), 2, RATE))              # never under the rate

class TestSplitPlanner(unittest.TestCase):
    def test_240_utxos_pay_3333_in_four(self):
        pool = coins(240, "14")
        plan = w.plan_payment(pool, Decimal("3333"), feerate=RATE, split=True)
        cap = w.max_inputs()
        self.assertEqual(cap, 72)                                  # 72 two-leaf inputs: 398,764 WU
        self.assertEqual(len(plan), -(-3333 // (cap * 14)))        # ceil(3333 / ~1000) = 4
        self.assertEqual([len(s) for s, _, _, _ in plan], [72, 72, 72, 23])
        check_plan(self, plan, Decimal("3333"), pool)
        # full transactions spend everything to the destination; the last one carries the change
        for s, pay, fee, change in plan[:3]:
            self.assertEqual((fee, change), (w.fee_for(72, 2, RATE), 0))
        s, pay, fee, change = plan[3]
        self.assertEqual(fee, w.fee_for(23, 2, RATE))
        self.assertEqual(change, 23 * 14 - pay - fee)
        # largest-first across the whole plan
        amounts = [u["amount"] for t in plan for u in t[0]]
        self.assertEqual(amounts, sorted(amounts, reverse=True))
    def test_largest_first_across_transactions(self):
        pool = coins(100, "1") + [dict(u, txid="b" + u["txid"][1:]) for u in coins(80, "5")]
        plan = w.plan_payment(pool, Decimal("420"), feerate=RATE, split=True)
        check_plan(self, plan, Decimal("420"), pool)
        self.assertTrue(all(u["amount"] == 5 for u in plan[0][0]))
        self.assertEqual(len(plan[0][0]), 72)
    def test_sub_floor_rest_keeps_floor_change_instead(self):
        # 72 x 1 XCF spent whole would leave 0.00005 XCF for the next transaction: below the floor
        fee72 = w.fee_for(72, 2, RATE)
        pool = coins(73, "1")
        amount = Decimal(72) - fee72 + Decimal("0.00005")
        plan = w.plan_payment(pool, amount, feerate=RATE, split=True)
        check_plan(self, plan, amount, pool)
        self.assertEqual(len(plan), 2)
        self.assertEqual(plan[0][3], FLOOR)                        # change of exactly the floor
        self.assertEqual(plan[1][1], Decimal("0.00015"))           # the rest is now above the floor
    def test_last_chunk_sub_floor_change_folds_into_fee(self):
        fee72, fee1 = w.fee_for(72, 2, RATE), w.fee_for(1, 2, RATE)
        pool = coins(73, "1")
        amount = (Decimal(72) - fee72) + (Decimal(1) - fee1 - Decimal("0.00003"))
        plan = w.plan_payment(pool, amount, feerate=RATE, split=True)
        check_plan(self, plan, amount, pool)
        self.assertEqual([(len(s), c) for s, _, _, c in plan], [(72, 0), (1, 0)])
        self.assertEqual(plan[1][2], fee1 + Decimal("0.00003"))    # 3,000 sat of would-be change went to the fee
    def test_single_transaction_is_exactly_select_coins(self):
        for pool, amount in ((coins(5, "3"), Decimal("7")), (coins(72, "14"), Decimal("1000")), (coins(1, "50"), Decimal("1"))):
            (s, pay, fee, change), = w.plan_payment(pool, amount, feerate=RATE, split=True)
            self.assertEqual((s, fee, change), w.select_coins(pool, amount, feerate=RATE))
            self.assertEqual(pay, amount)
    def test_without_split_the_cap_error_is_unchanged(self):
        with self.assertRaisesRegex(w.WalletError, r"^one transaction can carry at most 72 inputs \(1008\.00000000 XCF from "
                                    r"these UTXOs\); send at most about 1008\.00000000 XCF now and the rest in another send$"):
            w.plan_payment(coins(240, "14"), Decimal("3333"), feerate=RATE)
        with self.assertRaisesRegex(w.WalletError, "one transaction can carry at most 72"):
            w.select_coins(coins(240, "14"), Decimal("3333"), feerate=RATE)
    def test_split_insufficient(self):
        with self.assertRaisesRegex(w.WalletError, r"insufficient spendable funds: have 3360\.00000000 XCF"):
            w.plan_payment(coins(240, "14"), Decimal("3360"), feerate=RATE, split=True)
        with self.assertRaisesRegex(w.WalletError, "insufficient"):
            w.plan_payment(coins(10, "1"), Decimal("20"), feerate=RATE, split=True)
    def test_dust_coins_cannot_carry_a_split(self):
        with self.assertRaisesRegex(w.WalletError, "insufficient"):
            w.plan_payment(coins(200, "0.00012"), Decimal("0.01"), feerate=RATE, split=True)
    def test_fixed_fee_split_refused(self):
        (s, pay, fee, change), = w.plan_payment(coins(3, "5"), Decimal("7"), fixed_fee=Decimal("0.01"), split=True)
        self.assertEqual(fee, Decimal("0.01"))
        with self.assertRaisesRegex(w.WalletError, "fee rate"):
            w.plan_payment(coins(240, "14"), Decimal("3333"), fixed_fee=Decimal("0.01"), split=True)

class SplitBase(T.Base):
    """Node-RPC fakes with a distinct txid per transaction; the signer is faked."""
    def setUp(self):
        super().setUp()
        for k in ("XCOIN_EVENTS",): self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
        grace = mock.patch.object(w, "BROADCAST_GRACE", 0); grace.start(); self.addCleanup(grace.stop)
        self.signed, self.unlocks = [], 0
        def sign(seed, raw, prev):
            self.signed.append((seed, raw, prev)); return hashlib.sha256(raw.encode()).hexdigest() * 2
        real_sign, real_read = w.sign_offline, w.read_seed
        def read(path):
            self.unlocks += 1; return real_read(path)
        w.sign_offline, w.read_seed = sign, read
        self.addCleanup(setattr, w, "sign_offline", real_sign); self.addCleanup(setattr, w, "read_seed", real_read)
    @staticmethod
    def txid(hexstr): return hashlib.sha256(bytes.fromhex(hexstr)).hexdigest()
    def fake(self, pool, fail_at=None, reject_at=None, fail_msg="RPC sendrawtransaction: bad-txns-inputs-missingorspent"):
        spk = T.own(0)["scriptPubKey"]
        for u in pool: u["scriptPubKey"] = spk
        self.tested, self.sent = [], []
        def accept(p):
            self.tested.append(p[0][0]); i = len(self.tested)
            return [{"allowed": i != reject_at, "reject-reason": "min relay fee not met" if i == reject_at else None}]
        def send(p):
            if len(self.sent) + 1 == fail_at: raise w.WalletError(fail_msg)
            self.sent.append(self.txid(p[0])); return self.sent[-1]
        T.FakeRPC.responses = {
            "scantxoutset": {"success": True, "height": 200, "unspents": pool},
            "getblockchaininfo": {"chain": "test"}, "validateaddress": {"isvalid": True},
            "getmempoolinfo": {"minrelaytxfee": Decimal("0.000001"), "mempoolminfee": Decimal("0.000001")},
            "estimatesmartfee": {"errors": ["no data"]},
            "createrawtransaction": lambda p: json.dumps(p, sort_keys=True),
            "testmempoolaccept": accept,
            "decoderawtransaction": lambda p: {"txid": self.txid(p[0]), "vsize": 99691},
            "sendrawtransaction": send}
    def send(self, *argv, events=True):
        if events: os.environ["XCOIN_EVENTS"] = "1"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", *argv])
        ev = [l.split(" ", 1)[1] for l in err.getvalue().splitlines() if l.startswith("XCOIN-EVENT ")]
        return rc, out.getvalue(), err.getvalue(), ev
    def plan(self, pool, amount):
        return w.plan_payment([dict(u, amount=w.money(u["amount"])) for u in pool], Decimal(amount), feerate=RATE, split=True)

class TestSplitSendNode(SplitBase):
    def test_json_shape_one_unlock_sequential_broadcast(self):
        pool = coins(240, "14"); self.fake(pool)
        plan = self.plan(pool, "3333")
        rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes")
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        self.assertTrue(SPLIT_KEYS <= set(d))
        self.assertNotIn("broadcast_error", d)
        self.assertEqual((d["broadcast"], d["partial"], d["transactions"], d["signer"]), (True, False, 4, "offline keytool"))
        self.assertEqual(d["txids"], self.sent); self.assertEqual(d["txid"], self.sent[0]); self.assertEqual(len(set(self.sent)), 4)
        self.assertEqual(Decimal(d["amount"]), Decimal("3333"))
        self.assertEqual(Decimal(d["fee"]), sum(f for _, _, f, _ in plan))
        self.assertEqual(Decimal(d["change"]), plan[-1][3])
        self.assertEqual((d["inputs"], d["carried_inputs"], d["vsize"]), (239, 0, 4 * 99691))
        # ONE unlock, then every transaction signed (same seed) before the first broadcast
        self.assertEqual(self.unlocks, 1)
        self.assertEqual([s for s, _, _ in self.signed], [T.SEED] * 4)
        # each transaction pays the destination; only the last has change, to the two-leaf address
        creates = self.called("createrawtransaction")
        self.assertEqual([len(i) for i, _ in creates], [72, 72, 72, 23])
        self.assertEqual(len({(u["txid"], u["vout"]) for i, _ in creates for u in i}), 239)
        self.assertEqual([list(o[0]) for _, o in creates], [[T.DEST]] * 4)
        self.assertEqual([len(o) for _, o in creates], [1, 1, 1, 2])
        self.assertEqual(list(creates[3][1][1]), [T.own(0, "txa")["address"]])
        self.assertEqual(sum(Decimal(o[0][T.DEST]) for _, o in creates), Decimal("3333"))
        # policy-checked one at a time (two near-cap transactions exceed the package weight limit)
        self.assertEqual([len(p[0]) for p in self.called("testmempoolaccept")], [1, 1, 1, 1])
        self.assertEqual(ev, [f"signing {i} 4" for i in range(1, 5)] + ["broadcast-begin 4"]
                         + [f"broadcast {i} 4 {t}" for i, t in enumerate(self.sent, 1)] + ["done"])
    def test_partial_broadcast_reports_exactly_what_went_out(self):
        pool = coins(240, "14"); self.fake(pool, fail_at=3)
        plan = self.plan(pool, "3333")
        rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes")
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        self.assertTrue(SPLIT_KEYS | {"broadcast_error"} <= set(d))
        self.assertEqual((d["broadcast"], d["partial"], d["transactions"]), (True, True, 4))
        self.assertEqual(d["txids"], self.sent); self.assertEqual(len(self.sent), 2)
        self.assertIn("bad-txns-inputs-missingorspent", d["broadcast_error"])
        self.assertEqual(d["unsent_txids"], [self.txid(h) for h in self.tested[2:]])   # the failed one first
        self.assertEqual(Decimal(d["amount"]), plan[0][1] + plan[1][1])
        self.assertEqual(Decimal(d["fee"]), plan[0][2] + plan[1][2])
        self.assertEqual((d["inputs"], d["vsize"], Decimal(d["change"])), (144, 2 * 99691, 0))
        self.assertEqual(len(self.called("sendrawtransaction")), 3)      # the 4th is never tried
        self.assertEqual(ev, [f"signing {i} 4" for i in range(1, 5)] + ["broadcast-begin 4"]
                         + [f"broadcast {i} 4 {t}" for i, t in enumerate(self.sent, 1)] + ["done"])
    def test_partial_human(self):
        pool = coins(240, "14"); self.fake(pool, fail_at=4)
        rc, out, err, _ = self.send("send", T.DEST, "3333", "--split", "--yes", events=False)
        self.assertEqual(rc, 0, err)
        self.assertIn("PARTIAL SEND: 3 of 4 transactions broadcast; transaction 4 failed", out)
        rows = [l for l in out.splitlines() if "TXID:" in l]
        self.assertEqual([l.endswith("vbytes") for l in rows], [True, True, True, False])
        self.assertTrue(rows[3].startswith("  4/4  TXID:") and rows[3].endswith("UNKNOWN: look it up"))   # its result is unknown
        self.assertNotIn("NOT SENT", out)
        self.assertIn(f"Look up {self.txid(self.tested[3])} before paying the rest again", out)
    def test_partial_human_later_ones_never_tried(self):
        pool = coins(240, "14"); self.fake(pool, fail_at=2)
        rc, out, err, _ = self.send("send", T.DEST, "3333", "--split", "--yes", events=False)
        self.assertEqual(rc, 0, err)
        rows = [l for l in out.splitlines() if "TXID:" in l]
        self.assertTrue(rows[1].endswith("UNKNOWN: look it up"))
        self.assertTrue(rows[2].endswith("NOT SENT") and rows[3].endswith("NOT SENT"))
        self.assertIn("The NOT SENT transactions were never broadcast.", out)
    def test_first_broadcast_failure_is_an_error(self):
        pool = coins(240, "14"); self.fake(pool, fail_at=1)
        rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("bad-txns-inputs-missingorspent", err)
        # a dropped connection can hide a success: the error names the txid to look up
        self.assertIn(f"Nothing is confirmed sent, but if the connection dropped it may have gone out: look up {self.txid(self.tested[0])}", err)
        self.assertIn("(the other 3 transactions were never broadcast)", err)
        self.assertEqual(out, ""); self.assertNotIn("done", ev)
        self.assertEqual(ev[-1], "broadcast-begin 4")
    def test_dry_run_signs_all_broadcasts_nothing(self):
        pool = coins(240, "14"); self.fake(pool)
        rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes", "--dry-run")
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        self.assertEqual((d["broadcast"], d["partial"], d["transactions"], d["mempool_accept"]), (False, False, 4, True))
        self.assertEqual(d["txids"], [self.txid(s) for s in self.tested]); self.assertEqual(d["txid"], d["txids"][0])
        self.assertEqual(Decimal(d["amount"]), Decimal("3333"))
        self.assertEqual(self.called("sendrawtransaction"), [])
        self.assertEqual(ev, [f"signing {i} 4" for i in range(1, 5)] + ["done"])
    def test_any_mempool_reject_blocks_every_broadcast(self):
        pool = coins(240, "14"); self.fake(pool, reject_at=2)
        rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("node would reject transaction 2 of 4 (min relay fee not met); nothing was broadcast", err)
        self.assertEqual(self.called("sendrawtransaction"), [])
        self.fake(coins(240, "14"), reject_at=2)
        rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes", "--dry-run")
        d = json.loads(out)
        self.assertEqual((rc, d["mempool_accept"], d["reject_reason"]), (0, False, "transaction 2: min relay fee not met"))
    def test_human_preview_and_result(self):
        pool = coins(240, "14"); self.fake(pool)
        rc, out, err, _ = self.send("send", T.DEST, "3333", "--split", "--yes", events=False)
        self.assertEqual(rc, 0, err)
        self.assertIn("Transaction preview (split into 4 transactions)", out)
        self.assertIn("  Amount:      3333.00000000 XCF in total", out)
        self.assertIn("  Tx 1/4:      72 inputs, pays 1007.99003090 XCF, fee 0.00996910 XCF", out)
        self.assertIn("  Tx 4/4:      23 inputs", out)
        self.assertIn("Broadcast successful: 4 transactions", out)
    def test_without_split_unchanged_error_nothing_signed(self):
        pool = coins(240, "14"); self.fake(pool)
        rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("error: one transaction can carry at most 72 inputs", err)
        self.assertIn("the rest in another send", err)
        self.assertEqual((self.signed, self.called("createrawtransaction"), ev), ([], [], []))
    def test_split_single_transaction_behaves_like_today(self):
        runs = {}
        for flags in ((), ("--split",)):
            pool = coins(3, "50"); self.fake(pool); T.FakeRPC.calls = []
            rc, out, err, _ = self.send("send", T.DEST, "60", "--yes", *flags, events=False)
            runs[flags] = (rc, out, self.called("createrawtransaction"), self.sent)
        self.assertEqual(runs[()], runs[("--split",)])                 # same tx, same words
        self.assertIn("Broadcast successful\nTXID: ", runs[()][1])
        pool = coins(3, "50"); self.fake(pool)
        rc, out, err, _ = self.send("--json", "send", T.DEST, "60", "--yes", "--dry-run", events=False)
        plain = json.loads(out)
        rc, out, err, _ = self.send("--json", "send", T.DEST, "60", "--yes", "--dry-run", "--split", events=False)
        split = json.loads(out)
        self.assertEqual({k: split[k] for k in plain}, plain)          # today's keys, same values
        self.assertEqual((split["txids"], split["transactions"], split["partial"]), ([plain["txid"]], 1, False))
        self.assertEqual(Decimal(split["amount"]), Decimal("60"))
    def test_fee_guards(self):
        pool = coins(240, "14"); self.fake(pool)
        rc, _, err, _ = self.send("send", T.DEST, "3333", "--split", "--yes", "--max-fee", "0.03")
        self.assertEqual(rc, 1); self.assertIn("total fee 0.03309850 XCF exceeds --max-fee", err)
        rc, _, err, _ = self.send("send", T.DEST, "3333", "--split", "--yes", "--fee", "0.01")
        self.assertEqual(rc, 1); self.assertIn("a split send needs a fee rate", err)
        self.assertEqual(self.signed, [])

class TestSendEvents(SplitBase):
    def test_plain_send_events(self):
        pool = coins(1, "50"); self.fake(pool)
        rc, out, err, ev = self.send("--json", "send", T.DEST, "1", "--yes")
        self.assertEqual(rc, 0, err)
        self.assertEqual(ev, ["signing 1 1", "broadcast-begin 1", f"broadcast 1 1 {self.sent[0]}", "done"])
        self.assertTrue(all(l.startswith("XCOIN-EVENT ") for l in err.splitlines() if "XCOIN" in l))
        self.assertNotIn("XCOIN-EVENT", out)                             # stdout stays pure JSON
    def test_no_events_without_the_variable(self):
        for value in (None, "0", ""):
            pool = coins(240, "14"); self.fake(pool)
            if value is not None: os.environ["XCOIN_EVENTS"] = value
            rc, out, err, _ = self.send("--json", "send", T.DEST, "3333", "--split", "--yes", events=False)
            self.assertEqual(rc, 0, err)
            self.assertNotIn("XCOIN-EVENT", err + out)
    def test_failed_send_never_says_done(self):
        pool = coins(1, "50"); self.fake(pool, reject_at=1)
        rc, out, err, ev = self.send("--json", "send", T.DEST, "1", "--yes")
        self.assertEqual((rc, ev), (1, ["signing 1 1"]))                   # rejected before any broadcast: no broadcast-begin
    def test_broadcast_begin_just_before_the_first_send(self):
        """One timeline of stderr lines, RPC calls and the grace sleep: broadcast-begin comes
        after every signature and policy check, then the pause, then the first send."""
        pool = coins(240, "14"); self.fake(pool)
        line = []
        class Tee(io.StringIO):
            def write(s, text):
                line.extend(("stderr", l) for l in text.splitlines() if l.startswith("XCOIN-EVENT")); return super().write(text)
        real_call = T.FakeRPC.call
        def call(rpc, method, params=None, timeout=60):
            if method in ("testmempoolaccept", "sendrawtransaction"): line.append(("rpc", method))
            return real_call(rpc, method, params, timeout)
        os.environ["XCOIN_EVENTS"] = "1"
        with mock.patch.object(T.FakeRPC, "call", call), mock.patch.object(w, "BROADCAST_GRACE", 0.25), \
             mock.patch.object(w.time, "sleep", lambda s: line.append(("sleep", s))), redirect_stdout(io.StringIO()), redirect_stderr(Tee()):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", "--json", "send", T.DEST, "3333", "--split", "--yes"])
        self.assertEqual(rc, 0)
        at = line.index(("stderr", "XCOIN-EVENT broadcast-begin 4"))
        self.assertEqual(line[at + 1:at + 3], [("sleep", 0.25), ("rpc", "sendrawtransaction")])
        self.assertTrue(all(k != ("rpc", "sendrawtransaction") for k in line[:at]))
        self.assertEqual(sum(1 for k in line[:at] if k == ("rpc", "testmempoolaccept")), 4)
        self.assertEqual(sum(1 for k in line[:at] if k[1].startswith("XCOIN-EVENT signing")), 4)
        self.assertEqual(sum(1 for k in line if k[1] == "XCOIN-EVENT broadcast-begin 4"), 1)
    def test_no_broadcast_begin_or_pause_without_events_or_broadcast(self):
        slept = []
        with mock.patch.object(w.time, "sleep", slept.append):
            pool = coins(240, "14"); self.fake(pool)
            rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes", events=False)
            self.assertEqual((rc, slept), (0, []))                          # plain CLI use never pauses
            self.assertNotIn("broadcast-begin", err)
            self.fake(pool)
            rc, out, err, ev = self.send("--json", "send", T.DEST, "3333", "--split", "--yes", "--dry-run")
            self.assertEqual((rc, slept), (0, []))
            self.assertNotIn("broadcast-begin 4", ev)

class TestParentGone(SplitBase):
    """MMM quit or died mid-broadcast: the pipes it read are closed. The orphaned CLI (a real
    child process on real pipes; RPC and signing faked) still attempts every planned broadcast."""
    CHILD = """
import os, signal, sys, time
closed, tried, sigpipe = sys.argv[1:4]; sys.path[:0] = sys.argv[4:6]
if sigpipe == "default": signal.signal(signal.SIGPIPE, signal.SIG_DFL)   # as if not Python's own SIG_IGN
import wallet_cli as w, test_send_split as S
b = S.SplitBase(); b.setUp(); b.fake(S.coins(240, "14")); os.environ["XCOIN_EVENTS"] = "1"
send = S.T.FakeRPC.responses["sendrawtransaction"]
def attempt(p):
    while not os.path.exists(closed): time.sleep(0.01)                  # the parent has closed both pipes
    with open(tried, "a") as f: f.write(b.txid(p[0]) + "\\n")
    return send(p)
S.T.FakeRPC.responses["sendrawtransaction"] = attempt
sys.exit(w.main(["--file", str(b.wallet), "--config", "/nonexistent", *sys.argv[6:]]))
"""
    def run_orphan(self, *argv, sigpipe="python", close_after=b"XCOIN-EVENT broadcast-begin 4"):
        closed, tried = Path(self.tmp.name) / "closed", Path(self.tmp.name) / "tried"
        here = Path(__file__).resolve().parent
        p = subprocess.Popen([sys.executable, "-c", self.CHILD, str(closed), str(tried), sigpipe, str(here.parent), str(here), *argv],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in p.stderr:
            if line.startswith(close_after): break
        p.stdout.close(); p.stderr.close(); closed.touch()
        return p.wait(timeout=60), tried.read_text().split() if tried.exists() else []
    def test_every_broadcast_is_attempted_after_the_pipes_close(self):
        pool = coins(240, "14"); self.fake(pool)
        rc, out, err, _ = self.send("--json", "send", T.DEST, "3333", "--split", "--yes")   # the same send, pipes open
        planned = json.loads(out)["txids"]; self.assertEqual(len(planned), 4)
        for argv in (("--json",), ()):
            for sigpipe in ("python", "default"):
                with self.subTest(argv=argv, sigpipe=sigpipe):
                    for f in ("closed", "tried"): (Path(self.tmp.name) / f).unlink(missing_ok=True)
                    rc, tried = self.run_orphan(*argv, "send", T.DEST, "3333", "--split", "--yes", sigpipe=sigpipe)
                    self.assertEqual(tried, planned)        # all four, in order: no write aborted the loop
                    self.assertEqual(rc, 0)                 # the final report's write and the exit flush did not fail either

    def test_nothing_is_sent_when_the_parent_dies_before_broadcast_begin(self):
        # MMM never learned the send was committed, so it could not warn the user at the next
        # launch: the orphan must stop instead of broadcasting behind its back.
        pool = coins(240, "14"); self.fake(pool)
        for argv in (("--json",), ()):
            for sigpipe in ("python", "default"):
                with self.subTest(argv=argv, sigpipe=sigpipe):
                    for f in ("closed", "tried"): (Path(self.tmp.name) / f).unlink(missing_ok=True)
                    rc, tried = self.run_orphan(*argv, "send", T.DEST, "3333", "--split", "--yes",
                                                sigpipe=sigpipe, close_after=b"XCOIN-EVENT signing 1 4")
                    self.assertEqual(tried, [])
                    self.assertNotEqual(rc, 0)

class TestSplitSendExplorer(SplitBase):
    """--explorer: txids are computed locally, broadcast goes to /api/broadcast (faked)."""
    def setUp(self):
        super().setUp()
        self.info = T.own(0, "txa"); self.dest = T.own(1, "txa")["address"]
        pool = [{"txid": f"{i:064x}", "vout": i % 3, "amount": Decimal("14"), "height": 10, "confirmations": 191}
                for i in range(240)]
        def get(rpc, path, timeout=60):
            if path == "/api/utxos/" + self.info["address"]: return {"height": 200, "utxos": [dict(u) for u in pool]}
            if path == "/api/utxos/" + self.info["carried_address"]: return {"height": 200, "utxos": []}
            if path == "/api/feerate": return {"feerate_sat_vb": 1}
            raise AssertionError(path)
        p = mock.patch.object(w.ExplorerRPC, "_get", get); p.start(); self.addCleanup(p.stop)
        w.sign_offline = lambda seed, raw, prev: (self.signed.append((seed, raw, prev)), raw)[1]   # unsigned stays parseable
        self.posted, self.fail_at = [], None
        def urlopen(req, timeout=60):
            hexstr = json.loads(req.data)["hex"]; self.posted.append(hexstr)
            if len(self.posted) == self.fail_at:
                raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, io.BytesIO(b'{"reason": "txn-mempool-conflict"}'))
            return io.BytesIO(json.dumps({"txid": w.parse_signed_tx(hexstr)["txid"]}).encode())
        p = mock.patch("urllib.request.urlopen", urlopen); p.start(); self.addCleanup(p.stop)
    def explorer_send(self, *argv):
        return self.send("--explorer", "https://explorer.invalid", "--hrp", "txa", "--json", "send", self.dest, "3333", "--split", "--yes", *argv)
    def test_explorer_split_and_partial(self):
        self.fail_at = 3
        rc, out, err, ev = self.explorer_send()
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        local = [w.parse_signed_tx(h) for h in self.posted]
        self.assertEqual((d["partial"], d["broadcast"], d["transactions"], d["mempool_accept"]), (True, True, 4, None))
        self.assertEqual(d["txids"], [x["txid"] for x in local[:2]])
        self.assertEqual(d["vsize"], local[0]["vsize"] + local[1]["vsize"])
        self.assertEqual(d["broadcast_error"], "broadcast rejected: txn-mempool-conflict")
        self.assertEqual(ev[-4:], ["broadcast-begin 4", f"broadcast 1 4 {d['txids'][0]}", f"broadcast 2 4 {d['txids'][1]}", "done"])
        # the unsigned transactions the explorer path built: every output >= the floor, destination paid in each
        dest_spk = w.address_to_spk(self.dest, "txa")
        for _, raw, _ in self.signed:
            tx = T.parse_tx(raw)
            self.assertEqual(tx["vout"][0][1], dest_spk)
            self.assertTrue(all(v >= 10_000 for v, _ in tx["vout"]))
    def test_explorer_dry_run(self):
        rc, out, err, ev = self.explorer_send("--dry-run")
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        self.assertEqual((d["broadcast"], d["partial"], len(d["txids"]), self.posted), (False, False, 4, []))
        self.assertEqual(d["txids"], [w.parse_signed_tx(raw)["txid"] for _, raw, _ in self.signed])
        self.assertEqual(Decimal(d["amount"]), Decimal("3333"))
        self.assertEqual(ev, [f"signing {i} 4" for i in range(1, 5)] + ["done"])

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""send: an explicit refusal from the explorer or the node versus an unknown outcome. A fake
explorer (/api/utxos, /api/feerate, POST /api/broadcast in the shapes of xcoin-explorer.py) and a
fake node (JSON-RPC, errors as HTTP 500 + {"error": {"code", "message"}} like nexd) run on
127.0.0.1 in this process; the real ExplorerRPC and RPC classes talk to them over HTTP.
Signing is faked; nothing is broadcast anywhere."""

import base64, hashlib, io, json, os, sys, tempfile, threading, time, unittest, urllib.request
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wallet_cli as w
import test_wallet_cli as T

CONFLICT = "these coins are already being spent by an earlier send that has not confirmed yet. Wait for the next block, then send again."
SPENT = "these coins were already spent."
UNKNOWN = "Nothing is confirmed sent, but if the connection dropped it may have gone out: look up {} before sending again"
EXPLORER_RATE = Decimal("0.00001")          # the fake explorer's 1 sat/vB
NODE_RATE = Decimal("0.0001")               # the relay floor x10 the node path falls back to

class Server:
    """One fake HTTP service on 127.0.0.1 (port chosen by the OS), stopped at cleanup.
    `answers` scripts the broadcasts in turn: "ok", ("reject", reason), ("http", code, body),
    ("rpc-error", code, message), "drop" (connection closed, no reply), ("slow", seconds)."""
    def __init__(self, test, get=None, rpc=None):
        self.answers, self.posted, self.get, self.rpc = [], [], get, rpc
        srv = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(h, *a): pass
            def reply(h, code, obj):
                body = (obj if isinstance(obj, bytes) else json.dumps(obj, default=str).encode())
                h.send_response(code); h.send_header("Content-Type", "application/json")
                h.send_header("Content-Length", str(len(body))); h.end_headers(); h.wfile.write(body)
            def do_GET(h):
                code, obj = srv.get(h.path)
                h.reply(code, obj)
            def do_POST(h):
                data = h.rfile.read(int(h.headers.get("Content-Length") or 0))
                srv.handle_post(h, h.path, json.loads(data))
        class Quiet(ThreadingHTTPServer):
            daemon_threads = True
            def handle_error(s, request, client_address): pass     # a client that gave up (timeout) is expected
        self.httpd = Quiet(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        test.addCleanup(self.httpd.server_close); test.addCleanup(self.httpd.shutdown)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.port = self.httpd.server_address[1]
    def next_answer(self): return self.answers.pop(0) if self.answers else "ok"
    def handle_post(self, h, path, body):
        if self.rpc is not None: return self.rpc(h, body)
        assert path == "/api/broadcast", path
        self.posted.append(body["hex"]); a = self.next_answer()
        if a == "drop": h.close_connection = True; return                      # read, then hang up with no reply
        if isinstance(a, tuple) and a[0] == "slow": time.sleep(a[1]); a = "ok"
        if a == "ok": return h.reply(200, {"txid": w.parse_signed_tx(body["hex"])["txid"]})
        if a[0] == "reject": return h.reply(400, {"error": "rejected", "reason": a[1]})
        if a[0] == "http": return h.reply(a[1], a[2])
        raise AssertionError(a)

def error_lines(err): return [l for l in err.splitlines() if l.startswith("error:")]

class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        for k in ("XCOIN_EVENTS", "XCOIN_EXPLORER", "XCOIN_WALLET_PASSPHRASE"): self.addCleanup(os.environ.pop, k, None); os.environ.pop(k, None)
        self.wallet = Path(self.tmp.name) / "wallet.seed"; self.wallet.write_text(T.SEED + "\n"); os.chmod(self.wallet, 0o600)
        for p in (mock.patch.object(w, "BROADCAST_GRACE", 0), mock.patch.object(w, "PASSPHRASE_FROM_FD", None)):
            p.start(); self.addCleanup(p.stop)
        self.own = T.own(0, "txa")
    def run_cli(self, *argv, events=True):
        os.environ["XCOIN_EVENTS"] = "1" if events else "0"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = w.main(["--file", str(self.wallet), "--config", "/nonexistent", *argv])
        ev = [l.split(" ", 1)[1] for l in err.getvalue().splitlines() if l.startswith("XCOIN-EVENT ")]
        return rc, out.getvalue(), err.getvalue(), ev
    def assert_refused(self, rc, out, err, ev, *, plain, raw, token, n=1):
        self.assertEqual((rc, out), (1, ""), err)
        self.assertEqual(error_lines(err), [f"error: Nothing was sent: {plain} ({raw})"])
        self.assertEqual(ev[-2:], [f"broadcast-begin {n}", f"rejected 1 {n} {token}"])
        self.assertNotIn("Nothing is confirmed", err); self.assertNotIn("done", ev)
        self.assertFalse(any(e.startswith("broadcast ") for e in ev), ev)
    def assert_unknown(self, rc, out, err, ev, txid):
        self.assertEqual((rc, out), (1, ""), err)
        (line,) = error_lines(err)
        self.assertIn(UNKNOWN.format(txid), line)
        self.assertNotIn("Nothing was sent", line)
        self.assertFalse(any(e.startswith("rejected") for e in ev), ev)

# --- explorer ---------------------------------------------------------------------------------
class ExplorerBase(Base):
    def setUp(self):
        super().setUp()
        self.signed = []
        def sign(seed, raw, prev): self.signed.append(raw); return raw     # an unsigned tx stays parseable
        p = mock.patch.object(w, "sign_offline", sign); p.start(); self.addCleanup(p.stop)
        self.pool = []
        def get(path):
            if path == "/api/utxos/" + self.own["address"]: return 200, {"height": 200, "utxos": self.pool}
            if path == "/api/utxos/" + self.own["carried_address"]: return 200, {"height": 200, "utxos": []}
            if path == "/api/feerate": return 200, {"feerate_sat_vb": 1}
            return 404, {"error": "not_found"}
        self.explorer = Server(self, get=get)
        self.dest = T.own(1, "txa")["address"]
    def coins(self, n, each):
        self.pool = [{"txid": f"{i:064x}", "vout": i % 3, "amount": float(each), "height": 10, "confirmations": 191} for i in range(n)]
    def send(self, amount, *extra, json_out=True, events=True):
        return self.run_cli("--explorer", self.explorer.url, "--hrp", "txa", *(["--json"] if json_out else []),
                            "send", self.dest, amount, "--yes", *extra, events=events)
    def txids(self): return [w.parse_signed_tx(h)["txid"] for h in self.explorer.posted]

class TestExplorerRefusals(ExplorerBase):
    REASONS = [  # (explorer reason, plain words, event token)
        # what this chain's explorer really answers: its testmempoolaccept runs first, and the node
        # (src/rpc/mempool.cpp) reports spent coins as missing-inputs, and a send that conflicts with an
        # unconfirmed one as insufficient fee (rbf fee rules) or replacement-failed (validation.cpp)
        ("missing-inputs", SPENT, "missing-inputs"),
        ("replacement-failed", CONFLICT, "replacement-failed"),
        ("insufficient fee", CONFLICT, "insufficient-fee"),
        ("txn-mempool-conflict", CONFLICT, "txn-mempool-conflict"),
        ("insufficient fee, rejecting replacement 7f3a0c2e9b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a, "
         "less fees than conflicting txs; 0.00004 < 0.00005", CONFLICT, "insufficient-fee"),
        ("bad-txns-inputs-missingorspent", SPENT, "bad-txns-inputs-missingorspent"),
        ("min relay fee not met, 100 < 5412", "its fee is below the network's minimum relay fee. Send again with a higher fee.", "min-relay-fee-not-met"),
        ("mempool min fee not met, 100 < 200", "its fee is below what the network accepts right now. Send again with a higher fee.", "mempool-min-fee-not-met"),
        ("bad-txout-below-min, every output that is not NULL_DATA must carry at least the chain's minimum value",
         "an amount in it is below the network's smallest allowed output (0.00010000 XID, 10,000 sat).", "bad-txout-below-min"),
        ("dust", "an amount in it is below the network's smallest allowed output (0.00010000 XID, 10,000 sat).", "dust"),
        ("non-final", "the network refused this transaction.", "non-final"),
    ]
    def test_explicit_refusal_says_nothing_was_sent(self):
        for reason, plain, token in self.REASONS:
            with self.subTest(reason[:30]):
                self.coins(1, 50); self.explorer.posted = []; self.explorer.answers = [("reject", reason)]
                rc, out, err, ev = self.send("1")
                self.assert_refused(rc, out, err, ev, plain=plain, raw=reason, token=token)
                self.assertEqual(ev, ["signing 1 1", "broadcast-begin 1", f"rejected 1 1 {token}"])
                self.assertEqual(len(self.explorer.posted), 1)
    def test_refusals_before_the_node_is_asked(self):
        for code, body, plain, raw in ((400, {"error": "rejected"}, "the network refused this transaction.", "rejected"),
                                       (400, {"error": "rejected", "reason": None}, "the network refused this transaction.", "rejected"),
                                       (400, {"error": "bad_hex"}, "the transaction could not be read.", "bad_hex"),
                                       (413, {"error": "too_large"}, "the transaction is too large.", "too_large")):
            with self.subTest(body):
                self.coins(1, 50); self.explorer.answers = [("http", code, body)]
                self.assert_refused(*self.send("1"), plain=plain, raw=raw, token=raw)
    def test_human_output_too(self):
        self.coins(1, 50); self.explorer.answers = [("reject", "txn-mempool-conflict")]
        rc, out, err, ev = self.send("1", json_out=False, events=False)
        self.assertEqual((rc, ev), (1, []))
        self.assertEqual(error_lines(err), [f"error: Nothing was sent: {CONFLICT} (txn-mempool-conflict)"])
        self.assertNotIn("Broadcast successful", out)
    def test_already_known_to_the_network_counts_as_sent(self):
        for reason in ("txn-already-in-mempool", "txn-already-known", "Transaction already in block chain",
                       "Transaction outputs already in utxo set"):
            with self.subTest(reason):
                self.coins(1, 50); self.explorer.posted = []; self.explorer.answers = [("reject", reason)]
                rc, out, err, ev = self.send("1")
                self.assertEqual(rc, 0, err)
                d = json.loads(out); (txid,) = self.txids()
                self.assertEqual((d["broadcast"], d["txid"]), (True, txid))
                self.assertEqual(ev, ["signing 1 1", "broadcast-begin 1", f"broadcast 1 1 {txid}", "done"])
                self.explorer.answers = [("reject", reason)]
                rc, out, err, ev = self.send("1", json_out=False, events=False)
                self.assertEqual(rc, 0, err); self.assertIn("Broadcast successful", out)
    def test_unknown_outcome_keeps_the_look_it_up_wording(self):
        cases = [("drop", "drop"), ("503 node unreachable", ("http", 503, {"error": "node_unreachable", "note": "the explorer cannot reach its xCoin node right now"})),
                 ("500 internal", ("http", 500, {"error": "internal"})), ("502 proxy page", ("http", 502, b"<html>Bad gateway</html>")),
                 ("404 json without a reason", ("http", 404, {"error": "not_found"})),
                 ("504 carrying a reason", ("http", 504, {"error": "gateway_timeout", "reason": "upstream timed out"}))]
        for name, answer in cases:
            with self.subTest(name):
                self.coins(1, 50); self.explorer.posted = []; self.explorer.answers = [answer]
                rc, out, err, ev = self.send("1")
                (txid,) = self.txids()
                self.assert_unknown(rc, out, err, ev, txid)
                if answer != "drop": self.assertIn(f"the explorer answered HTTP {answer[1]}", err)
                if name.startswith("503"): self.assertIn("node_unreachable", err); self.assertNotIn("broadcast rejected", err)
    def test_timeout_keeps_the_look_it_up_wording(self):
        real = urllib.request.urlopen
        self.coins(1, 50); self.explorer.answers = [("slow", 3)]
        with mock.patch("urllib.request.urlopen", lambda req, timeout=60: real(req, timeout=0.3)):
            rc, out, err, ev = self.send("1")
        self.assert_unknown(rc, out, err, ev, self.txids()[0])
        self.assertIn("timed out", err)

class TestExplorerSplit(ExplorerBase):
    def plan(self):
        pool = [dict(u, amount=w.money(u["amount"])) for u in self.pool]
        return w.plan_payment(pool, Decimal("3333"), feerate=EXPLORER_RATE, split=True)
    def test_first_refused_nothing_sent(self):
        self.coins(240, 14); self.explorer.answers = [("reject", "txn-mempool-conflict")]
        rc, out, err, ev = self.send("3333", "--split")
        self.assert_refused(rc, out, err, ev, plain=CONFLICT, raw="txn-mempool-conflict", token="txn-mempool-conflict", n=4)
        self.assertEqual(len(self.explorer.posted), 1)                                  # the other three never tried
    def test_later_refusal_keeps_exact_partial_accounting(self):
        self.coins(240, 14); plan = self.plan(); self.assertEqual(len(plan), 4)
        self.explorer.answers = ["ok", "ok", ("reject", "txn-mempool-conflict")]
        rc, out, err, ev = self.send("3333", "--split")
        self.assertEqual(rc, 0, err)
        d = json.loads(out); posted = self.txids()
        self.assertEqual(len(posted), 3)                                                # the 4th never tried
        local = [w.parse_signed_tx(r)["txid"] for r in self.signed]
        self.assertEqual((d["partial"], d["broadcast"], d["transactions"]), (True, True, 4))
        self.assertEqual(d["txids"], local[:2]); self.assertEqual(d["unsent_txids"], local[2:])
        self.assertEqual(Decimal(d["amount"]), plan[0][1] + plan[1][1])
        self.assertEqual(Decimal(d["fee"]), plan[0][2] + plan[1][2])
        self.assertEqual((d["inputs"], Decimal(d["change"])), (144, 0))
        self.assertEqual(d["vsize"], sum(w.parse_signed_tx(r)["vsize"] for r in self.signed[:2]))
        self.assertEqual((d["broadcast_error"], d["broadcast_rejected"]), ("broadcast rejected: txn-mempool-conflict", True))
        self.assertEqual(ev[-4:], ["broadcast-begin 4", f"broadcast 1 4 {local[0]}", f"broadcast 2 4 {local[1]}", "done"])
        self.assertFalse(any(e.startswith("rejected") for e in ev))
    def test_later_refusal_human(self):
        self.coins(240, 14); self.explorer.answers = ["ok", "ok", ("reject", "bad-txns-inputs-missingorspent")]
        rc, out, err, _ = self.send("3333", "--split", json_out=False, events=False)
        self.assertEqual(rc, 0, err)
        self.assertIn(f"PARTIAL SEND: 2 of 4 transactions broadcast; the network refused transaction 3: {SPENT} (bad-txns-inputs-missingorspent)", out)
        rows = [l for l in out.splitlines() if "TXID:" in l]
        self.assertEqual([l.endswith("vbytes") for l in rows], [True, True, False, False])
        self.assertTrue(rows[2].endswith("NOT SENT: the network refused it") and rows[3].endswith("  NOT SENT"), rows)
        self.assertNotIn("UNKNOWN", out); self.assertNotIn("Look up", out)
        self.assertIn("The NOT SENT transactions were never broadcast.", out)
    def test_later_drop_is_still_unknown(self):
        self.coins(240, 14); plan = self.plan(); self.explorer.answers = ["ok", "ok", "drop"]
        rc, out, err, ev = self.send("3333", "--split")
        self.assertEqual(rc, 0, err)
        d = json.loads(out); local = [w.parse_signed_tx(r)["txid"] for r in self.signed]
        self.assertEqual((d["partial"], d["txids"], d["unsent_txids"]), (True, local[:2], local[2:]))
        self.assertEqual(Decimal(d["amount"]), plan[0][1] + plan[1][1])
        self.assertTrue(d["broadcast_error"].startswith("cannot reach the explorer")); self.assertNotIn("broadcast_rejected", d)
        self.explorer.answers = ["ok", "ok", "drop"]
        rc, out, err, _ = self.send("3333", "--split", json_out=False, events=False)
        rows = [l for l in out.splitlines() if "TXID:" in l]
        self.assertTrue(rows[2].endswith("UNKNOWN: look it up") and rows[3].endswith("NOT SENT"))
        self.assertIn("before paying the rest again: if the connection dropped it may have gone out", out)
    def test_already_in_mempool_mid_split_counts_as_sent(self):
        self.coins(240, 14); self.explorer.answers = ["ok", ("reject", "txn-already-in-mempool"), "ok", "ok"]
        rc, out, err, ev = self.send("3333", "--split")
        self.assertEqual(rc, 0, err)
        d = json.loads(out); local = [w.parse_signed_tx(r)["txid"] for r in self.signed]
        self.assertEqual((d["partial"], d["txids"], Decimal(d["amount"])), (False, local, Decimal("3333")))
        self.assertEqual([e for e in ev if e.startswith("broadcast ")], [f"broadcast {i} 4 {t}" for i, t in enumerate(local, 1)])

# --- node RPC ---------------------------------------------------------------------------------
class NodeBase(Base):
    USER, PASSWORD = "rpcuser", "rpc-test-password"
    def setUp(self):
        super().setUp()
        self.signed, self.pool = [], []
        def sign(seed, raw, prev): self.signed.append(raw); return hashlib.sha256(raw.encode()).hexdigest() * 2
        p = mock.patch.object(w, "sign_offline", sign); p.start(); self.addCleanup(p.stop)
        self.node = Server(self, rpc=self.rpc)
        self.sent, self.verdicts = [], []          # verdicts: testmempoolaccept's answers in turn (default: allowed)
    @staticmethod
    def txid(hexstr): return hashlib.sha256(bytes.fromhex(hexstr)).hexdigest()
    def rpc(self, h, body):
        want = "Basic " + base64.b64encode(f"{self.USER}:{self.PASSWORD}".encode()).decode()
        if h.headers.get("Authorization") != want: return h.reply(401, b"")
        method, params, rid = body["method"], body.get("params") or [], body.get("id")
        ok = lambda r: h.reply(200, {"result": r, "error": None, "id": rid})
        if method == "sendrawtransaction":
            self.node.posted.append(params[0]); a = self.node.next_answer()
            if a == "drop": h.close_connection = True; return
            if a == "ok": self.sent.append(self.txid(params[0])); return ok(self.sent[-1])
            if a[0] == "rpc-error": return h.reply(500, {"result": None, "error": {"code": a[1], "message": a[2]}, "id": rid})
            if a[0] == "http": return h.reply(a[1], a[2])
            raise AssertionError(a)
        answers = {"scantxoutset": lambda: {"success": True, "height": 200, "unspents": self.pool},
                   "getblockchaininfo": lambda: {"chain": "test"}, "validateaddress": lambda: {"isvalid": True},
                   "getmempoolinfo": lambda: {"minrelaytxfee": "0.00001", "mempoolminfee": "0.00001"},
                   "estimatesmartfee": lambda: {"errors": ["Insufficient data or no feerate found"]},
                   "createrawtransaction": lambda: json.dumps(params, sort_keys=True, default=str),
                   "testmempoolaccept": lambda: [self.verdicts.pop(0) if self.verdicts else {"allowed": True}],
                   "decoderawtransaction": lambda: {"txid": self.txid(params[0]), "vsize": 99691}}
        if method not in answers: return h.reply(500, {"result": None, "error": {"code": -32601, "message": "Method not found"}, "id": rid})
        return ok(answers[method]())
    def coins(self, n, each):
        spk = self.own["scriptPubKey"]
        self.pool = [{"txid": f"{i:064x}", "vout": 0, "amount": each, "scriptPubKey": spk, "height": 10, "coinbase": False,
                      "confirmations": 191} for i in range(n)]
    def send(self, amount, *extra, json_out=True):
        return self.run_cli("--rpc-host", "127.0.0.1", "--rpc-port", str(self.node.port), "--rpc-user", self.USER,
                            "--rpc-password", self.PASSWORD, *(["--json"] if json_out else []),
                            "send", T.own(1, "txa")["address"], amount, "--yes", *extra)
    def local_txids(self): return [self.txid(hashlib.sha256(r.encode()).hexdigest() * 2) for r in self.signed]

class TestNodeRefusals(NodeBase):
    REASONS = [  # (RPC code, node message, plain words, token)
        (-26, "insufficient fee, rejecting replacement 7f3a0c2e9b1d, less fees than conflicting txs; 0.00004 < 0.00005", CONFLICT, "insufficient-fee"),
        (-26, "txn-mempool-conflict", CONFLICT, "txn-mempool-conflict"),
        (-26, "replacement-failed, insufficient feerate: does not improve feerate diagram", CONFLICT, "replacement-failed"),
        (-25, "bad-txns-inputs-missingorspent", SPENT, "bad-txns-inputs-missingorspent"),
        (-25, "Inputs missing or spent", SPENT, "inputs-missing-or-spent"),
        (-26, "min relay fee not met, 100 < 5412", "its fee is below the network's minimum relay fee. Send again with a higher fee.", "min-relay-fee-not-met"),
        (-26, "bad-txout-below-min, every output that is not NULL_DATA must carry at least the chain's minimum value",
         "an amount in it is below the network's smallest allowed output (0.00010000 XID, 10,000 sat).", "bad-txout-below-min"),
        (-22, "TX decode failed. Make sure the tx has at least one input.", "the transaction could not be read.", "tx-decode-failed"),
    ]
    def test_explicit_refusal_says_nothing_was_sent(self):
        for code, msg, plain, token in self.REASONS:
            with self.subTest(msg[:30]):
                self.coins(1, 50); self.node.posted = []; self.node.answers = [("rpc-error", code, msg)]
                rc, out, err, ev = self.send("1")
                self.assert_refused(rc, out, err, ev, plain=plain, raw=msg, token=token)
                self.assertEqual(len(self.node.posted), 1)
    def test_already_known_to_the_node_counts_as_sent(self):
        for code, msg in ((-27, "Transaction outputs already in utxo set"), (-27, "Transaction already in block chain"),
                          (-26, "txn-already-in-mempool"), (-26, "txn-already-known")):
            with self.subTest(msg):
                self.coins(1, 50); self.signed = []; self.node.answers = [("rpc-error", code, msg)]
                rc, out, err, ev = self.send("1")
                self.assertEqual(rc, 0, err)
                d = json.loads(out); (txid,) = self.local_txids()
                self.assertEqual((d["broadcast"], d["txid"]), (True, txid))
                self.assertEqual(ev[-2:], [f"broadcast 1 1 {txid}", "done"])
    def test_unknown_outcome_keeps_the_look_it_up_wording(self):
        for name, answer in (("drop", "drop"), ("500 without a JSON body", ("http", 500, b"<html>oops</html>")),
                             ("warming up (not a verdict on the transaction)", ("rpc-error", -28, "Loading block index..."))):
            with self.subTest(name):
                self.coins(1, 50); self.signed = []; self.node.answers = [answer]
                rc, out, err, ev = self.send("1")
                self.assert_unknown(rc, out, err, ev, self.local_txids()[0])
    def test_split_later_refusal_keeps_exact_partial_accounting(self):
        self.coins(240, 14)
        pool = [dict(u, amount=w.money(u["amount"])) for u in self.pool]
        plan = w.plan_payment(pool, Decimal("3333"), feerate=NODE_RATE, split=True)
        self.node.answers = ["ok", ("rpc-error", -26, "txn-mempool-conflict")]
        rc, out, err, ev = self.send("3333", "--split")
        self.assertEqual(rc, 0, err)
        d = json.loads(out); local = self.local_txids()
        self.assertEqual((d["partial"], d["txids"], d["unsent_txids"]), (True, self.sent, local[1:]))
        self.assertEqual(self.sent, local[:1])
        self.assertEqual((Decimal(d["amount"]), Decimal(d["fee"]), d["inputs"]), (plan[0][1], plan[0][2], 72))
        self.assertEqual((d["broadcast_error"], d["broadcast_rejected"]), ("broadcast rejected: txn-mempool-conflict", True))
        self.assertEqual(len(self.node.posted), 2)
    def test_split_first_refused(self):
        self.coins(240, 14); self.node.answers = [("rpc-error", -25, "bad-txns-inputs-missingorspent")]
        rc, out, err, ev = self.send("3333", "--split")
        self.assert_refused(rc, out, err, ev, plain=SPENT, raw="bad-txns-inputs-missingorspent", token="bad-txns-inputs-missingorspent", n=4)
        self.assertEqual(len(self.node.posted), 1)

class TestNodeCheck(NodeBase):
    """The node path asks testmempoolaccept before broadcast-begin. A refusal there is the node's
    answer, so certain: "Nothing was sent:" in plain words and the rejected event, nothing posted.
    A transaction the node already has is out: it is broadcast (the node answers with its txid) and
    counted as sent."""
    REFUSED = [("missing-inputs", SPENT, "missing-inputs"), ("replacement-failed", CONFLICT, "replacement-failed"),
               ("insufficient fee", CONFLICT, "insufficient-fee"),
               ("min relay fee not met", "its fee is below the network's minimum relay fee. Send again with a higher fee.", "min-relay-fee-not-met"),
               ("bad-txout-below-min", "an amount in it is below the network's smallest allowed output (0.00010000 XID, 10,000 sat).", "bad-txout-below-min"),
               ("non-final", "the network refused this transaction.", "non-final")]
    def test_refused_by_the_check_says_nothing_was_sent(self):
        for reason, plain, token in self.REFUSED:
            with self.subTest(reason):
                self.coins(1, 50); self.node.posted = []
                self.verdicts = [{"allowed": False, "reject-reason": reason}]
                rc, out, err, ev = self.send("1")
                self.assertEqual((rc, out), (1, ""), err)
                self.assertEqual(error_lines(err), [f"error: Nothing was sent: {plain} ({reason})"])
                self.assertEqual(ev, ["signing 1 1", f"rejected 1 1 {token}"])            # no broadcast-begin: nothing committed
                self.assertEqual(self.node.posted, [])
                self.assertNotIn("would reject", err); self.assertNotIn("Nothing is confirmed", err)
    def test_human_output_too(self):
        self.coins(1, 50); self.verdicts = [{"allowed": False, "reject-reason": "missing-inputs"}]
        rc, out, err, ev = self.send("1", json_out=False)
        self.assertEqual(rc, 1)
        self.assertEqual(error_lines(err), [f"error: Nothing was sent: {SPENT} (missing-inputs)"])
        self.assertNotIn("Broadcast successful", out)
    def test_split_any_refusal_blocks_every_broadcast(self):
        self.coins(240, 14)
        self.verdicts = [{"allowed": True}, {"allowed": False, "reject-reason": "missing-inputs"}]
        rc, out, err, ev = self.send("3333", "--split")
        self.assertEqual((rc, out), (1, ""), err)
        self.assertEqual(error_lines(err), [f"error: Nothing was sent: the node refused transaction 2 of 4, so none of the 4 was broadcast: "
                                            f"{SPENT} (missing-inputs)"])
        self.assertEqual(ev, [f"signing {i} 4" for i in range(1, 5)] + ["rejected 2 4 missing-inputs"])
        self.assertEqual(self.node.posted, [])
    def test_already_on_the_network_counts_as_sent(self):
        for reason, answer in (("txn-already-in-mempool", "ok"), ("txn-same-nonwitness-data-in-mempool", "ok"),
                               ("txn-already-known", ("rpc-error", -27, "Transaction outputs already in utxo set"))):
            with self.subTest(reason):
                self.coins(1, 50); self.signed, self.node.posted = [], []
                self.verdicts = [{"allowed": False, "reject-reason": reason}]; self.node.answers = [answer]
                rc, out, err, ev = self.send("1")
                self.assertEqual(rc, 0, err)
                d = json.loads(out); (txid,) = self.local_txids()
                self.assertEqual((d["broadcast"], d["txid"], d["reject_reason"]), (True, txid, reason))
                self.assertEqual(ev, ["signing 1 1", "broadcast-begin 1", f"broadcast 1 1 {txid}", "done"])
                self.assertEqual(len(self.node.posted), 1)
                self.assertNotIn("error:", err)
    def test_already_on_the_network_in_a_split(self):
        self.coins(240, 14)
        self.verdicts = [{"allowed": True}, {"allowed": False, "reject-reason": "txn-already-in-mempool"}]
        rc, out, err, ev = self.send("3333", "--split")
        self.assertEqual(rc, 0, err)
        d = json.loads(out); local = self.local_txids()
        self.assertEqual((d["partial"], d["txids"], d["mempool_accept"]), (False, local, True))
        self.assertNotIn("reject_reason", d)
        self.assertEqual([e for e in ev if e.startswith("broadcast ")], [f"broadcast {i} 4 {t}" for i, t in enumerate(local, 1)])
    def test_dry_run_names_it(self):
        self.coins(1, 50); self.verdicts = [{"allowed": False, "reject-reason": "txn-already-in-mempool"}]
        rc, out, err, ev = self.send("1", "--dry-run", json_out=False)
        self.assertEqual(rc, 0, err); self.assertIn("Mempool check: already on the network (txn-already-in-mempool)", out)
        self.verdicts = [{"allowed": False, "reject-reason": "missing-inputs"}]
        rc, out, err, ev = self.send("1", "--dry-run", json_out=False)
        self.assertEqual(rc, 0, err); self.assertIn("Mempool check: would be REJECTED (missing-inputs)", out)
        self.assertEqual(self.node.posted, [])

class TestRejectHelpers(unittest.TestCase):
    def test_this_nodes_reasons_in_plain_words(self):
        """Every reason this chain's node gives for coins that are spent or already being spent
        (pq-main / post-quantum src/validation.cpp, src/rpc/mempool.cpp, src/common/messages.cpp)."""
        for r in ("missing-inputs", "bad-txns-inputs-missingorspent", "Inputs missing or spent"):
            self.assertEqual(w.reject_plain(r), SPENT, r)
        for r in ("insufficient fee, rejecting replacement 1f, less fees than conflicting txs; 0.0001 < 0.0002",
                  "insufficient fee (including sibling eviction)", "replacement-failed",
                  "replacement-failed, insufficient feerate: does not improve feerate diagram",
                  "too many potential replacements", "txn-mempool-conflict"):
            self.assertEqual(w.reject_plain(r), CONFLICT, r)
    def test_tokens_are_one_word(self):
        for reason, token in (("insufficient fee, rejecting replacement x", "insufficient-fee"), ("bad_hex", "bad_hex"),
                              ("TX decode failed. Make sure", "tx-decode-failed"), ("", "rejected"), ("  ;; ", "rejected"),
                              ("non-mandatory-script-verify-flag (Signature must be zero)", "non-mandatory-script-verify-flag")):
            self.assertEqual(w.reject_token(reason), token)
            self.assertNotIn(" ", w.reject_token(reason))
    def test_already_out_reasons(self):
        for r in ("txn-already-in-mempool", "txn-already-known", "Transaction already in block chain",
                  "transaction outputs already in utxo set", "txn-same-nonwitness-data-in-mempool"):
            self.assertTrue(w.BroadcastRejected(r).already_out, r)
        for r in ("txn-mempool-conflict", "bad-txns-inputs-missingorspent", "insufficient fee"):
            self.assertFalse(w.BroadcastRejected(r).already_out, r)
        self.assertTrue(w.BroadcastRejected("anything", already=True).already_out)

if __name__ == "__main__":
    unittest.main(verbosity=2)

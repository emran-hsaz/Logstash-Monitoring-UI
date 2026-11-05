"""Tests for lsmon and lsdash. Standard library only:

    python3 -m unittest discover -s tests -v
"""

import base64
import copy
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import lsdash  # noqa: E402
import lsmon  # noqa: E402
import mock_logstash  # noqa: E402


def raw(e, t0=1000.0, **kw):
    """A raw snapshot as lsmon.collect() would return it, e seconds in."""
    return {"t": t0 + e, "stats": mock_logstash.build_stats(e, **kw),
            "pipelines_info": mock_logstash.build_pipelines_info()["pipelines"]}


def pipe(sample, pid):
    return next(p for p in sample["pipelines"] if p["id"] == pid)


def codes(sample, scope=None):
    return {f["code"] for f in sample["findings"] if scope is None or f["scope"] == scope}


class RateTests(unittest.TestCase):
    def setUp(self):
        self.th = dict(lsmon.DEFAULT_THRESHOLDS)
        self.a, self.b = raw(100), raw(130)
        self.s = lsmon.compute(self.a, self.b, self.th)

    def test_first_sample_has_no_rates(self):
        s = lsmon.compute(None, raw(100), self.th)
        self.assertIsNone(s["interval_s"])
        self.assertIsNone(pipe(s, "txn-processing-logs")["in_per_sec"])

    def test_rates_use_jvm_uptime(self):
        self.assertEqual(self.s["interval_s"], 30.0)
        p = pipe(self.s, "txn-processing-logs")
        self.assertAlmostEqual(p["in_per_sec"], 980 * 1.0, delta=980 * 0.15)
        self.assertAlmostEqual(p["cost_ms_per_event"], 3.9, places=1)

    def test_wall_clock_jitter_does_not_matter(self):
        late = copy.deepcopy(self.b)
        late["t"] += 25  # the timer fired late, but JVM uptime moved 30s
        s = lsmon.compute(self.a, late, self.th)
        self.assertEqual(s["interval_s"], 30.0)

    def test_drift_and_filling_queue(self):
        p = pipe(self.s, "api-gateway-payloads")
        self.assertGreater(p["drift_per_sec"], 100)
        self.assertEqual(p["queue_trend"], "filling")
        self.assertGreater(p["queue_eta_s"], 0)
        self.assertIn("worker_util", codes(self.s, "pipeline:api-gateway-payloads"))
        self.assertIn("backpressure", codes(self.s, "pipeline:api-gateway-payloads"))

    def test_draining_and_steady_queue(self):
        self.assertEqual(pipe(self.s, "api-gateway-headers")["queue_trend"], "draining")
        self.assertEqual(pipe(self.s, "txn-processing-logs")["queue_trend"], "steady")

    def test_gc_overhead(self):
        self.assertIsNotNone(self.s["gc_young_per_sec"])
        self.assertEqual(self.s["gc_old_per_sec"], 0.0)
        self.assertLess(self.s["gc_time_percent"], 1.0)

    def test_idle_pipelines(self):
        self.assertEqual(pipe(self.s, "sandbox-test-logs")["state"], "idle")
        self.assertNotIn("stalled", codes(self.s))


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.th = dict(lsmon.DEFAULT_THRESHOLDS)

    def test_restart_is_detected(self):
        before = raw(100)
        after = raw(5, t0=1200)  # uptime went backwards
        after["stats"]["ephemeral_id"] = "new"
        s = lsmon.compute(before, after, self.th)
        self.assertTrue(s["restart_detected"])
        self.assertIsNone(s["node_in_per_sec"])
        self.assertIn("restart", codes(s))

    def test_pipeline_reload_resets_counters(self):
        a, b = raw(100), raw(130)
        b["stats"]["pipelines"]["txn-audit-logs"]["events"]["in"] = 10
        b["stats"]["pipelines"]["txn-audit-logs"]["events"]["out"] = 10
        s = lsmon.compute(a, b, self.th)
        p = pipe(s, "txn-audit-logs")
        self.assertIsNone(p["in_per_sec"])
        self.assertIn("counter_reset", codes(s, "pipeline:txn-audit-logs"))

    def test_stall_needs_sustained_silence(self):
        th = dict(self.th, stall_seconds=60)
        a, b, c = raw(100), raw(130), raw(170)
        s1 = lsmon.compute(a, b, th)
        self.assertEqual(pipe(s1, "settlement-batch-logs")["state"], "quiet")
        s2 = lsmon.compute(b, c, th)  # b carries quiet_since from the first call
        self.assertEqual(pipe(s2, "settlement-batch-logs")["state"], "stalled")
        self.assertIn("stalled", codes(s2, "pipeline:settlement-batch-logs"))

    def test_reload_failure_reported(self):
        s = lsmon.compute(raw(100, flaky=True), raw(130, flaky=True), self.th)
        self.assertIn("reload_failures", codes(s, "pipeline:settlement-batch-logs"))

    def test_heap_alone_is_not_an_alarm(self):
        a, b = raw(100), raw(130)
        b["stats"]["jvm"]["mem"]["heap_used_percent"] = 90
        s = lsmon.compute(a, b, self.th)
        heap = [f for f in s["findings"] if f["code"] == "heap"]
        self.assertEqual(heap[0]["severity"], "INFO")

    def test_heap_with_gc_pressure_is_critical(self):
        a, b = raw(100), raw(130)
        b["stats"]["jvm"]["mem"]["heap_used_percent"] = 90
        b["stats"]["jvm"]["gc"]["collectors"]["old"]["collection_count"] = 60
        b["stats"]["jvm"]["gc"]["collectors"]["old"]["collection_time_in_millis"] = 9000
        s = lsmon.compute(a, b, self.th)
        sev = {f["code"]: f["severity"] for f in s["findings"]}
        self.assertEqual(sev["heap"], "CRIT")
        self.assertEqual(sev["gc_old"], "CRIT")
        self.assertIn("gc_overhead", sev)
        self.assertEqual(s["overall"], "CRIT")

    def test_missing_sections_do_not_crash(self):
        bare = {"t": 1.0, "stats": {"jvm": {"uptime_in_millis": 1000}, "pipelines": {"p": {}}}}
        bare2 = {"t": 2.0, "stats": {"jvm": {"uptime_in_millis": 2000}, "pipelines": {"p": {}}}}
        s = lsmon.compute(bare, bare2, self.th)
        self.assertEqual(s["overall"], "OK")
        lsmon.render(s, self.th, lsmon.Palette(False))

    def test_threshold_file_rejects_typos(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"heap_wran": 50}, fh)
        try:
            with self.assertRaises(ValueError):
                lsmon.load_thresholds(fh.name)
        finally:
            os.unlink(fh.name)


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = mock_logstash.make_server(0, "node-01", user="monitor", password="s3cret")
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def run_cli(self, *extra):
        os.environ["LS_API_USER"], os.environ["LS_API_PASSWORD"] = "monitor", "s3cret"
        try:
            return lsmon.main(["--url", "http://127.0.0.1:%d" % self.port, "--quiet",
                               "--state-file", os.path.join(self.tmp, "s.json"),
                               "--log-file", os.path.join(self.tmp, "m.jsonl")] + list(extra))
        finally:
            del os.environ["LS_API_USER"], os.environ["LS_API_PASSWORD"]

    def test_once_writes_state_and_log(self):
        self.assertEqual(self.run_cli(), 0)
        time.sleep(1.1)
        self.assertEqual(self.run_cli(), 0)
        with open(os.path.join(self.tmp, "m.jsonl")) as fh:
            lines = [json.loads(line) for line in fh]
        self.assertGreaterEqual(len(lines), 2)
        self.assertIsNotNone(lines[-1]["node_in_per_sec"])
        self.assertEqual(oct(os.stat(os.path.join(self.tmp, "s.json")).st_mode & 0o777), "0o600")

    def test_unreachable_is_logged_and_nagios_code(self):
        log = os.path.join(self.tmp, "down.jsonl")
        rc = lsmon.main(["--url", "http://127.0.0.1:1", "--quiet", "--nagios", "--timeout", "1",
                         "--state-file", os.path.join(self.tmp, "d.json"), "--log-file", log])
        self.assertEqual(rc, 3)
        with open(log) as fh:
            self.assertIn("error", json.loads(fh.readline()))

    def test_wrong_credentials_fail_cleanly(self):
        c = lsmon.Client("http://127.0.0.1:%d" % self.port, "monitor", "wrong")
        with self.assertRaises(RuntimeError):
            lsmon.collect(c)


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mocks = [mock_logstash.make_server(0, "node-0%d" % i, flaky=(i == 2)) for i in (1, 2)]
        for m in cls.mocks:
            threading.Thread(target=m.serve_forever, daemon=True).start()
        clients = [("node-0%d" % i, lsmon.Client("http://127.0.0.1:%d" % m.server_address[1]))
                   for i, m in zip((1, 2), cls.mocks)]
        clients.append(("node-03", lsmon.Client("http://127.0.0.1:1", timeout=1)))  # down
        cls.dash = lsdash.Dashboard(clients, refresh=0.5, history=10, label="TEST")
        cls.dash.poll_once()
        time.sleep(1.1)
        cls.dash.poll_once()
        cls.web = lsdash.make_server(cls.dash, "127.0.0.1", 0, auth=("ops", "pw"))
        cls.url = "http://127.0.0.1:%d" % cls.web.server_address[1]
        threading.Thread(target=cls.web.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown()
        for m in cls.mocks:
            m.shutdown()

    def get(self, path, auth=("ops", "pw")):
        req = urllib.request.Request(self.url + path)
        if auth:
            req.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % auth).encode()).decode())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return opener.open(req, timeout=5)

    def test_state_aggregates_nodes(self):
        s = self.dash.state()
        self.assertEqual(s["kpis"]["nodes_total"], 3)
        self.assertEqual(s["kpis"]["nodes_up"], 2)
        p = next(p for p in s["pipelines"] if p["id"] == "txn-processing-logs")
        self.assertEqual(p["total_nodes"], 2)
        self.assertEqual(len(p["split"]), 3)
        self.assertGreater(p["in"], 1000)

    def test_findings_grouped_with_nodes(self):
        att = self.dash.state()["attention"]
        down = [a for a in att if a["code"] == "unreachable"]
        self.assertEqual(down[0]["nodes"], ["node-03"])
        util = [a for a in att if a["code"] == "worker_util"]
        self.assertEqual(sorted(util[0]["nodes"]), ["node-01", "node-02"])
        reload_fail = [a for a in att if a["code"] == "reload_failures"]
        self.assertEqual(reload_fail[0]["nodes"], ["node-02"])

    def test_http_requires_auth(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/api/state", auth=None)
        self.assertEqual(cm.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError):
            self.get("/", auth=("ops", "nope"))

    def test_http_serves_page_and_state(self):
        page = self.get("/").read().decode()
        self.assertIn("<title>Logstash Monitor</title>", page)
        self.assertNotIn("__REFRESH_MS__", page)
        state = json.loads(self.get("/api/state").read().decode())
        self.assertEqual(state["label"], "TEST")
        self.assertEqual(self.get("/healthz", auth=None).read(), b"ok\n")


if __name__ == "__main__":
    unittest.main()

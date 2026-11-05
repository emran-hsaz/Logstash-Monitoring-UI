#!/usr/bin/env python3
"""
A fake Logstash monitoring API for demos and tests.

It serves /_node/stats and /_node/pipelines with counters that grow
realistically over time, including a saturated pipeline with a filling
persisted queue, a draining queue, a stalled pipeline and (with --flaky)
a failed pipeline reload. All names and numbers are invented.

    python3 tools/mock_logstash.py --port 9601 --name node-01 --heavy
    python3 tools/mock_logstash.py --port 9602 --name node-02 --flaky
    python3 tools/mock_logstash.py --port 9603 --name node-03
"""

import argparse
import base64
import hashlib
import json
import math
import socketserver
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

BYTES_PER_EVENT = 1500
QUEUE_MAX = 1 << 30            # 1 GiB persisted queue
COUNTER_BASE_S = 140000        # pretend the counters have been running ~1.6 days
UPTIME_BASE_S = 12 * 86400 + 4 * 3600

PIPELINES = [
    dict(id="txn-processing-logs", workers=5, batch=500, rin=980, rout=983, util=13.0, bp=0.001,
         queue="steady", q_pct=12, dlq=280000, cost=3.9, reloads=6),
    dict(id="api-gateway-payloads", workers=6, batch=500, rin=622, rout=468, util=88.0, bp=1.85,
         queue="filling", q_pct=72, cost=14.2, reloads=4),
    dict(id="txn-audit-logs", workers=3, batch=250, rin=352, rout=355, util=6.6, bp=0.002,
         queue=None, dlq=140000, cost=8.7, reloads=6),
    dict(id="api-gateway-headers", workers=6, batch=500, rin=129, rout=204, util=61.0, bp=0.41,
         queue="draining", q_pct=58, cost=6.4, reloads=5),
    dict(id="service-events-logs", workers=3, batch=250, rin=71, rout=71, util=6.0, bp=0.001,
         queue=None, cost=3.1, reloads=6),
    dict(id="settlement-batch-logs", workers=3, batch=250, rin=0, rout=0, util=0.0, bp=0.0,
         queue=None, cost=0, reloads=3, lifetime=1710000),
]
IDLE = ["batch-reconcile-logs", "partner-feed-logs", "replay-archive-logs", "sandbox-test-logs",
        "legacy-xml-ingest", "metrics-forwarder", "notifications-logs", "report-export-logs",
        "scheduler-events-logs"]


def _flow(v):
    return {"current": round(v, 4), "last_1_minute": round(v, 4), "lifetime": round(v, 4)}


def _count(rate, e, phase):
    return int(rate * (COUNTER_BASE_S + e) + 0.6 * rate * math.sin(e / 5.0 + phase))


def build_stats(e, name="node-01", heavy=False, flaky=False, started=0.0):
    """Pure function: the /_node/stats payload `e` seconds after start."""
    seed = int(hashlib.sha1(name.encode()).hexdigest(), 16)
    scale = 0.97 + (seed % 7) / 100.0
    phase = (seed % 100) / 15.0
    pipelines = {}
    total_in = total_out = total_dur = 0

    for spec in PIPELINES:
        rin, rout = spec["rin"] * scale, spec["rout"] * scale
        if spec.get("lifetime"):
            ein = eout = spec["lifetime"]
        else:
            ein, eout = _count(rin, e, phase), _count(rout, e, phase)
        dur = int(eout * spec["cost"])
        total_in, total_out, total_dur = total_in + ein, total_out + eout, total_dur + dur
        wobble = 1 + 0.04 * math.sin(e / 4.0 + phase)
        p = {
            "events": {"in": ein, "filtered": eout, "out": eout, "duration_in_millis": dur,
                       "queue_push_duration_in_millis": int(spec["bp"] * (UPTIME_BASE_S + e) * 1000)},
            "flow": {
                "input_throughput": _flow(rin), "filter_throughput": _flow(rout), "output_throughput": _flow(rout),
                "queue_backpressure": _flow(spec["bp"] * wobble),
                "worker_concurrency": _flow(spec["util"] * spec["workers"] / 100.0),
                "worker_utilization": _flow(min(100.0, spec["util"] * wobble)),
            },
            "plugins": {"inputs": [], "filters": [], "outputs": [{
                "id": "es-" + spec["id"], "name": "elasticsearch",
                "documents": {"successes": eout, "non_retryable_failures": 0},
                "bulk_requests": {"successes": eout // spec["batch"] if spec["batch"] else 0, "with_errors": 0},
            }]},
            "reloads": {"successes": spec["reloads"], "failures": 0, "last_error": None},
            "queue": {"type": "memory", "events_count": 0, "queue_size_in_bytes": 0, "max_queue_size_in_bytes": 0},
        }
        if spec["queue"]:
            e0 = spec["q_pct"] / 100.0 * QUEUE_MAX / BYTES_PER_EVENT
            growth = rin - rout
            if spec["queue"] == "steady":
                events, growth = e0 + 40 * math.sin(e / 5.0), 0.0
            elif spec["queue"] == "filling":
                events = min(QUEUE_MAX * 0.995 / BYTES_PER_EVENT, e0 + growth * e)
            else:
                events = max(0.0, e0 + growth * e)
            events = int(events)
            p["queue"] = {
                "type": "persisted", "events_count": events,
                "queue_size_in_bytes": events * BYTES_PER_EVENT, "max_queue_size_in_bytes": QUEUE_MAX,
                "capacity": {"queue_size_in_bytes": events * BYTES_PER_EVENT,
                             "max_queue_size_in_bytes": QUEUE_MAX, "page_capacity_in_bytes": 64 << 20},
            }
            p["flow"]["queue_persisted_growth_events"] = _flow(growth)
            p["flow"]["queue_persisted_growth_bytes"] = _flow(growth * BYTES_PER_EVENT)
        if spec.get("dlq"):
            p["dead_letter_queue"] = {"queue_size_in_bytes": spec["dlq"], "dropped_events": 0, "expired_events": 0}
        if flaky and spec["id"] == "settlement-batch-logs":
            p["reloads"]["failures"] = 1
            p["reloads"]["last_error"] = {"message": "Expected one of [ \\t\\r\\n], \"#\", \"{\" at line 14, column 3"}
        pipelines[spec["id"]] = p

    for pid in IDLE:
        pipelines[pid] = {
            "events": {"in": 0, "filtered": 0, "out": 0, "duration_in_millis": 0, "queue_push_duration_in_millis": 0},
            "flow": {"worker_utilization": _flow(0.0), "queue_backpressure": _flow(0.0)},
            "reloads": {"successes": 2, "failures": 0},
            "queue": {"type": "memory"},
        }

    period = 20.0
    lo, span = (45.0, 30.0) if heavy else (18.0, 26.0)
    heap_pct = int(lo + span * ((e % period) / period))
    heap_max = 8 << 30
    young_rate = 1.4 if heavy else 0.6 + (seed % 3) / 10.0
    young = int(young_rate * (COUNTER_BASE_S + e))
    return {
        "host": "logstash-" + name, "name": "logstash-" + name, "version": "9.3.0",
        "id": str(uuid.UUID(int=seed % (1 << 128))),
        "ephemeral_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "%s-%s" % (name, started))),
        "status": "green", "pipeline": {"workers": 8, "batch_size": 125, "batch_delay": 50},
        "jvm": {
            "threads": {"count": 148 + seed % 5, "peak_count": 228},
            "mem": {"heap_used_percent": heap_pct, "heap_used_in_bytes": heap_pct * heap_max // 100,
                    "heap_max_in_bytes": heap_max, "heap_committed_in_bytes": heap_max},
            "gc": {"collectors": {
                "young": {"collection_count": young, "collection_time_in_millis": int(young * 3.1)},
                "old": {"collection_count": 0, "collection_time_in_millis": 0}}},
            "uptime_in_millis": int((UPTIME_BASE_S + e) * 1000),
        },
        "process": {
            "open_file_descriptors": 204 + seed % 8, "max_file_descriptors": 16384,
            "cpu": {"percent": int(9 + 2 * math.sin(e / 6.0 + phase)),
                    "load_average": {"1m": round(1.1 + 0.2 * math.sin(e / 9.0 + phase), 2),
                                     "5m": round(1.05 + 0.05 * math.sin(e / 30.0), 2), "15m": 1.01}},
        },
        "events": {"in": total_in, "filtered": total_out, "out": total_out, "duration_in_millis": total_dur},
        "flow": {"input_throughput": _flow(sum(s["rin"] for s in PIPELINES) * scale),
                 "output_throughput": _flow(sum(s["rout"] for s in PIPELINES) * scale)},
        "pipelines": pipelines,
        "reloads": {"successes": 0, "failures": 0},
    }


def build_pipelines_info():
    info = {s["id"]: {"workers": s["workers"], "batch_size": s["batch"], "batch_delay": 50} for s in PIPELINES}
    for pid in IDLE:
        info[pid] = {"workers": 2, "batch_size": 125, "batch_delay": 50}
    return {"pipelines": info}


class ThreadingServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(port, name="node-01", heavy=False, flaky=False, bind="127.0.0.1", user=None, password=None):
    started = time.time()
    expected = None
    if user:
        expected = "Basic " + base64.b64encode(("%s:%s" % (user, password or "")).encode()).decode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if expected and self.headers.get("Authorization") != expected:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="logstash"')
                self.end_headers()
                return
            path = self.path.split("?")[0].rstrip("/")
            e = time.time() - started
            if path == "/_node/stats":
                body = build_stats(e, name, heavy, flaky, started)
            elif path == "/_node/pipelines":
                body = build_pipelines_info()
            elif path in ("", "/_node"):
                s = build_stats(e, name, heavy, flaky, started)
                body = {k: s[k] for k in ("host", "name", "version", "id", "ephemeral_id", "status")}
            else:
                self.send_response(404)
                self.end_headers()
                return
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ThreadingServer((bind, port), Handler)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fake Logstash monitoring API for demos and tests")
    ap.add_argument("--port", type=int, default=9601)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--name", default="node-01")
    ap.add_argument("--heavy", action="store_true", help="higher heap and GC activity")
    ap.add_argument("--flaky", action="store_true", help="report a failed pipeline reload")
    a = ap.parse_args(argv)
    srv = make_server(a.port, a.name, a.heavy, a.flaky, a.bind)
    print("mock Logstash API '%s' on http://%s:%d" % (a.name, a.bind, a.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

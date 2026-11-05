#!/usr/bin/env python3
"""
lsdash - a live web dashboard for a fleet of Logstash nodes.

Polls every node's monitoring API, reuses lsmon's rate and findings engine,
keeps a short in-memory history for trend lines, and serves a single page
the whole team can open in a browser. Standard library only.

    lsdash --node node-01=http://10.0.0.11:9600 --node node-02=http://10.0.0.12:9600
    lsdash --config /etc/lsmon/lsdash.json

Binds to 127.0.0.1 by default. Use --bind 0.0.0.0 (plus LSDASH_USER /
LSDASH_PASSWORD, and ideally --tls-cert/--tls-key) to share it with a team.
"""

import argparse
import base64
import hmac
import json
import os
import socketserver
import ssl
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import lsmon  # noqa: E402

VERSION = lsmon.VERSION


# --------------------------------------------------------------------------
# Polling
# --------------------------------------------------------------------------

class Node(object):
    def __init__(self, name, client, maxlen):
        self.name = name
        self.client = client
        self.prev = None
        self.sample = None
        self.error = None
        self.last_ok = None
        self.hist = deque(maxlen=maxlen)


class Dashboard(object):
    def __init__(self, nodes, refresh=2.0, history=60, thresholds=None, cores=None,
                 title="Logstash Monitor", label=""):
        self.refresh = float(refresh)
        self.maxlen = max(2, int(history / self.refresh))
        self.nodes = [Node(name, client, self.maxlen) for name, client in nodes]
        self.th = thresholds or dict(lsmon.DEFAULT_THRESHOLDS)
        self.cores = cores
        self.title = title
        self.label = label
        self.history_s = history
        self.hist = deque(maxlen=self.maxlen)
        self.phist = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=max(1, min(16, len(self.nodes))))

    def _poll_node(self, n):
        try:
            raw = lsmon.collect(n.client)
            sample = lsmon.compute(n.prev, raw, self.th, self.cores)
            with self.lock:
                n.prev, n.sample, n.error, n.last_ok = raw, sample, None, time.time()
                if sample["node_in_per_sec"] is not None:
                    n.hist.append(sample["node_in_per_sec"])
        except Exception as e:  # keep polling the other nodes whatever happens
            with self.lock:
                n.error = str(e)

    def poll_once(self):
        list(self.pool.map(self._poll_node, self.nodes))
        with self.lock:
            live = [n.sample for n in self.nodes if n.sample and not n.error]
            ins = [s["node_in_per_sec"] for s in live if s["node_in_per_sec"] is not None]
            outs = [s["node_out_per_sec"] for s in live if s["node_out_per_sec"] is not None]
            if ins:
                self.hist.append((time.time(), sum(ins), sum(outs)))
                per = {}
                for s in live:
                    for p in s["pipelines"]:
                        per[p["id"]] = per.get(p["id"], 0) + (p["in_per_sec"] or 0)
                for pid, v in per.items():
                    self.phist.setdefault(pid, deque(maxlen=self.maxlen)).append(v)

    def run_forever(self):
        while True:
            t0 = time.time()
            self.poll_once()
            time.sleep(max(0.2, self.refresh - (time.time() - t0)))

    def start(self):
        t = threading.Thread(target=self.run_forever, name="lsdash-poller")
        t.daemon = True
        t.start()
        return t

    def state(self):
        with self.lock:
            return build_state(self)


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

def _mean(vals):
    vals = [v for v in vals if v is not None]
    return sum(vals) / len(vals) if vals else None


def _sum(vals):
    vals = [v for v in vals if v is not None]
    return sum(vals) if vals else None


def build_state(d):
    th = d.th
    now = time.time()
    rank = lsmon.SEVERITY_RANK
    names = [n.name for n in d.nodes]
    nodes_out, attention, by_pipe = [], {}, {}

    def attend(sev, code, scope, msg, node):
        key = (code, scope)
        a = attention.get(key)
        if a is None:
            attention[key] = {"severity": sev, "code": code, "scope": scope, "message": msg, "nodes": [node]}
            return
        if node not in a["nodes"]:
            a["nodes"].append(node)
        if rank[sev] > rank[a["severity"]]:
            a["severity"], a["message"] = sev, msg

    live = [(n, n.sample) for n in d.nodes if n.sample and not n.error]
    total_in = _sum(s["node_in_per_sec"] for _, s in live)

    for idx, n in enumerate(d.nodes):
        if n.error or not n.sample:
            msg = n.error or "waiting for first sample"
            if n.error:
                attend("CRIT", "unreachable", "node", "Node unreachable - " + msg, n.name)
            nodes_out.append({"name": n.name, "index": idx, "status": "CRIT" if n.error else "OK",
                              "down": True, "error": msg,
                              "last_ok_ago": round(now - n.last_ok) if n.last_ok else None})
            continue
        s = n.sample
        warn = crit = 0
        for f in s["findings"]:
            if f["severity"] == "INFO":
                continue
            warn += f["severity"] == "WARN"
            crit += f["severity"] == "CRIT"
            attend(f["severity"], f["code"], f["scope"], f["message"], n.name)
        for p in s["pipelines"]:
            by_pipe.setdefault(p["id"], []).append((idx, p))
        active = [p for p in s["pipelines"] if p["state"] != "idle"]
        active.sort(key=lambda p: -(p["in_per_sec"] or 0))
        nodes_out.append({
            "name": n.name, "index": idx, "down": False, "status": s["overall"],
            "warn": warn, "crit": crit, "host": s["node"]["host"], "version": s["node"]["version"],
            "uptime_s": s["node"]["uptime_s"], "polled_ago": round(now - n.last_ok, 1),
            "in": s["node_in_per_sec"], "out": s["node_out_per_sec"],
            "share": (s["node_in_per_sec"] / total_in * 100) if total_in and s["node_in_per_sec"] is not None else None,
            "history": list(n.hist),
            "heap_pct": s["heap_used_percent"], "heap_used": s["heap_used_bytes"], "heap_max": s["heap_max_bytes"],
            "cpu": s["cpu_percent"], "load_1m": s["load_1m"], "load_5m": s["load_5m"],
            "gc_pct": s["gc_time_percent"], "gc_young": s["gc_young_per_sec"], "gc_young_pause": s["gc_young_pause_ms"],
            "gc_old": s["gc_old_per_sec"], "gc_old_total": s["gc_old_total"],
            "threads": s["threads"], "threads_peak": s["threads_peak"], "fds": s["open_fds"], "max_fds": s["max_fds"],
            "pipelines": [{k: p[k] for k in ("id", "in_per_sec", "out_per_sec", "worker_util", "backpressure",
                                             "queue_type", "queue_pct", "dlq_bytes", "state", "workers", "batch_size")}
                          for p in active],
            "idle": len(s["pipelines"]) - len(active),
        })

    pipelines = []
    for pid, entries in by_pipe.items():
        ps = [p for _, p in entries]
        busy = [p for p in ps if p["state"] != "idle"]
        ins = _sum(p["in_per_sec"] for p in ps)
        outs = _sum(p["out_per_sec"] for p in ps)
        q = max((p for p in ps if p["queue_pct"] is not None), key=lambda p: p["queue_pct"], default=None)
        weighted = [(p["cost_ms_per_event"], p["out_per_sec"]) for p in ps
                    if p["cost_ms_per_event"] is not None and p["out_per_sec"]]
        cost = (sum(c * w for c, w in weighted) / sum(w for _, w in weighted)) if weighted else None
        split = [0.0] * len(names)
        for idx, p in entries:
            split[idx] = p["in_per_sec"] or 0
        util = _mean(p["worker_util"] for p in busy)
        states = set(p["state"] for p in ps)
        state = "active" if "active" in states else "stalled" if "stalled" in states else \
            "quiet" if "quiet" in states else "unknown" if "unknown" in states else "idle"
        sev = "OK"
        for a in attention.values():
            if a["scope"] == "pipeline:" + pid and rank[a["severity"]] > rank[sev]:
                sev = a["severity"]
        pipelines.append({
            "id": pid, "state": state, "severity": sev,
            "workers": ps[0]["workers"], "batch_size": ps[0]["batch_size"],
            "active_nodes": sum(1 for p in ps if p["state"] == "active"), "total_nodes": len(ps),
            "in": ins, "out": outs, "drift": (ins - outs) if ins is not None and outs is not None else None,
            "split": split, "trend": list(d.phist.get(pid, [])),
            "util": util, "headroom": (100.0 / util) if util else None,
            "backpressure": _mean(p["backpressure"] for p in busy),
            "queue_type": "persisted" if any(p["queue_type"] == "persisted" for p in ps) else "memory",
            "queue_pct": q["queue_pct"] if q else None, "queue_trend": q["queue_trend"] if q else None,
            "queue_eta_s": q["queue_eta_s"] if q else None,
            "cost_ms": cost, "dlq_bytes": _sum(p["dlq_bytes"] for p in ps),
            "reloads_ok": sum(p["reloads_ok"] for p in ps), "reloads_failed": sum(p["reloads_failed"] for p in ps),
            "events_in": sum(p["events_in"] for p in ps),
        })
    pipelines.sort(key=lambda p: (p["state"] == "idle", -(p["in"] or 0), p["id"]))

    att = sorted(attention.values(), key=lambda a: (-rank[a["severity"]], a["scope"], a["code"]))
    heaps = [s["heap_used_percent"] for _, s in live if s["heap_used_percent"] is not None]
    statuses = [n["status"] for n in nodes_out]
    return {
        "title": d.title, "label": d.label, "version": VERSION, "refresh_s": d.refresh,
        "history_s": d.history_s, "generated_at": now, "thresholds": th, "node_names": names,
        "kpis": {
            "in": total_in, "out": _sum(s["node_out_per_sec"] for _, s in live),
            "nodes_total": len(d.nodes), "nodes_up": len(live),
            "nodes_warn": statuses.count("WARN"), "nodes_crit": statuses.count("CRIT"),
            "pipelines_total": len(pipelines),
            "pipelines_active": sum(1 for p in pipelines if p["state"] == "active"),
            "pipelines_idle": sum(1 for p in pipelines if p["state"] == "idle"),
            "pipelines_stalled": sum(1 for p in pipelines if p["state"] == "stalled"),
            "findings_warn": sum(1 for a in att if a["severity"] == "WARN"),
            "findings_crit": sum(1 for a in att if a["severity"] == "CRIT"),
            "heap_max": max(heaps) if heaps else None, "heap_avg": _mean(heaps),
            "gc_pct_max": max([s["gc_time_percent"] for _, s in live if s["gc_time_percent"] is not None] or [None],
                              key=lambda v: -1 if v is None else v),
            "es_errors": _sum(s["es_errors"] for _, s in live),
            "dlq_bytes": _sum(p["dlq_bytes"] for p in pipelines),
        },
        "history": [[round(t, 1), i, o] for t, i, o in d.hist],
        "attention": att,
        "pipelines": pipelines,
        "nodes": nodes_out,
    }


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class ThreadingServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(dash, bind="127.0.0.1", port=8600, auth=None, tls_cert=None, tls_key=None):
    expected = None
    if auth:
        expected = "Basic " + base64.b64encode(("%s:%s" % auth).encode("utf-8")).decode("ascii")
    page = (PAGE.replace("__TITLE__", _html_escape(dash.title))
                .replace("__REFRESH_MS__", str(int(dash.refresh * 1000)))).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "lsdash/" + VERSION
        sys_version = ""

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/healthz":
                return self._send(200, b"ok\n", "text/plain")
            if expected:
                got = self.headers.get("Authorization") or ""
                if not hmac.compare_digest(got.encode("utf-8"), expected.encode("utf-8")):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="lsdash"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            if path in ("/", "/index.html"):
                return self._send(200, page, "text/html; charset=utf-8")
            if path == "/api/state":
                return self._send(200, json.dumps(dash.state()).encode("utf-8"), "application/json")
            self._send(404, b"not found\n", "text/plain")

    srv = ThreadingServer((bind, port), Handler)
    if tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_cert, tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def _html_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="lsdash", description="Live web dashboard for a fleet of Logstash nodes.",
        epilog="Logstash API credentials: LS_API_USER / LS_API_PASSWORD. "
               "Dashboard login: LSDASH_USER / LSDASH_PASSWORD.")
    ap.add_argument("--config", help="JSON config file (see examples/lsdash.example.json)")
    ap.add_argument("--node", action="append", default=[], metavar="NAME=URL",
                    help="a Logstash node to poll; repeat for each node")
    ap.add_argument("--bind", help="address to listen on (default 127.0.0.1)")
    ap.add_argument("--port", type=int, help="port to listen on (default 8600)")
    ap.add_argument("--refresh", type=float, help="seconds between polls (default 2)")
    ap.add_argument("--history", type=int, help="seconds of trend history kept in memory (default 60)")
    ap.add_argument("--title", help="page title (default 'Logstash Monitor')")
    ap.add_argument("--label", help="short tag shown next to the title, e.g. a site or cluster name")
    ap.add_argument("--cores", type=int, help="CPU cores per Logstash host, enables the load check")
    ap.add_argument("--thresholds", help="JSON file overriding default thresholds")
    ap.add_argument("--timeout", type=float, default=3.0, help="API timeout per node in seconds")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification for https node URLs")
    ap.add_argument("--ca-cert", help="CA bundle for https node URLs")
    ap.add_argument("--tls-cert", help="serve the dashboard over HTTPS with this certificate")
    ap.add_argument("--tls-key", help="private key for --tls-cert")
    ap.add_argument("--version", action="version", version="lsdash " + VERSION)
    return ap.parse_args(argv)


def load_config(args):
    cfg = {}
    if args.config:
        with open(args.config) as fh:
            cfg = json.load(fh)
    nodes = list(cfg.get("nodes", []))
    for spec in args.node:
        if "=" not in spec:
            raise ValueError("--node must look like NAME=URL, got %r" % spec)
        name, url = spec.split("=", 1)
        nodes.append({"name": name.strip(), "url": url.strip()})
    if not nodes:
        raise ValueError("no nodes configured; use --node NAME=URL or a --config file")
    th = dict(lsmon.DEFAULT_THRESHOLDS)
    if isinstance(cfg.get("thresholds"), dict):
        th.update(cfg["thresholds"])
    elif isinstance(cfg.get("thresholds"), str):
        th = lsmon.load_thresholds(cfg["thresholds"])
    if args.thresholds:
        th = lsmon.load_thresholds(args.thresholds)

    def pick(name, default):
        v = getattr(args, name)
        return v if v is not None else cfg.get(name, default)

    return {
        "nodes": nodes, "thresholds": th,
        "bind": pick("bind", "127.0.0.1"), "port": int(pick("port", 8600)),
        "refresh": float(pick("refresh", 2.0)), "history": int(pick("history", 60)),
        "title": pick("title", "Logstash Monitor"), "label": pick("label", ""),
        "cores": pick("cores", None),
        "tls_cert": pick("tls_cert", None), "tls_key": pick("tls_key", None),
    }


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        cfg = load_config(args)
    except (OSError, ValueError) as e:
        print("lsdash: %s" % e, file=sys.stderr)
        return 2

    clients = []
    for n in cfg["nodes"]:
        user = n.get("user") or os.environ.get("LS_API_USER")
        pw = os.environ.get(n["password_env"]) if n.get("password_env") else os.environ.get("LS_API_PASSWORD")
        clients.append((n["name"], lsmon.Client(n["url"], user, pw, timeout=args.timeout,
                                                insecure=args.insecure, cafile=args.ca_cert)))
    dash = Dashboard(clients, cfg["refresh"], cfg["history"], cfg["thresholds"], cfg["cores"],
                     cfg["title"], cfg["label"])

    auth = None
    if os.environ.get("LSDASH_USER"):
        auth = (os.environ["LSDASH_USER"], os.environ.get("LSDASH_PASSWORD", ""))
    elif cfg["bind"] not in ("127.0.0.1", "localhost", "::1"):
        print("lsdash: warning: listening on %s without a login; set LSDASH_USER and LSDASH_PASSWORD"
              % cfg["bind"], file=sys.stderr)

    try:
        srv = make_server(dash, cfg["bind"], cfg["port"], auth, cfg["tls_cert"], cfg["tls_key"])
    except OSError as e:
        print("lsdash: cannot listen on %s:%s - %s" % (cfg["bind"], cfg["port"], e), file=sys.stderr)
        return 1
    dash.start()
    scheme = "https" if cfg["tls_cert"] else "http"
    print("lsdash %s polling %d node(s) every %ss - open %s://%s:%d/" % (
        VERSION, len(clients), cfg["refresh"], scheme,
        cfg["bind"] if cfg["bind"] != "0.0.0.0" else "<this-host>", cfg["port"]))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# --------------------------------------------------------------------------
# The page (single file: markup, styles and script inline)
# --------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#0f1012;--card:#17181b;--line:#28292e;--t:#e8e8ea;--m:#8b8c92;--soft:#1d1e22;--link:#5b9bff;
 --warn:#f5b31a;--crit:#ef4444;--ok:#22c55e;--tag:#1d2a44;--tagt:#7aa7ff;--warnt:#111}
:root[data-theme=light]{--bg:#f6f7f9;--card:#fff;--line:#e3e5e9;--t:#17181b;--m:#6b6e76;--soft:#eef0f3;--link:#2563eb;
 --warn:#d97706;--crit:#dc2626;--ok:#16a34a;--tag:#e6eefc;--tagt:#2456c5;--warnt:#fff}
*{box-sizing:border-box}html,body{background:var(--bg)}
body{margin:0;color:var(--t);font:14px/1.4 Inter,"Segoe UI",system-ui,-apple-system,Arial,sans-serif;padding:22px}
.mono{font-family:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace}
.m{color:var(--m);font-size:13px}.sub{color:var(--m);font-size:11.5px}
.top{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}.top h1{font-size:20px;margin:0}
.tag{background:var(--tag);color:var(--tagt);font-size:12px;padding:3px 8px;border-radius:6px;font-weight:600}
.right{margin-left:auto;display:flex;gap:10px;align-items:center}
button{background:transparent;color:var(--t);border:1px solid var(--line);padding:6px 12px;border-radius:7px;font:inherit;font-size:13px;cursor:pointer}
button:hover{background:var(--soft)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.kpis{display:grid;grid-template-columns:1.8fr repeat(6,1fr);gap:12px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.big{font-size:28px;font-weight:600;margin:3px 0;font-variant-numeric:tabular-nums}.big small{font-size:14px;color:var(--m);font-weight:400}
.b{font-size:11px;font-weight:700;padding:2px 7px;border-radius:5px;white-space:nowrap}
.bw{color:var(--warnt);background:var(--warn)}.bc{color:#fff;background:var(--crit)}.bo{border:1px solid var(--line);color:var(--ok)}
.att .row{display:flex;gap:14px;align-items:center;padding:9px 0;border-top:1px solid var(--line);flex-wrap:wrap}
.chips{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
.chip{border:1px solid var(--line);border-radius:10px;padding:1px 8px;font-size:12px;color:var(--m)}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th{color:var(--m);font-weight:500;font-size:12px;text-align:right;padding:8px 9px;border-bottom:1px solid var(--line);white-space:nowrap}
th:first-child,td:first-child{text-align:left}td{padding:9px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
.split{display:inline-flex;height:7px;width:110px;gap:2px;vertical-align:middle}.split i{border-radius:2px;min-width:2px}
.bar{height:3px;background:var(--line);margin-top:5px;border-radius:2px}.bar b{display:block;height:3px;background:#3b82f6;border-radius:2px}
.warn{color:var(--warn)}.crit{color:var(--crit)}.good{color:var(--ok)}
.sec{display:flex;align-items:baseline;gap:10px;margin:20px 0 10px}.sec b{font-size:15px}
.nodes{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:12px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line);margin:12px -16px 0}
.stats div{padding:9px 13px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.stats div:nth-child(4n){border-right:0}
.stats b{display:block;font-size:17px;font-weight:600;font-variant-numeric:tabular-nums}
.kpis>.card,.nodes>.card,.att .row>span{min-width:0}.att .row>span{overflow-wrap:anywhere}
table.nt th,table.nt td{padding:8px 6px}table.nt td{font-size:13px}
.link{color:var(--link);font-size:12.5px;cursor:pointer;margin-top:8px;display:inline-block;background:none;border:0;padding:0}
.foot{margin-top:16px;color:var(--m);font-size:12px;display:flex;gap:24px;flex-wrap:wrap}
.empty{padding:30px;text-align:center;color:var(--m)}
@media (max-width:1100px){.kpis{grid-template-columns:repeat(2,1fr)}.kpis .wide{grid-column:span 2}}
@media (max-width:520px){body{padding:16px}.nodes{grid-template-columns:minmax(0,1fr)}.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.right{margin-left:0}.stats{grid-template-columns:repeat(2,1fr)}.stats div:nth-child(2n){border-right:0}}
</style></head>
<body>
<div class="top">
  <span style="color:#3b82f6;font-size:20px">&#8599;</span><h1>__TITLE__</h1><span id="label"></span><span class="m" id="meta"></span>
  <div class="right"><span class="m" id="live"><span class="dot" style="background:var(--m)"></span>connecting…</span>
  <button id="idleBtn">Show idle</button><button id="themeBtn">Light theme</button></div>
</div>
<div id="app"><div class="card empty">Waiting for the first poll…</div></div>
<script>
(function(){
"use strict";
var REFRESH = __REFRESH_MS__;
var COLORS = ["#3b82f6","#e8622c","#16a37a","#a855f7","#eab308","#06b6d4","#ec4899","#84cc16"];
function load(k){try{return window.localStorage.getItem(k);}catch(e){return null;}}
function save(k,v){try{window.localStorage.setItem(k,v);}catch(e){}}
var showIdle = load("lsdash.idle") === "1";
var openIdle = {};
var theme = load("lsdash.theme") || "dark";
var last = null;
function applyTheme(){document.documentElement.setAttribute("data-theme", theme);
  document.getElementById("themeBtn").textContent = theme === "dark" ? "Light theme" : "Dark theme";}
applyTheme();
document.getElementById("themeBtn").onclick = function(){theme = theme === "dark" ? "light" : "dark"; save("lsdash.theme", theme); applyTheme();};
document.getElementById("idleBtn").onclick = function(){showIdle = !showIdle; save("lsdash.idle", showIdle ? "1" : "0"); if (last) render(last);};

function esc(s){return String(s == null ? "" : s).replace(/[&<>"']/g, function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
function num(v,d){if(v == null) return "\u2013"; d = d || 0; return Number(v).toLocaleString("en-US",{minimumFractionDigits:d,maximumFractionDigits:d});}
function cnt(v){if(v == null) return "\u2013"; var a = Math.abs(v);
  if(a >= 1e9) return (v/1e9).toFixed(2)+"B"; if(a >= 1e6) return (v/1e6).toFixed(2)+"M"; if(a >= 1e3) return (v/1e3).toFixed(1)+"K"; return String(Math.round(v));}
function bytes(v){if(v == null) return "\u2013"; var u=["B","K","M","G","T"], i=0; while(v >= 1024 && i < 4){v/=1024;i++;} return (i ? v.toFixed(1) : v)+u[i];}
function dur(s){if(s == null) return "\u2013"; if(s < 90) return Math.round(s)+"s"; if(s < 5400) return Math.round(s/60)+"m"; if(s < 172800) return Math.round(s/3600)+"h"; return Math.round(s/86400)+"d";}
function up(s){var d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60); return d ? d+"d "+h+"h" : h+"h "+m+"m";}
function lvl(v,w,c){if(v == null) return ""; if(c != null && v >= c) return "crit"; if(v >= w) return "warn"; return "";}
function badge(sev,n){if(sev === "CRIT") return '<span class="b bc">&#9650; '+(n ? n+" CRIT" : "CRIT")+'</span>';
  if(sev === "WARN") return '<span class="b bw">&#9650; '+(n ? n+" WARN" : "WARN")+'</span>'; return '<span class="b bo">OK</span>';}
function spark(arr,w,h,color,fluid){
  var sz = fluid ? 'style="width:100%;height:'+h+'px"' : 'width="'+w+'" height="'+h+'"';
  if(!arr || arr.length < 2) return '<svg '+sz+' viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none"></svg>';
  var mx = Math.max.apply(null, arr)*1.15 || 1, st = w/(arr.length-1);
  var pts = arr.map(function(v,i){return (i*st).toFixed(1)+","+(h-(v/mx)*(h-2)-1).toFixed(1);}).join(" ");
  return '<svg '+sz+' viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none"><polygon points="0,'+h+' '+pts+' '+w+','+h+'" fill="'+color+'" opacity=".18"/>'+
    '<polyline points="'+pts+'" fill="none" stroke="'+color+'" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>';}
function chip(name, names){var i = names.indexOf(name); return '<span class="chip"><span class="dot" style="background:'+COLORS[i % COLORS.length]+'"></span>'+esc(name)+'</span>';}
function drift(v){if(v == null) return "\u2013"; if(Math.abs(v) < 0.5) return "0";
  return '<span class="'+(v > 0 ? "warn" : "good")+'">'+(v > 0 ? "+" : "\u2212")+num(Math.abs(v))+'/s</span>';}
function queueCell(p,t){
  if(p.queue_type !== "persisted" || p.queue_pct == null) return '<span class="m">memory</span>';
  var c = lvl(p.queue_pct, t.queue_warn, t.queue_crit); if(p.queue_trend === "filling" && !c) c = "warn";
  var sub = p.queue_trend === "filling" ? "filling \u00b7 full in ~"+dur(p.queue_eta_s) : p.queue_trend === "draining" ? "draining \u00b7 ~"+dur(p.queue_eta_s) : (p.queue_trend || "");
  return '<span class="'+c+'">'+(c ? "&#9650; " : "")+num(p.queue_pct,1)+'%</span><div class="sub">'+esc(sub)+'</div>';}

function render(S){
  last = S;
  var t = S.thresholds, k = S.kpis, names = S.node_names, h = [];
  document.getElementById("label").innerHTML = S.label ? '<span class="tag">'+esc(S.label)+'</span>' : "";
  document.getElementById("meta").textContent = k.nodes_total+" node"+(k.nodes_total === 1 ? "" : "s")+" \u00b7 refresh "+S.refresh_s+"s";
  document.getElementById("idleBtn").textContent = showIdle ? "Hide idle" : "Show idle";

  var hin = S.history.map(function(r){return r[1];});
  var fsev = k.findings_crit ? "crit" : k.findings_warn ? "warn" : "good";
  h.push('<div class="kpis">',
    '<div class="card wide"><div class="m">Events in \u00b7 all nodes</div><div class="big">'+num(k.in)+' <small>/s</small></div>',
    '<div class="m">'+num(k.out)+'/s out \u00b7 trend over '+S.history_s+'s</div><div style="margin-top:6px">'+spark(hin,330,34,"#3b82f6",true)+'</div></div>',
    '<div class="card"><div class="m">Nodes reporting</div><div class="big '+(k.nodes_up < k.nodes_total ? "crit" : "")+'">'+k.nodes_up+' <small>of '+k.nodes_total+'</small></div><div class="m">'+k.nodes_crit+' CRIT \u00b7 '+k.nodes_warn+' WARN</div></div>',
    '<div class="card"><div class="m">Pipelines with traffic</div><div class="big">'+k.pipelines_active+' <small>of '+k.pipelines_total+'</small></div><div class="m">'+k.pipelines_idle+' idle'+(k.pipelines_stalled ? ' \u00b7 <span class="warn">'+k.pipelines_stalled+' stalled</span>' : "")+'</div></div>',
    '<div class="card"><div class="m">Findings</div><div class="big '+fsev+'">'+(k.findings_crit + k.findings_warn ? "&#9650; " : "")+(k.findings_crit + k.findings_warn)+'</div><div class="m">'+k.findings_crit+' critical \u00b7 '+k.findings_warn+' warning</div></div>',
    '<div class="card"><div class="m">JVM heap</div><div class="big">'+num(k.heap_max)+'%</div><div class="m">highest node \u00b7 average '+num(k.heap_avg)+'%</div></div>',
    '<div class="card"><div class="m">GC overhead</div><div class="big '+(lvl(k.gc_pct_max, t.gc_overhead_warn, t.gc_overhead_crit) || "good")+'">'+num(k.gc_pct_max,2)+'%</div><div class="m">worst node \u00b7 warn at '+t.gc_overhead_warn+'%</div></div>',
    '<div class="card"><div class="m">Elasticsearch write errors</div><div class="big '+(k.es_errors ? "crit" : "")+'">'+(k.es_errors == null ? "\u2013" : num(k.es_errors))+'</div><div class="m">last interval \u00b7 DLQ '+bytes(k.dlq_bytes)+'</div></div>',
    '</div>');

  h.push('<div class="card att" style="margin-bottom:14px;padding-bottom:4px"><div style="margin-bottom:8px"><b>Attention</b> <span class="m">'+k.findings_crit+' critical \u00b7 '+k.findings_warn+' warning \u00b7 grouped across nodes</span></div>');
  if(!S.attention.length) h.push('<div class="row"><span class="b bo">OK</span><span>Nothing needs attention right now.</span></div>');
  S.attention.forEach(function(a){
    var scope = a.scope === "node" ? (a.nodes.length === 1 ? a.nodes[0] : "JVM") : a.scope.replace(/^pipeline:/, "");
    h.push('<div class="row">'+badge(a.severity)+'<span class="mono">'+esc(scope)+'</span><span>'+esc(a.message)+'</span><span class="chips">'+a.nodes.map(function(n){return chip(n,names);}).join("")+'</span></div>');
  });
  h.push('</div>');

  var pl = S.pipelines.filter(function(p){return showIdle || p.state !== "idle";});
  var idle = S.pipelines.length - pl.length, maxIn = Math.max.apply(null, S.pipelines.map(function(p){return p.in || 0;}).concat([1]));
  h.push('<div class="card" style="padding:12px 16px"><div style="margin-bottom:4px"><b>Pipelines</b> <span class="m">summed across all nodes, busiest first \u00b7 trend over '+S.history_s+'s</span></div><div class="tw"><table>',
    '<tr><th>Pipeline</th><th>In/s</th><th>Out/s</th><th style="text-align:left">Split by node</th><th style="text-align:left">Trend</th><th>Workers busy</th><th>Headroom</th><th>Backpressure</th><th>Queue</th><th>Drift</th><th>Cost / event</th><th>DLQ</th><th>Reloads ok/fail</th><th>Events in</th></tr>');
  pl.forEach(function(p){
    var tot = p.split.reduce(function(a,b){return a+b;},0);
    var split = tot ? p.split.map(function(v,i){return v ? '<i style="flex:'+v+';background:'+COLORS[i % COLORS.length]+'"></i>' : "";}).join("") : "";
    var flagged = p.state === "stalled" || p.severity !== "OK";
    h.push('<tr><td><span class="mono '+(p.state === "stalled" ? "warn" : "")+'">'+esc(p.id)+'</span><div class="sub">'+(p.workers || "?")+'w \u00d7 '+(p.batch_size || "?")+' \u00b7 '+(p.state === "stalled" ? '<span class="warn">stalled</span> \u00b7 ' : "")+'active on '+p.active_nodes+' of '+p.total_nodes+'</div></td>',
      '<td>'+num(p.in)+'<div class="bar"><b style="width:'+Math.min(100,(p.in || 0)/maxIn*100).toFixed(0)+'%"></b></div></td><td>'+num(p.out)+'</td>',
      '<td style="text-align:left"><span class="split">'+split+'</span></td>',
      '<td style="text-align:left">'+spark(p.trend,110,24,p.severity !== "OK" ? "#f5b31a" : "#3b82f6")+'</td>',
      '<td class="'+lvl(p.util,t.worker_util_warn,t.worker_util_crit)+'">'+(p.util == null ? "\u2013" : num(p.util,1)+"%")+'</td>',
      '<td>'+(p.headroom == null ? "\u2013" : num(p.headroom,1)+"\u00d7")+'</td>',
      '<td class="'+lvl(p.backpressure,t.backpressure_warn,t.backpressure_crit)+'">'+num(p.backpressure,3)+'</td>',
      '<td>'+queueCell(p,t)+'</td><td>'+drift(p.drift)+'</td>',
      '<td>'+(p.cost_ms == null ? "\u2013" : num(p.cost_ms,1)+" ms")+'</td>',
      '<td class="'+(p.dlq_bytes ? "warn" : "")+'">'+(p.dlq_bytes ? bytes(p.dlq_bytes) : "\u2013")+'</td>',
      '<td class="'+(p.reloads_failed ? "crit" : "")+'">'+p.reloads_ok+'/'+p.reloads_failed+'</td>',
      '<td>'+cnt(p.events_in)+'</td></tr>');
  });
  h.push('</table></div>');
  if(idle) h.push('<button class="link" data-act="idle">Show '+idle+' idle pipeline'+(idle === 1 ? "" : "s")+'</button>');
  h.push('</div>');

  h.push('<div class="sec"><b>Nodes</b><span class="m">per-node JVM health \u00b7 pipelines sorted by events in/s</span></div><div class="nodes">');
  S.nodes.forEach(function(n){
    var col = COLORS[n.index % COLORS.length];
    if(n.down){
      h.push('<div class="card"><div style="display:flex;align-items:center"><span class="dot" style="background:'+col+'"></span><b class="mono">'+esc(n.name)+'</b><span style="margin-left:auto">'+badge(n.status)+'</span></div>',
        '<div class="'+(n.status === "CRIT" ? "crit" : "m")+'" style="margin-top:12px">'+esc(n.error)+'</div>',
        '<div class="sub" style="margin-top:6px">'+(n.last_ok_ago != null ? "last good poll "+dur(n.last_ok_ago)+" ago" : "")+'</div></div>');
      return;
    }
    var pressure = (n.gc_young || 0) >= t.gc_young_warn || (n.gc_old || 0) > t.gc_old_warn;
    var heapC = pressure ? lvl(n.heap_pct, t.heap_warn, t.heap_crit) : "";
    var ps = openIdle[n.name] ? n.pipelines : n.pipelines.slice(0, 6), more = n.pipelines.length - ps.length;
    h.push('<div class="card"><div style="display:flex;align-items:center"><span class="dot" style="background:'+col+'"></span><b class="mono">'+esc(n.name)+'</b><span style="margin-left:auto">'+badge(n.status, n.crit || n.warn)+'</span></div>',
      '<div class="sub" style="margin-left:14px">'+esc(n.host || "")+' \u00b7 v'+esc(n.version)+' \u00b7 up '+up(n.uptime_s)+' \u00b7 polled '+num(n.polled_ago,0)+'s ago</div>',
      '<div style="display:flex;gap:14px;align-items:center;margin-top:4px"><div><div class="big">'+num(n.in)+' <small>/s in</small></div><div class="m">'+num(n.out)+'/s out \u00b7 '+num(n.share)+'% of traffic</div></div><div style="flex:1">'+spark(n.history,300,40,col,true)+'</div></div>',
      '<div class="stats">',
      '<div><span class="m">Heap</span><b class="'+heapC+'">'+num(n.heap_pct)+'%</b><span class="sub">'+bytes(n.heap_used)+' of '+bytes(n.heap_max)+'</span></div>',
      '<div><span class="m">CPU (process)</span><b>'+num(n.cpu)+'%</b><span class="sub">Logstash process</span></div>',
      '<div><span class="m">Load 1m</span><b>'+num(n.load_1m,2)+'</b><span class="sub">5m '+num(n.load_5m,2)+'</span></div>',
      '<div><span class="m">GC overhead</span><b class="'+lvl(n.gc_pct,t.gc_overhead_warn,t.gc_overhead_crit)+'">'+num(n.gc_pct,2)+'%</b><span class="sub">of wall clock</span></div>',
      '<div><span class="m">Young GC</span><b class="'+lvl(n.gc_young,t.gc_young_warn)+'">'+num(n.gc_young,2)+'/s</b><span class="sub">pause '+num(n.gc_young_pause,1)+' ms</span></div>',
      '<div><span class="m">Old GC</span><b class="'+((n.gc_old || 0) > t.gc_old_warn ? "warn" : "good")+'">'+num(n.gc_old,3)+'/s</b><span class="sub">'+num(n.gc_old_total)+' total</span></div>',
      '<div><span class="m">Threads</span><b>'+num(n.threads)+'</b><span class="sub">peak '+num(n.threads_peak)+'</span></div>',
      '<div><span class="m">File handles</span><b>'+num(n.fds)+'</b><span class="sub">'+(n.max_fds ? num(n.fds/n.max_fds*100,1) : "\u2013")+'% of '+num(n.max_fds)+'</span></div>',
      '</div><div class="tw"><table class="nt"><tr><th>Pipeline</th><th>In/s</th><th>Out/s</th><th>Busy</th><th>Backpr.</th><th>Queue</th></tr>');
    ps.forEach(function(p){
      h.push('<tr><td><span class="mono '+(p.state === "stalled" ? "warn" : "")+'">'+esc(p.id)+'</span><div class="sub">'+(p.workers || "?")+'w \u00d7 '+(p.batch_size || "?")+(p.dlq_bytes ? ' \u00b7 DLQ '+bytes(p.dlq_bytes) : "")+'</div></td>',
        '<td>'+num(p.in_per_sec)+'</td><td>'+num(p.out_per_sec)+'</td>',
        '<td class="'+lvl(p.worker_util,t.worker_util_warn,t.worker_util_crit)+'">'+(p.worker_util == null ? "\u2013" : num(p.worker_util,1)+"%")+'</td>',
        '<td class="'+lvl(p.backpressure,t.backpressure_warn,t.backpressure_crit)+'">'+num(p.backpressure,3)+'</td>',
        '<td class="'+lvl(p.queue_pct,t.queue_warn,t.queue_crit)+'">'+(p.queue_type === "persisted" && p.queue_pct != null ? num(p.queue_pct,1)+"%" : '<span class="m">memory</span>')+'</td></tr>');
    });
    h.push('</table></div>');
    if(more > 0) h.push('<button class="link" data-act="node" data-node="'+esc(n.name)+'">Show '+more+' more</button>');
    else if(openIdle[n.name]) h.push('<button class="link" data-act="node" data-node="'+esc(n.name)+'">Show less</button>');
    if(n.idle) h.push('<div class="sub" style="margin-top:6px">'+n.idle+' idle pipeline'+(n.idle === 1 ? "" : "s")+' hidden</div>');
    h.push('</div>');
  });
  h.push('</div>');
  h.push('<div class="foot"><span>lsdash '+esc(S.version)+'</span><span>rates are deltas over JVM uptime \u00b7 survive pipeline reloads</span><span>history kept in memory: '+S.history_s+'s</span><span>thresholds shared with lsmon</span></div>');
  document.getElementById("app").innerHTML = h.join("");
}

document.getElementById("app").addEventListener("click", function(e){
  var el = e.target.closest ? e.target.closest("[data-act]") : null; if(!el) return;
  if(el.getAttribute("data-act") === "idle"){showIdle = true; save("lsdash.idle","1");}
  else {var n = el.getAttribute("data-node"); openIdle[n] = !openIdle[n];}
  if(last) render(last);
});

function setLive(ok, ts){
  document.getElementById("live").innerHTML = ok ? '<span class="dot" style="background:var(--ok)"></span>Live \u00b7 '+new Date(ts*1000).toLocaleTimeString([], {hour12:false})
    : '<span class="dot" style="background:var(--crit)"></span>Disconnected \u00b7 retrying';
}
function tick(){
  var x = new XMLHttpRequest(); x.open("GET","api/state",true); x.timeout = Math.max(4000, REFRESH*2);
  x.onload = function(){ if(x.status === 200){ try{ var S = JSON.parse(x.responseText); render(S); setLive(true, S.generated_at);} catch(e){ setLive(false);} } else setLive(false); setTimeout(tick, REFRESH); };
  x.onerror = x.ontimeout = function(){ setLive(false); setTimeout(tick, REFRESH); };
  x.send();
}
tick();
})();
</script>
</body></html>
"""


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
lsmon - a surgical, dependency-free monitor for Logstash pipelines.

Reads the Logstash monitoring API (/_node/stats, /_node/pipelines), turns the
cumulative counters into real per-second rates, and tells you which pipeline
on which node is struggling and why: worker saturation, backpressure,
persisted-queue growth, stalls, reload failures, heap and GC pressure.

Standard library only. Copy one file onto an air-gapped server and run it.

    lsmon                          # one sample (rates appear from the 2nd run)
    lsmon --watch                  # live view, refreshes every 10s
    lsmon --once --quiet --log-file /var/log/lsmon/metrics.jsonl   # for a timer
    lsmon --history 20 --log-file /var/log/lsmon/metrics.jsonl     # recent log

This file is also imported by lsdash.py, the multi-node web dashboard.
"""

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

VERSION = "1.0.0"

DEFAULT_URL = "http://127.0.0.1:9600"

# Thresholds shared by lsmon and lsdash. Override any of them with
# --thresholds FILE (a JSON object with the keys you want to change).
DEFAULT_THRESHOLDS = {
    "heap_warn": 75.0,           # % heap used, only alarming together with GC pressure
    "heap_crit": 85.0,
    "gc_young_warn": 2.0,        # young collections per second
    "gc_old_warn": 0.0,          # old collections per second; healthy is exactly 0
    "gc_old_crit": 1.0,
    "gc_overhead_warn": 5.0,     # % of wall clock spent in GC pauses
    "gc_overhead_crit": 10.0,
    "worker_util_warn": 80.0,    # % of pipeline worker time busy
    "worker_util_crit": 95.0,
    "backpressure_warn": 1.0,    # Logstash queue_backpressure flow metric
    "backpressure_crit": 5.0,
    "queue_warn": 80.0,          # % of persisted queue capacity used
    "queue_crit": 95.0,
    "fd_warn": 80.0,             # % of max file descriptors
    "load_per_core_warn": 1.0,   # 1m load average / cores (needs --cores)
    "stall_seconds": 60,         # zero in and zero out for this long = stalled
}

SEVERITY_RANK = {"OK": 0, "INFO": 1, "WARN": 2, "CRIT": 3}


# --------------------------------------------------------------------------
# Logstash API client
# --------------------------------------------------------------------------

class Client(object):
    """Minimal HTTP(S) client for the Logstash monitoring API.

    Proxy environment variables are ignored on purpose: the Logstash API is
    almost always on the same host or an internal network.
    """

    def __init__(self, url=DEFAULT_URL, user=None, password=None, timeout=5.0,
                 insecure=False, cafile=None):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.auth = None
        if user:
            token = "%s:%s" % (user, password or "")
            self.auth = "Basic " + base64.b64encode(token.encode("utf-8")).decode("ascii")
        handlers = [urllib.request.ProxyHandler({})]
        if self.url.startswith("https"):
            if insecure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                ctx = ssl.create_default_context(cafile=cafile)
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def get(self, path):
        req = urllib.request.Request(self.url + path, headers={
            "Accept": "application/json",
            "User-Agent": "lsmon/" + VERSION,
        })
        if self.auth:
            req.add_header("Authorization", self.auth)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError("HTTP %d from %s%s" % (e.code, self.url, path))
        except urllib.error.URLError as e:
            raise RuntimeError("cannot reach Logstash API at %s (%s)" % (self.url, e.reason))
        except (OSError, ValueError) as e:
            raise RuntimeError("error reading %s%s: %s" % (self.url, path, e))


def client_from_env(url, timeout=5.0, insecure=False, cafile=None):
    """Credentials come from the environment, never the command line."""
    return Client(url, os.environ.get("LS_API_USER"), os.environ.get("LS_API_PASSWORD"),
                  timeout=timeout, insecure=insecure, cafile=cafile)


def collect(client):
    """Take one raw snapshot of a Logstash node."""
    stats = client.get("/_node/stats")
    try:
        info = client.get("/_node/pipelines").get("pipelines") or {}
    except RuntimeError:
        info = {}
    return {"t": time.time(), "stats": stats, "pipelines_info": info}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def dig(d, *keys, **kw):
    default = kw.get("default")
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d if d is not None else default


def flow_value(f):
    """Logstash flow metrics are {current, last_1_minute, lifetime, ...}."""
    if isinstance(f, dict):
        for key in ("current", "last_1_minute", "last_5_minutes", "lifetime"):
            if f.get(key) is not None:
                return float(f[key])
        return None
    if isinstance(f, (int, float)):
        return float(f)
    return None


def load_thresholds(path=None):
    t = dict(DEFAULT_THRESHOLDS)
    if path:
        with open(path) as fh:
            user = json.load(fh)
        unknown = set(user) - set(t)
        if unknown:
            raise ValueError("unknown threshold keys: %s" % ", ".join(sorted(unknown)))
        t.update(user)
    return t


def worst(severities):
    best = "OK"
    for s in severities:
        if SEVERITY_RANK.get(s, 0) > SEVERITY_RANK[best]:
            best = s
    return best


def level(value, warn, crit=None):
    if value is None:
        return "OK"
    if crit is not None and value >= crit:
        return "CRIT"
    if value >= warn:
        return "WARN"
    return "OK"


def _r(v, nd=2):
    return None if v is None else round(v, nd)


# --------------------------------------------------------------------------
# Rate computation and findings
# --------------------------------------------------------------------------

def compute(prev, cur, thresholds=None, cores=None):
    """Turn two raw snapshots into rates and findings.

    Rates are deltas over JVM uptime, not wall clock, so a slow API response
    or a late timer does not distort them. If Logstash restarted between the
    two snapshots, or a pipeline reload reset its counters, the affected rates
    are reported as None for one cycle instead of as nonsense.

    `cur` is annotated in place with `quiet_since` so stall detection can
    span several samples; persist it with the snapshot.
    """
    th = thresholds or DEFAULT_THRESHOLDS
    s = cur["stats"]
    jvm = s.get("jvm") or {}
    proc = s.get("process") or {}
    findings = []

    def find(sev, code, scope, msg):
        findings.append({"severity": sev, "code": code, "scope": scope, "message": msg})

    up_ms = dig(jvm, "uptime_in_millis", default=0)
    restart = False
    dt = None
    ps = None
    if prev:
        ps = prev["stats"]
        prev_up = dig(ps, "jvm", "uptime_in_millis", default=0)
        if up_ms < prev_up or ps.get("ephemeral_id") != s.get("ephemeral_id"):
            restart = True
            ps = None
        else:
            dt = (up_ms - prev_up) / 1000.0
            if dt <= 0:
                ps, dt = None, None
    if restart:
        find("INFO", "restart", "node", "Logstash restarted since the last sample; rates resume next cycle")

    def rate(path_cur, path_prev):
        if ps is None or dt is None or path_cur is None or path_prev is None:
            return None
        d = path_cur - path_prev
        return None if d < 0 else d / dt

    # ---- JVM ----
    gcs = dig(jvm, "gc", "collectors", default={})
    yc, yt = dig(gcs, "young", "collection_count", default=0), dig(gcs, "young", "collection_time_in_millis", default=0)
    oc, ot = dig(gcs, "old", "collection_count", default=0), dig(gcs, "old", "collection_time_in_millis", default=0)
    gc_young = gc_old = gc_pct = young_pause = None
    if ps is not None:
        pg = dig(ps, "jvm", "gc", "collectors", default={})
        pyc, pyt = dig(pg, "young", "collection_count", default=0), dig(pg, "young", "collection_time_in_millis", default=0)
        poc, pot = dig(pg, "old", "collection_count", default=0), dig(pg, "old", "collection_time_in_millis", default=0)
        gc_young = rate(yc, pyc)
        gc_old = rate(oc, poc)
        if yt >= pyt and ot >= pot and dt:
            gc_pct = ((yt - pyt) + (ot - pot)) / (dt * 1000.0) * 100.0
        if yc > pyc:
            young_pause = (yt - pyt) / float(yc - pyc)

    heap_pct = dig(jvm, "mem", "heap_used_percent")
    heap_used = dig(jvm, "mem", "heap_used_in_bytes")
    heap_max = dig(jvm, "mem", "heap_max_in_bytes")
    cpu_pct = dig(proc, "cpu", "percent")
    load = dig(proc, "cpu", "load_average", default={}) or {}
    fds, max_fds = dig(proc, "open_file_descriptors"), dig(proc, "max_file_descriptors")

    gc_pressure = (gc_young is not None and gc_young >= th["gc_young_warn"]) or \
                  (gc_old is not None and gc_old > th["gc_old_warn"])
    if heap_pct is not None and heap_pct >= th["heap_warn"]:
        if gc_pressure:
            sev = "CRIT" if heap_pct >= th["heap_crit"] else "WARN"
            find(sev, "heap", "node", "Heap %d%% with GC pressure - heap is likely undersized" % heap_pct)
        else:
            find("INFO", "heap", "node", "Heap %d%% but GC is calm - normal G1 fill, no action" % heap_pct)
    if gc_young is not None and gc_young >= th["gc_young_warn"]:
        find("WARN", "gc_young", "node", "Young GC %.2f/s (warn %.1f/s) - heavy heap churn" % (gc_young, th["gc_young_warn"]))
    if gc_old is not None and gc_old > th["gc_old_warn"]:
        find("CRIT" if gc_old >= th["gc_old_crit"] else "WARN", "gc_old", "node",
             "Old GC %.3f/s - premature promotion, heap too small" % gc_old)
    if gc_pct is not None and gc_pct >= th["gc_overhead_warn"]:
        find(level(gc_pct, th["gc_overhead_warn"], th["gc_overhead_crit"]), "gc_overhead", "node",
             "%.1f%% of wall clock spent in GC pauses" % gc_pct)
    if fds and max_fds:
        fd_pct = fds * 100.0 / max_fds
        if fd_pct >= th["fd_warn"]:
            find("WARN", "fds", "node", "File descriptors at %.0f%% (%d of %d)" % (fd_pct, fds, max_fds))
    if cores and load.get("1m") is not None and load["1m"] / float(cores) >= th["load_per_core_warn"]:
        find("WARN", "load", "node", "Load %.2f on %d cores" % (load["1m"], cores))

    # ---- Node events ----
    node_in = rate(dig(s, "events", "in"), dig(ps, "events", "in") if ps else None)
    node_out = rate(dig(s, "events", "out"), dig(ps, "events", "out") if ps else None)

    # ---- Pipelines ----
    quiet_prev = (prev or {}).get("quiet_since", {}) if not restart else {}
    quiet_now = {}
    pipelines = []
    es_errors_total = 0
    es_errors_seen = False
    info = cur.get("pipelines_info") or {}
    for pid, p in sorted((s.get("pipelines") or {}).items()):
        ev = p.get("events") or {}
        pp = dig(ps, "pipelines", pid) if ps else None
        pev = (pp or {}).get("events") or {}
        reset = bool(pp) and (ev.get("in", 0) < pev.get("in", 0) or ev.get("out", 0) < pev.get("out", 0))
        usable = bool(pp) and not reset and dt
        in_ps = rate(ev.get("in"), pev.get("in")) if usable else None
        out_ps = rate(ev.get("out"), pev.get("out")) if usable else None
        cost = None
        if usable and ev.get("out", 0) > pev.get("out", 0):
            cost = (ev.get("duration_in_millis", 0) - pev.get("duration_in_millis", 0)) / float(ev["out"] - pev["out"])
            cost = cost if cost >= 0 else None

        flow = p.get("flow") or {}
        util = flow_value(flow.get("worker_utilization"))
        bp = flow_value(flow.get("queue_backpressure"))
        headroom = (100.0 / util) if util else None

        q = p.get("queue") or {}
        qtype = q.get("type", "memory")
        q_pct = q_events = q_bytes = q_max = q_eta = None
        q_trend = None
        if qtype == "persisted":
            q_bytes = q.get("queue_size_in_bytes", dig(q, "capacity", "queue_size_in_bytes"))
            q_max = q.get("max_queue_size_in_bytes", dig(q, "capacity", "max_queue_size_in_bytes"))
            q_events = q.get("events_count", q.get("events"))
            if q_bytes is not None and q_max:
                q_pct = q_bytes * 100.0 / q_max
            # Prefer Logstash's own smoothed growth flow metrics (8.5+); fall
            # back to deltas between our samples on older versions.
            ev_rate = flow_value(flow.get("queue_persisted_growth_events"))
            b_rate = flow_value(flow.get("queue_persisted_growth_bytes"))
            if usable and (ev_rate is None or b_rate is None):
                pq = pp.get("queue") or {}
                pq_events = pq.get("events_count", pq.get("events"))
                pq_bytes = pq.get("queue_size_in_bytes", dig(pq, "capacity", "queue_size_in_bytes"))
                if ev_rate is None and q_events is not None and pq_events is not None:
                    ev_rate = (q_events - pq_events) / dt
                if b_rate is None and q_bytes is not None and pq_bytes is not None:
                    b_rate = (q_bytes - pq_bytes) / dt
            if ev_rate is not None:
                noise = max(1.0, 0.02 * (in_ps or 0))
                if ev_rate > noise:
                    q_trend = "filling"
                    if b_rate and b_rate > 0 and q_max:
                        q_eta = max(0.0, (q_max - q_bytes) / b_rate)
                elif ev_rate < -noise:
                    q_trend = "draining"
                    if q_events:
                        q_eta = q_events / -ev_rate
                else:
                    q_trend = "steady"

        dlq = dig(p, "dead_letter_queue", "queue_size_in_bytes")
        rl_ok = dig(p, "reloads", "successes", default=0)
        rl_fail = dig(p, "reloads", "failures", default=0)
        last_err = dig(p, "reloads", "last_error", "message")

        es_err = None
        for out in dig(p, "plugins", "outputs", default=[]) or []:
            if out.get("name") == "elasticsearch":
                cur_err = dig(out, "documents", "non_retryable_failures", default=0) + \
                    dig(out, "bulk_requests", "with_errors", default=0)
                prev_err = None
                if usable:
                    for po in dig(pp, "plugins", "outputs", default=[]) or []:
                        if po.get("id") == out.get("id"):
                            prev_err = dig(po, "documents", "non_retryable_failures", default=0) + \
                                dig(po, "bulk_requests", "with_errors", default=0)
                if prev_err is not None and cur_err >= prev_err:
                    es_err = (es_err or 0) + (cur_err - prev_err)
        if es_err is not None:
            es_errors_seen = True
            es_errors_total += es_err

        lifetime_in = ev.get("in", 0)
        if lifetime_in == 0 and ev.get("out", 0) == 0:
            state = "idle"
        elif in_ps is None:
            state = "unknown"
        elif in_ps == 0 and out_ps == 0:
            since = quiet_prev.get(pid, cur["t"] - (dt or 0))
            quiet_now[pid] = since
            state = "stalled" if cur["t"] - since >= th["stall_seconds"] else "quiet"
        else:
            state = "active"

        pinfo = info.get(pid) or {}
        workers = pinfo.get("workers") or dig(p, "pipeline", "workers")
        batch = pinfo.get("batch_size") or dig(p, "pipeline", "batch_size")

        scope = "pipeline:" + pid
        if reset:
            find("INFO", "counter_reset", scope, "Counters reset (pipeline reload); rates resume next cycle")
        if state == "stalled":
            find("WARN", "stalled", scope, "No events in or out for %ds - stalled?" % int(cur["t"] - quiet_now[pid]))
        if util is not None and util >= th["worker_util_warn"] and state != "idle":
            find(level(util, th["worker_util_warn"], th["worker_util_crit"]), "worker_util", scope,
                 "Workers %.1f%% busy - add workers before adding hardware" % util)
        if bp is not None and bp >= th["backpressure_warn"]:
            find(level(bp, th["backpressure_warn"], th["backpressure_crit"]), "backpressure", scope,
                 "Backpressure %.2f - inputs are waiting on the queue" % bp)
        if q_pct is not None and q_pct >= th["queue_warn"]:
            find(level(q_pct, th["queue_warn"], th["queue_crit"]), "queue", scope,
                 "Persisted queue %.0f%% full%s" % (q_pct, ", still filling" if q_trend == "filling" else ""))
        elif q_trend == "filling" and q_eta is not None and q_eta < 3600:
            find("WARN", "queue_filling", scope,
                 "Persisted queue %.0f%% and filling - full in %s" % (q_pct or 0, fmt_duration(q_eta)))
        if rl_fail:
            find("WARN", "reload_failures", scope,
                 "%d reload failure%s since start%s" % (rl_fail, "s" if rl_fail != 1 else "",
                                                        (": " + last_err[:120]) if last_err else ""))
        if es_err:
            find("WARN", "es_errors", scope, "%d Elasticsearch write error%s this interval" % (es_err, "s" if es_err != 1 else ""))

        pipelines.append({
            "id": pid, "state": state, "workers": workers, "batch_size": batch,
            "in_per_sec": _r(in_ps, 1), "out_per_sec": _r(out_ps, 1),
            "drift_per_sec": _r(in_ps - out_ps, 1) if in_ps is not None and out_ps is not None else None,
            "worker_util": _r(util, 1), "headroom": _r(headroom, 1), "backpressure": _r(bp, 3),
            "cost_ms_per_event": _r(cost, 2),
            "queue_type": qtype, "queue_pct": _r(q_pct, 1), "queue_events": q_events,
            "queue_bytes": q_bytes, "queue_max_bytes": q_max, "queue_trend": q_trend, "queue_eta_s": _r(q_eta, 0),
            "dlq_bytes": dlq, "events_in": lifetime_in, "events_out": ev.get("out", 0),
            "reloads_ok": rl_ok, "reloads_failed": rl_fail, "es_errors": es_err,
        })

    cur["quiet_since"] = quiet_now
    overall = worst(f["severity"] for f in findings if f["severity"] != "INFO")
    return {
        "timestamp": datetime.fromtimestamp(cur["t"], timezone.utc).isoformat(timespec="seconds"),
        "lsmon_version": VERSION,
        "node": {
            "name": s.get("name"), "host": s.get("host"), "version": s.get("version"),
            "id": s.get("id"), "status": s.get("status"), "uptime_s": int(up_ms / 1000),
        },
        "interval_s": _r(dt, 1), "restart_detected": restart, "overall": overall,
        "heap_used_percent": heap_pct, "heap_used_bytes": heap_used, "heap_max_bytes": heap_max,
        "gc_young_per_sec": _r(gc_young, 2), "gc_old_per_sec": _r(gc_old, 3),
        "gc_young_pause_ms": _r(young_pause, 1), "gc_old_total": oc, "gc_time_percent": _r(gc_pct, 2),
        "threads": dig(jvm, "threads", "count"), "threads_peak": dig(jvm, "threads", "peak_count"),
        "cpu_percent": cpu_pct, "load_1m": load.get("1m"), "load_5m": load.get("5m"), "load_15m": load.get("15m"),
        "open_fds": fds, "max_fds": max_fds,
        "node_in_per_sec": _r(node_in, 1), "node_out_per_sec": _r(node_out, 1),
        "es_errors": es_errors_total if es_errors_seen else None,
        "pipelines": pipelines,
        "findings": findings,
    }


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------

def fmt_num(v, nd=0, dash="-"):
    if v is None:
        return dash
    return ("{:,.%df}" % nd).format(v)


def fmt_count(v):
    if v is None:
        return "-"
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(v) >= div:
            return "%.2f%s" % (v / div, suf)
    return str(int(v))


def fmt_bytes(v):
    if v is None:
        return "-"
    for div, suf in ((1 << 40, "T"), (1 << 30, "G"), (1 << 20, "M"), (1 << 10, "K")):
        if v >= div:
            return "%.1f%s" % (v / float(div), suf)
    return "%dB" % v


def fmt_drift(v):
    if v is None:
        return "-"
    return "0" if abs(v) < 0.5 else "%+.0f" % v


def fmt_duration(sec):
    if sec is None:
        return "-"
    sec = int(sec)
    if sec < 90:
        return "%ds" % sec
    if sec < 5400:
        return "%dm" % round(sec / 60.0)
    if sec < 172800:
        return "%dh" % round(sec / 3600.0)
    return "%dd" % round(sec / 86400.0)


def fmt_uptime(sec):
    d, rem = divmod(int(sec or 0), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return "%dd %dh" % (d, h) if d else "%dh %dm" % (h, m)


class Palette(object):
    def __init__(self, enabled):
        self.on = enabled

    def c(self, text, code):
        return "\033[%sm%s\033[0m" % (code, text) if self.on else text

    def sev(self, text, severity):
        return self.c(text, {"CRIT": "31;1", "WARN": "33", "INFO": "36", "OK": "32"}.get(severity, "0"))

    def dim(self, text):
        return self.c(text, "2")

    def bold(self, text):
        return self.c(text, "1")


def render(sample, th, pal, show_all=False):
    """Render one computed sample as a terminal report."""
    out = []
    n = sample["node"]
    out.append("%s · %s · v%s · up %s · overall %s" % (
        pal.bold("lsmon"), n.get("name") or n.get("host") or "?", n.get("version") or "?",
        fmt_uptime(n.get("uptime_s")), pal.sev(sample["overall"], sample["overall"])))
    if sample["interval_s"] is None:
        out.append(pal.dim("first sample or restart - rates appear on the next run"))
    out.append("")

    hp, gy, go, gp = sample["heap_used_percent"], sample["gc_young_per_sec"], sample["gc_old_per_sec"], sample["gc_time_percent"]
    pressure = (gy or 0) >= th["gc_young_warn"] or (go or 0) > th["gc_old_warn"]
    heap_sev = level(hp, th["heap_warn"], th["heap_crit"]) if pressure else ("INFO" if (hp or 0) >= th["heap_warn"] else "OK")
    heap_txt = "%s%%" % fmt_num(hp)
    if sample["heap_used_bytes"] and sample["heap_max_bytes"]:
        heap_txt += " %s/%s" % (fmt_bytes(sample["heap_used_bytes"]), fmt_bytes(sample["heap_max_bytes"]))
    out.append("%s   heap %s   young GC %s/s   old GC %s/s   GC overhead %s" % (
        pal.dim("NODE"), pal.sev(heap_txt, heap_sev),
        pal.sev(fmt_num(gy, 2), level(gy, th["gc_young_warn"])),
        pal.sev(fmt_num(go, 3), "WARN" if (go or 0) > th["gc_old_warn"] else "OK"),
        pal.sev(fmt_num(gp, 2) + "%", level(gp, th["gc_overhead_warn"], th["gc_overhead_crit"]))))
    out.append("       cpu %s%%   load %s %s %s   threads %s   fds %s/%s   in %s/s   out %s/s" % (
        fmt_num(sample["cpu_percent"]), fmt_num(sample["load_1m"], 2), fmt_num(sample["load_5m"], 2),
        fmt_num(sample["load_15m"], 2), fmt_num(sample["threads"]), fmt_num(sample["open_fds"]),
        fmt_num(sample["max_fds"]), fmt_num(sample["node_in_per_sec"]), fmt_num(sample["node_out_per_sec"])))
    out.append("")

    cols = [("PIPELINE", 26, "<"), ("IN/SEC", 9, ">"), ("OUT/SEC", 9, ">"), ("UTIL%", 7, ">"),
            ("BACKPR", 8, ">"), ("QUEUE%", 8, ">"), ("DRIFT", 8, ">"), ("COST", 8, ">"),
            ("EVENTS IN", 11, ">"), ("RELOAD", 8, ">")]
    out.append(pal.dim("".join(("{:%s%d}" % (a, w)).format(h) for h, w, a in cols)))
    shown = [p for p in sample["pipelines"] if show_all or p["state"] != "idle"]
    shown.sort(key=lambda p: -(p["in_per_sec"] or 0))
    for p in shown:
        pid = p["id"] if len(p["id"]) < 25 else p["id"][:23] + "…"
        cells = [
            (pid, "OK"),
            (fmt_num(p["in_per_sec"]), "OK"),
            (fmt_num(p["out_per_sec"]), "OK"),
            (fmt_num(p["worker_util"], 1), level(p["worker_util"], th["worker_util_warn"], th["worker_util_crit"])),
            (fmt_num(p["backpressure"], 3), level(p["backpressure"], th["backpressure_warn"], th["backpressure_crit"])),
            ((fmt_num(p["queue_pct"]) + "%") if p["queue_pct"] is not None else "mem" if p["queue_type"] == "memory" else "-",
             level(p["queue_pct"], th["queue_warn"], th["queue_crit"]) if p["queue_trend"] != "filling" else "WARN"),
            (fmt_drift(p["drift_per_sec"]),
             "WARN" if (p["drift_per_sec"] or 0) > 0.5 else ("GOOD" if (p["drift_per_sec"] or 0) < -0.5 else "OK")),
            ((fmt_num(p["cost_ms_per_event"], 1) + "ms") if p["cost_ms_per_event"] is not None else "-", "OK"),
            (fmt_count(p["events_in"]), "OK"),
            ("%d/%d" % (p["reloads_ok"], p["reloads_failed"]), "WARN" if p["reloads_failed"] else "OK"),
        ]
        if p["state"] == "stalled":
            cells[0] = (cells[0][0], "WARN")
        line = ""
        for (txt, sev), (_, w, a) in zip(cells, cols):
            padded = ("{:%s%d}" % (a, w)).format(txt)
            if sev in ("WARN", "CRIT"):
                line += pal.sev(padded, sev)
            elif sev == "GOOD":
                line += pal.sev(padded, "OK")
            else:
                line += padded
        out.append(line)
    hidden = len(sample["pipelines"]) - len(shown)
    if hidden:
        out.append(pal.dim("+ %d idle pipeline%s (use --all)" % (hidden, "s" if hidden != 1 else "")))

    out.append("")
    if sample["findings"]:
        out.append(pal.dim("FINDINGS"))
        order = sorted(sample["findings"], key=lambda f: -SEVERITY_RANK[f["severity"]])
        for f in order:
            out.append("%s [%s] %s" % (pal.sev("{:<5}".format(f["severity"]), f["severity"]), f["scope"], f["message"]))
    else:
        out.append(pal.sev("No findings - all pipelines and the JVM look healthy", "OK"))
    return "\n".join(out)


# --------------------------------------------------------------------------
# State and log files
# --------------------------------------------------------------------------

def default_state_file(url):
    h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    uid = os.getuid() if hasattr(os, "getuid") else 0
    return os.path.join(tempfile.gettempdir(), "lsmon-%s-%s.json" % (uid, h))


def read_state(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def write_state(path, raw):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(raw, fh)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def append_log(path, record):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")


def show_history(path, n, pal):
    try:
        with open(path) as fh:
            lines = fh.readlines()[-n:]
    except OSError as e:
        print("cannot read %s: %s" % (path, e), file=sys.stderr)
        return 2
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        try:
            ts = datetime.fromisoformat(d["timestamp"]).astimezone().strftime("%m-%d %H:%M:%S")
        except (KeyError, ValueError):
            ts = "?"
        if d.get("error"):
            print("%s  %s  %s" % (pal.dim(ts), pal.sev("CRIT ", "CRIT"), d["error"]))
            continue
        print("%s  %s  heap=%s%%  gc/s=%s  gc%%=%s  in/s=%s  out/s=%s  findings=%d" % (
            pal.dim(ts), pal.sev("{:<5}".format(d.get("overall", "?")), d.get("overall", "OK")),
            fmt_num(d.get("heap_used_percent")), fmt_num(d.get("gc_young_per_sec"), 2),
            fmt_num(d.get("gc_time_percent"), 2), fmt_num(d.get("node_in_per_sec")),
            fmt_num(d.get("node_out_per_sec")), len(d.get("findings") or [])))
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="lsmon",
        description="Surgical, dependency-free monitor for Logstash pipelines.",
        epilog="API credentials, if needed, are read from LS_API_USER and LS_API_PASSWORD.")
    ap.add_argument("--url", default=os.environ.get("LSMON_URL", DEFAULT_URL),
                    help="Logstash API base URL (default %(default)s)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="take one sample and exit (default)")
    mode.add_argument("--watch", action="store_true", help="refresh continuously")
    mode.add_argument("--history", type=int, metavar="N", help="print the last N records of --log-file and exit")
    ap.add_argument("--interval", type=float, default=10.0, help="seconds between refreshes in --watch (default 10)")
    ap.add_argument("--cores", type=int, help="CPU cores on the Logstash host, enables the load check")
    ap.add_argument("--state-file", help="where --once keeps the previous snapshot (default: temp dir)")
    ap.add_argument("--log-file", help="append each sample as one JSON line to this file")
    ap.add_argument("--thresholds", help="JSON file overriding default thresholds")
    ap.add_argument("--json", action="store_true", help="print the computed sample as JSON")
    ap.add_argument("--quiet", action="store_true", help="print nothing (for timers; use with --log-file)")
    ap.add_argument("--all", action="store_true", help="include idle pipelines")
    ap.add_argument("--no-color", action="store_true", help="disable colours (also honours NO_COLOR)")
    ap.add_argument("--timeout", type=float, default=5.0, help="API timeout in seconds")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification for an https API")
    ap.add_argument("--ca-cert", help="CA bundle for an https API")
    ap.add_argument("--nagios", action="store_true", help="exit 0/1/2/3 for OK/WARN/CRIT/unreachable")
    ap.add_argument("--version", action="version", version="lsmon " + VERSION)
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    pal = Palette(not args.no_color and not os.environ.get("NO_COLOR") and sys.stdout.isatty())
    try:
        th = load_thresholds(args.thresholds)
    except (OSError, ValueError) as e:
        print("lsmon: bad thresholds file: %s" % e, file=sys.stderr)
        return 2

    if args.history is not None:
        if not args.log_file:
            print("lsmon: --history needs --log-file", file=sys.stderr)
            return 2
        return show_history(args.log_file, args.history, pal)

    client = client_from_env(args.url, args.timeout, args.insecure, args.ca_cert)

    if args.watch:
        prev = None
        try:
            while True:
                try:
                    raw = collect(client)
                    sample = compute(prev, raw, th, args.cores)
                    prev = raw
                    body = json.dumps(sample, indent=2) if args.json else render(sample, th, pal, args.all)
                    if args.log_file:
                        append_log(args.log_file, sample)
                except RuntimeError as e:
                    body = pal.sev("CRIT  %s" % e, "CRIT")
                if sys.stdout.isatty():
                    sys.stdout.write("\033[H\033[2J")
                print(body)
                print(pal.dim("\nrefresh %ss · %s · Ctrl-C to quit" % (
                    fmt_num(args.interval, 0), datetime.now().strftime("%H:%M:%S"))))
                sys.stdout.flush()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0

    state_file = args.state_file or default_state_file(args.url)
    prev = read_state(state_file)
    try:
        raw = collect(client)
    except RuntimeError as e:
        if args.log_file:
            append_log(args.log_file, {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "overall": "CRIT", "error": str(e), "findings": [],
            })
        if not args.quiet:
            print("lsmon: %s" % e, file=sys.stderr)
        return 3 if args.nagios else 1
    if prev and prev.get("url") != args.url:
        prev = None
    sample = compute(prev, raw, th, args.cores)
    raw["url"] = args.url
    try:
        write_state(state_file, raw)
    except OSError as e:
        print("lsmon: warning: could not persist state to %s: %s" % (state_file, e), file=sys.stderr)
    if args.log_file:
        append_log(args.log_file, sample)
    if not args.quiet:
        print(json.dumps(sample, indent=2) if args.json else render(sample, th, pal, args.all))
    if args.nagios:
        return {"OK": 0, "WARN": 1, "CRIT": 2}.get(sample["overall"], 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

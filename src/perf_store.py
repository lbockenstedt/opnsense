"""Firewall performance history: counters to rates, 5-minute averages, 7 days on disk.

The spoke samples the firewall about once a minute (``OpnSpoke._perf_sample_tick``).
Interface byte and packet counters only ever grow, so each sample is turned
into a rate against the previous one (``counter_rates``). ``PerfAverager``
averages the rates and gauges (CPU, memory, states) into 5-minute buckets, and
``PerfStore`` keeps 7 days of those buckets in one JSON file. The hub gets a
copy of every bucket (``STORAGE_PERF_SAMPLE``) and asks the spoke for other
ranges (``OPNSENSE_GET_PERF_HISTORY``). Same design as the TrueNAS spoke.
Standard library only.
"""
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List

logger = logging.getLogger("OpnPerfStore")

BUCKET_S = 300
KEEP_S = 7 * 86400
DATA_DIR = os.getenv("LM_OPNSENSE_DATA_DIR", "/var/lib/lm-opnsense")

# Counter name in a sample -> metric suffix and multiplier (bytes -> bits).
_COUNTERS = (("in_bytes", "in_bps", 8), ("out_bytes", "out_bps", 8),
             ("in_pkts", "in_pps", 1), ("out_pkts", "out_pps", 1),
             ("in_errs", "in_errps", 1), ("out_errs", "out_errps", 1))


def counter_rates(prev: Dict[str, Any], cur: Dict[str, Any]) -> Dict[str, float]:
    """Per-second rates between two counter samples.

    A sample is ``{"time": epoch, "interfaces": {name: {"in_bytes": n, ...}}}``.
    Returns totals (``in_bps``, ``out_bps``, ``in_pps``, ``out_pps``,
    ``errps``) plus ``if:<name>:<in|out>_<bps|pps>`` per interface. An interface whose
    counter went down (a reboot or counter reset) or that is missing from the
    previous sample is left out of this interval.
    """
    # No usable interval: no rates.
    seconds = (cur or {}).get("time", 0) - (prev or {}).get("time", 0)
    if not prev or seconds <= 0:
        return {}
    out: Dict[str, float] = {}
    before = prev.get("interfaces") or {}
    for name, now in (cur.get("interfaces") or {}).items():
        old = before.get(name)
        if not old:
            continue
        # Only counters both samples have; a drop means the counter was reset.
        deltas = {field: now[field] - old[field] for field, _, _ in _COUNTERS
                  if field in now and field in old}
        if not deltas or any(d < 0 for d in deltas.values()):
            continue
        for field, metric, scale in _COUNTERS:
            if field not in deltas:
                continue
            rate = round(deltas[field] * scale / seconds, 2)
            # Errors are kept as one firewall-wide total to keep the file small.
            if metric.endswith("errps"):
                out["errps"] = round(out.get("errps", 0) + rate, 2)
                continue
            out[f"if:{name}:{metric}"] = rate
            out[metric] = round(out.get(metric, 0) + rate, 2)
    return out


class PerfAverager:
    """Running sums for the current 5-minute bucket, per device."""

    def __init__(self):
        """Start with no open buckets."""
        # device -> (bucket start, {metric: [sum, count]})
        self._open: Dict[str, tuple] = {}
        self._closed: List[Dict[str, Any]] = []

    def add(self, device_id: str, metrics: Dict[str, float], now: float) -> None:
        """Add one sample to the device's current 5-minute bucket."""
        bucket = int(now // BUCKET_S) * BUCKET_S
        cur = self._open.get(device_id)
        if cur and cur[0] != bucket:
            self._close(device_id)
        _, sums = self._open.setdefault(device_id, (bucket, {}))
        for k, v in metrics.items():
            s = sums.setdefault(k, [0.0, 0])
            s[0] += v
            s[1] += 1

    def close_finished(self, now: float) -> List[Dict[str, Any]]:
        """Averages of every bucket that has ended, as
        ``{device_id, ts, samples, metrics}``."""
        current = int(now // BUCKET_S) * BUCKET_S
        for device_id in [d for d, (b, _) in self._open.items() if b < current]:
            self._close(device_id)
        closed, self._closed = self._closed, []
        return closed

    def _close(self, device_id: str) -> None:
        """Turn the device's open bucket into an average (empty buckets are dropped)."""
        bucket, sums = self._open.pop(device_id)
        if not sums:
            return
        self._closed.append({
            "device_id": device_id, "ts": bucket,
            "samples": max(n for _, n in sums.values()),
            "metrics": {k: round(s / n, 2) for k, (s, n) in sums.items()},
        })


class PerfStore:
    """``{device_id: [{ts, samples, metrics, sent}]}`` (oldest first), saved to
    ``perf.json`` after every change. ``sent`` marks buckets the hub has, so
    buckets made while the hub was unreachable are sent later."""

    def __init__(self, path: str = None):
        """Use ``path`` or ``$LM_OPNSENSE_DATA_DIR/perf.json``; read lazily."""
        self.path = path or os.path.join(DATA_DIR, "perf.json")
        self._lock = threading.Lock()
        self._series = None

    def _load(self) -> Dict[str, List[Dict[str, Any]]]:
        """The series, read from disk the first time (empty if missing or unreadable)."""
        if self._series is None:
            try:
                with open(self.path, encoding="utf-8") as f:
                    data = json.load(f)
                self._series = {k: v for k, v in data.items() if isinstance(v, list)} \
                    if isinstance(data, dict) else {}
            except FileNotFoundError:
                self._series = {}
            except (OSError, ValueError) as e:
                logger.warning("perf store %s unreadable (%s); starting empty", self.path, e)
                self._series = {}
        return self._series

    def _save(self) -> None:
        """Write atomically; on failure keep the data in memory and warn."""
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._series, f, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as e:
            logger.warning("perf store %s not saved: %s", self.path, e)

    def add(self, rows: List[Dict[str, Any]], now: float = None) -> None:
        """Save closed buckets (unsent) and drop anything older than 7 days."""
        now = time.time() if now is None else now
        with self._lock:
            series = self._load()
            for r in rows:
                by_ts = {x["ts"]: x for x in series.get(r["device_id"], [])}
                by_ts[int(r["ts"])] = {"ts": int(r["ts"]), "samples": r.get("samples"),
                                       "metrics": r["metrics"], "sent": False}
                series[r["device_id"]] = [by_ts[t] for t in sorted(by_ts)]
            for device_id in list(series):
                series[device_id] = [x for x in series[device_id] if x["ts"] >= now - KEEP_S]
                if not series[device_id]:
                    del series[device_id]
            self._save()

    def unsent(self, limit: int = 2000) -> List[Dict[str, Any]]:
        """Oldest buckets the hub hasn't received yet."""
        with self._lock:
            rows = [{"device_id": d, "ts": x["ts"], "samples": x["samples"], "metrics": x["metrics"]}
                    for d, xs in self._load().items() for x in xs if not x.get("sent")]
        return sorted(rows, key=lambda r: r["ts"])[:limit]

    def mark_sent(self, rows: List[Dict[str, Any]]) -> None:
        """Record that the hub received these buckets."""
        keys = {(r["device_id"], int(r["ts"])) for r in rows}
        with self._lock:
            for d, xs in self._load().items():
                for x in xs:
                    if (d, x["ts"]) in keys:
                        x["sent"] = True
            self._save()

    def history(self, device_id: str, start: float, end: float) -> List[Dict[str, Any]]:
        """The device's buckets with ``start <= ts <= end``, oldest first."""
        with self._lock:
            return [{"ts": x["ts"], "samples": x["samples"], "metrics": x["metrics"]}
                    for x in self._load().get(device_id, []) if start <= x["ts"] <= end]

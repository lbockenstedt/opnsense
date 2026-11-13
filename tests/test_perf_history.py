"""Firewall performance history: counter-to-rate conversion, 7-day store,
the OPNSENSE_GET_PERF_HISTORY command and the push to the hub."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from opn_spoke import OpnSpoke  # noqa: E402
from opn_perf_store import PerfStore, counter_rates  # noqa: E402

NOW = 1_800_000_000


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _counters(t, wan_in, wan_out, lan_in=0):
    return {"time": t, "interfaces": {
        "WAN": {"in_bytes": wan_in, "out_bytes": wan_out, "in_pkts": wan_in // 100,
                "out_pkts": wan_out // 100, "in_errs": 0, "out_errs": 0},
        "LAN": {"in_bytes": lan_in, "out_bytes": 0}}}


def test_counter_rates_and_reset():
    first = _counters(NOW, 1000, 2000)
    second = _counters(NOW + 10, 2000, 6000, lan_in=500)
    rates = counter_rates(first, second)
    assert rates["if:WAN:in_bps"] == 800 and rates["if:WAN:out_bps"] == 3200
    assert rates["if:WAN:in_pps"] == 1 and rates["if:LAN:in_bps"] == 400
    assert rates["in_bps"] == 1200 and rates["errps"] == 0
    # The WAN counters went down (reboot): WAN is skipped, LAN still counts.
    third = _counters(NOW + 20, 10, 10, lan_in=1500)
    rates = counter_rates(second, third)
    assert "if:WAN:in_bps" not in rates and rates["in_bps"] == 800
    # No previous sample, or no time passed: no rates.
    assert counter_rates(None, first) == {} and counter_rates(first, first) == {}
    # A gap (missed samples) gives no rate rather than one averaged over the gap.
    assert counter_rates(first, _counters(NOW + 600, 9000, 9000)) == {}


def test_store_prunes_after_7_days_and_serves_a_range(tmp_path):
    store = PerfStore(str(tmp_path / "perf.json"))
    store.add([{"device_id": "fw", "ts": NOW - 8 * 86400, "samples": 5, "metrics": {"cpu": 1}},
               {"device_id": "fw", "ts": NOW - 600, "samples": 5, "metrics": {"cpu": 2}},
               {"device_id": "fw", "ts": NOW - 300, "samples": 5, "metrics": {"cpu": 3}}], now=NOW)
    again = PerfStore(str(tmp_path / "perf.json"))
    assert [r["metrics"]["cpu"] for r in again.history("fw", 0, NOW)] == [2, 3]
    assert [r["ts"] for r in again.history("fw", NOW - 400, NOW)] == [NOW - 300]


class _Hub:
    def __init__(self):
        self._hub_ws = object()
        self.sent = []

    async def send_to_hub(self, kind, data):
        self.sent.append((kind, data))
        return True


def _spoke(tmp_path):
    spoke = OpnSpoke("spoke-1", {"id": "fw-1", "host": "fw", "api_key": "k", "api_secret": "s"})
    spoke.perf_store = PerfStore(str(tmp_path / "perf.json"))
    samples = [{"time": NOW + i * 60, "interfaces": _counters(0, 1000 * i, 0)["interfaces"],
                "metrics": {"cpu": 10.0 * i, "states": 100}} for i in range(7)]

    async def fake_sample():
        return {"status": "SUCCESS", "data": samples.pop(0)}
    spoke.engine.get_perf_sample = fake_sample
    return spoke


def test_tick_averages_stores_and_pushes_to_the_hub(tmp_path):
    spoke = _spoke(tmp_path)
    hub = spoke.control_plane = _Hub()
    start = (NOW // 300) * 300 + 300
    for i in range(7):
        _run(spoke._perf_sample_tick(start + i * 60))
    # Minutes 0-4 made one 5-minute bucket; minute 5 closed it.
    kind, data = hub.sent[0]
    assert kind == "STORAGE_PERF_SAMPLE" and data["module"] == "opnsense"
    row = data["samples"][0]
    assert row["device_id"] == "fw-1" and row["ts"] == start
    assert row["metrics"]["cpu"] == 20.0 and row["metrics"]["states"] == 100
    # The first sample has no rate yet; the others moved 1000 bytes a minute.
    assert row["metrics"]["if:WAN:in_bps"] == round(1000 * 8 / 60, 2)
    assert spoke.perf_store.unsent() == []
    # The history command reads the spoke's own copy.
    res = _run(spoke.handle_command("OPNSENSE_GET_PERF_HISTORY", {"start": start, "end": start + 1}))
    assert res["status"] == "SUCCESS" and [r["ts"] for r in res["data"]] == [start]


def test_tick_keeps_buckets_unsent_while_the_hub_is_away(tmp_path):
    spoke = _spoke(tmp_path)
    start = (NOW // 300) * 300 + 300
    for i in range(6):
        _run(spoke._perf_sample_tick(start + i * 60))
    assert [r["ts"] for r in spoke.perf_store.unsent()] == [start]


def test_tick_marks_sent_only_on_a_confirmed_send_and_keeps_good_counters(tmp_path):
    spoke = _spoke(tmp_path)
    hub = spoke.control_plane = _Hub()

    async def unconfirmed(kind, data):
        hub.sent.append((kind, data))
    hub.send_to_hub = unconfirmed
    start = (NOW // 300) * 300 + 300
    for i in range(6):
        _run(spoke._perf_sample_tick(start + i * 60))
    assert hub.sent and [r["ts"] for r in spoke.perf_store.unsent()] == [start]
    # A sample with no interface counters keeps the previous counters.
    good = spoke._default.perf_prev

    async def no_traffic():
        return {"status": "SUCCESS", "data": {"time": NOW, "interfaces": {}, "metrics": {"cpu": 1}}}
    spoke.engine.get_perf_sample = no_traffic
    _run(spoke._perf_sample_tick(start + 360))
    assert spoke._default.perf_prev is good


def test_engine_perf_sample_reads_counters_and_gauges():
    from opnsense_engine import OpnsenseEngine
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")
    replies = {
        "/api/diagnostics/traffic/interface": {"time": NOW, "interfaces": {"wan": {
            "name": "WAN", "bytes received": "100", "bytes transmitted": 200,
            "packets received": 3, "packets transmitted": 4,
            "input errors": 0, "output errors": 1}}},
        "/api/diagnostics/system/system_resources": {"memory": {"total": "8000", "used": 2000}},
        "/api/diagnostics/activity/get_activity": {"headers": ["CPU: 1.0% user, 95.0% idle"]},
        "/api/diagnostics/firewall/pf_states": {"current": "42", "limit": "1000"},
    }

    async def fake_request(method, endpoint, data=None):
        return replies[endpoint]
    eng._request = fake_request
    data = _run(eng.get_perf_sample())["data"]
    assert data["time"] == NOW and data["metrics"] == {"cpu": 5.0, "mem": 25.0, "states": 42.0}
    assert data["interfaces"]["WAN"] == {"in_bytes": 100, "out_bytes": 200, "in_pkts": 3,
                                         "out_pkts": 4, "in_errs": 0, "out_errs": 1}
    # Replies that are empty or say "failed" are not data, nor is a row without counters.
    replies["/api/diagnostics/traffic/interface"]["interfaces"]["lan"] = {"name": "LAN", "x": "?"}
    assert "LAN" not in _run(eng.get_perf_sample())["data"]["interfaces"]
    replies.update({k: {"result": "failed"} for k in list(replies)[:2]})
    replies.update({k: {} for k in list(replies)[2:]})
    assert _run(eng.get_perf_sample())["status"] == "ERROR"


def test_store_is_opnsense_own_when_another_role_loaded_perf_store_first(monkeypatch):
    """An agent hosting several roles imports them into one process, so a
    flat module name another role loaded first (truenas had a perf_store)
    would be reused and firewall averages written to that role's file."""
    import importlib
    import types
    other = types.ModuleType("perf_store")
    other.PerfStore = other.PerfAverager = type("OtherRoleStore", (), {})
    other.counter_rates = lambda prev, cur: {}
    monkeypatch.setitem(sys.modules, "perf_store", other)
    monkeypatch.delitem(sys.modules, "opn_spoke", raising=False)
    spoke_module = importlib.import_module("opn_spoke")
    assert spoke_module.PerfStore.__module__ == "opn_perf_store"
    assert spoke_module.PerfAverager.__module__ == "opn_perf_store"

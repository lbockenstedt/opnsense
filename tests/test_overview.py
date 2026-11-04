"""Tests for OpnsenseEngine.get_overview (OPNSENSE_GET_OVERVIEW, the
firewall module's Overview tab)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from opnsense_engine import OpnsenseEngine  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _engine(responses):
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")
    traffic = list(responses.pop("traffic"))

    async def fake_request(method, endpoint, data=None):
        if endpoint == "/api/diagnostics/traffic/interface":
            return traffic.pop(0)
        return responses.get(endpoint, {"status": "ERROR", "message": "HTTP 403"})

    eng._request = fake_request
    return eng


def test_overview_builds_dashboard_snapshot():
    eng = _engine({
        "/api/diagnostics/system/system_information": {
            "name": "fw01.lab", "versions": ["OPNsense 25.7-amd64", "FreeBSD 14.3"]},
        "/api/diagnostics/system/system_time": {"uptime": "3 days 04:00:00", "loadavg": "0.1, 0.2, 0.3"},
        "/api/diagnostics/system/system_resources": {"memory": {"total": "8000", "used": 2000}},
        "/api/diagnostics/activity/get_activity": {"headers": [
            "last pid: 1;  load averages: 0.1",
            "CPU:  2.0% user,  0.0% nice,  1.5% system,  0.5% interrupt, 96.0% idle"]},
        "/api/routes/gateway/status": {"items": [
            {"name": "WAN_DHCP", "address": "1.2.3.1", "status": "none",
             "status_translated": "Online", "delay": "4.1 ms", "loss": "0.0 %"},
            {"name": "WAN2", "address": "5.6.7.1", "status": "down",
             "status_translated": "Offline", "delay": "~", "loss": "100 %"}]},
        "traffic": [
            {"time": 100.0, "interfaces": {"wan": {"name": "WAN", "bytes received": "1000",
                                                   "bytes transmitted": "500"}}},
            {"time": 102.0, "interfaces": {"wan": {"name": "WAN", "bytes received": "3000",
                                                   "bytes transmitted": "1500"}}},
        ],
    })
    res = _run(eng.get_overview())
    assert res["status"] == "SUCCESS"
    data = res["data"]
    assert data["hostname"] == "fw01.lab"
    assert data["version"] == "OPNsense 25.7-amd64"
    assert data["uptime"] == "3 days 04:00:00"
    assert data["cpu_percent"] == 4.0
    assert data["memory"] == {"used": 2000.0, "total": 8000.0, "percent": 25.0}
    assert [g["online"] for g in data["gateways"]] == [True, False]
    assert data["interfaces"] == [{"name": "WAN", "in_bps": 8000, "out_bps": 4000}]


def test_overview_section_failure_is_blank_not_fatal():
    eng = _engine({
        "/api/diagnostics/system/system_time": {"uptime": "1 day", "loadavg": "0"},
        "traffic": [{"status": "ERROR"}, {"status": "ERROR"}],
    })
    res = _run(eng.get_overview())
    assert res["status"] == "SUCCESS"
    assert res["data"]["uptime"] == "1 day"
    assert res["data"]["gateways"] == [] and res["data"]["interfaces"] == []
    assert res["data"]["cpu_percent"] is None


def test_overview_unreachable_firewall_is_error():
    eng = _engine({"traffic": [{"status": "ERROR"}, {"status": "ERROR"}]})
    assert _run(eng.get_overview())["status"] == "ERROR"

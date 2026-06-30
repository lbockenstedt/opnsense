"""Tests for OpnsenseEngine.get_arp_table (OPNSENSE_GET_ARP_TABLE source for
the firewall→NetBox discovery sync).

Self-contained: inserts src/ on sys.path and uses the flat imports the spoke
uses itself, so it runs without a package install.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from opnsense_engine import OpnsenseEngine  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_engine(monkey_rows):
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")

    async def fake_request(method, endpoint, data=None):
        assert method == "GET"
        assert endpoint == "/api/diagnostics/interface/search_arp"
        return {"rows": monkey_rows}

    eng._request = fake_request
    return eng


def test_get_arp_table_normalizes_rows():
    eng = _make_engine([
        {"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "ws-05", "intf": "lan"},
        {"ip": "10.0.0.6", "mac": "11:22:33:44:55:66", "hostname": "", "interface": "opt1"},
    ])
    res = _run(eng.get_arp_table())
    assert res["status"] == "SUCCESS"
    assert res["data"] == [
        {"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "ws-05", "interface": "lan"},
        {"ip": "10.0.0.6", "mac": "11:22:33:44:55:66", "hostname": "unknown", "interface": "opt1"},
    ]


def test_get_arp_table_drops_empty_rows_and_keeps_raw_mac():
    # A row with neither ip nor mac is dropped; the MAC is returned raw (the
    # hub/netbox normalize it — the spoke is a thin reader).
    eng = _make_engine([
        {"ip": "10.0.0.7", "mac": "AA-BB-CC-DD-EE-FF"},  # raw, non-colon, no hostname/intf
        {"ip": "", "mac": "", "hostname": "ghost"},      # dropped
    ])
    res = _run(eng.get_arp_table())
    assert res["status"] == "SUCCESS"
    assert res["data"] == [
        {"ip": "10.0.0.7", "mac": "AA-BB-CC-DD-EE-FF", "hostname": "unknown", "interface": ""},
    ]


def test_get_arp_table_handles_missing_rows_key():
    # Some OPNsense versions return the list under a different key; fall back to
    # an empty list rather than crashing.
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")

    async def fake_request(method, endpoint, data=None):
        return {"status": "ok"}  # no "rows"

    eng._request = fake_request
    res = _run(eng.get_arp_table())
    assert res["status"] == "SUCCESS"
    assert res["data"] == []


def test_get_dhcp_leases_limit_param_uncapped():
    # limit<=0 disables the cap so the discovery sync gets the full lease set.
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")

    async def fake_request(method, endpoint, data=None):
        rows = [{"address": f"10.0.0.{i}", "hostname": f"h{i}", "hwaddr": f"aa:bb:cc:dd:ee:{i:02x}"}
                for i in range(250)]
        return {"rows": rows}

    eng._request = fake_request
    # Default (interactive path) caps at 200.
    capped = _run(eng.get_dhcp_leases())
    assert len(capped["data"]) == 200
    # Sync path: limit=0 returns all 250.
    full = _run(eng.get_dhcp_leases(limit=0))
    assert len(full["data"]) == 250
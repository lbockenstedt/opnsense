"""Tests for OpnsenseEngine.get_dhcp_leases.

Locks in:
  * dict-keyed `rows` are flattened (not silently dropped → empty);
  * a non-dict / error response surfaces as ERROR (not silent empty);
  * the lease field mapping (address→ip, hwaddr→mac, hostname, expire).

Self-contained: inserts src/ on sys.path, flat imports, no package install.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from opnsense_engine import OpnsenseEngine  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_engine(ret):
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")

    async def fake_request(method, endpoint, data=None):
        assert endpoint == "/api/kea/leases4/search"
        return ret

    eng._request = fake_request
    return eng


def test_dhcp_leases_map_fields():
    eng = _make_engine({"rows": [
        {"address": "10.0.0.5", "hwaddr": "AA:BB:CC:DD:EE:FF",
         "hostname": "ws-05", "expire": 1735680000},
        {"address": "10.0.0.6", "hwaddr": "11:22:33:44:55:66",
         "hostname": "", "expire": 0},
    ]})
    res = _run(eng.get_dhcp_leases())
    assert res["status"] == "SUCCESS"
    assert res["data"] == [
        {"ip": "10.0.0.5", "hostname": "ws-05", "mac": "AA:BB:CC:DD:EE:FF",
         "lease_end": "1735680000"},
        {"ip": "10.0.0.6", "hostname": "unknown", "mac": "11:22:33:44:55:66",
         "lease_end": "unknown"},
    ]


def test_dhcp_leases_flatten_dict_keyed_rows():
    """Kea may return rows keyed by address (a dict) — must not become empty."""
    eng = _make_engine({"rows": {
        "10.0.0.5": {"address": "10.0.0.5", "hwaddr": "AA:BB:CC:DD:EE:FF",
                     "hostname": "ws-05", "expire": 0},
    }})
    res = _run(eng.get_dhcp_leases())
    assert res["status"] == "SUCCESS"
    assert len(res["data"]) == 1
    assert res["data"][0]["ip"] == "10.0.0.5"


def test_dhcp_leases_empty_is_success():
    eng = _make_engine({"rows": []})
    res = _run(eng.get_dhcp_leases())
    assert res["status"] == "SUCCESS"
    assert res["data"] == []


def test_dhcp_leases_no_rows_key_is_success_empty():
    eng = _make_engine({"total": 0, "rowCount": 0})
    res = _run(eng.get_dhcp_leases())
    assert res["status"] == "SUCCESS"
    assert res["data"] == []


def test_dhcp_leases_non_dict_response_is_error():
    eng = _make_engine("not json")
    res = _run(eng.get_dhcp_leases())
    assert res["status"] == "ERROR"
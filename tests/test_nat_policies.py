"""Tests for OpnsenseEngine.get_nat_policies.

Locks in two fixes:
  * the 1:1 controller is probed as `one_to_one` (not the non-existent
    `nat_1to1`);
  * a total probe failure (every endpoint errors — e.g. OPNsense < 26.1 with no
    MVC NAT API, or an API key lacking Firewall: NAT scope) surfaces as a loud
    ERROR instead of degrading to SUCCESS+empty (which rendered as
    "No NAT Policies found" with no reason).

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


def _make_engine(responses):
    """``responses`` maps the probed endpoint URL → returned dict. Captures the
    exact URLs the engine probes so a wrong controller name fails the test."""
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")
    probed = []

    async def fake_request(method, endpoint, data=None):
        # The engine appends ?show_all=1 to GET probes — record + key on base.
        base = endpoint.split("?", 1)[0]
        probed.append(base)
        return responses.get(base, {"status": "ERROR", "message": "not found"})

    eng._request = fake_request
    return eng, probed


def test_probes_one_to_one_controller_not_nat_1to1():
    eng, probed = _make_engine({
        "/api/firewall/d_nat/search_rule": {"rows": []},
        "/api/firewall/source_nat/search_rule": {"rows": []},
        "/api/firewall/one_to_one/search_rule": {"rows": []},
    })
    res = _run(eng.get_nat_policies())
    assert res["status"] == "SUCCESS"
    assert "/api/firewall/one_to_one/search_rule" in probed
    assert not any("nat_1to1" in p for p in probed)


def test_all_endpoints_error_surfaces_loud_error():
    eng, _ = _make_engine({
        "/api/firewall/d_nat/search_rule": {"status": "ERROR", "message": "404 Not Found"},
        "/api/firewall/source_nat/search_rule": {"status": "ERROR", "message": "404 Not Found"},
        "/api/firewall/one_to_one/search_rule": {"status": "ERROR", "message": "404 Not Found"},
    })
    res = _run(eng.get_nat_policies())
    # The whole point: not a silent SUCCESS+empty.
    assert res["status"] == "ERROR"
    assert "26.1" in res["message"]
    assert "404 Not Found" in res["message"]


def test_partial_failure_returns_rules_plus_warning():
    eng, _ = _make_engine({
        "/api/firewall/d_nat/search_rule": {"rows": [
            {"uuid": "u1", "protocol": "TCP", "target": "10.0.0.5",
             "destination.network": "203.0.113.1", "destination.port": "443",
             "local-port": "8443", "descr": "fwd"},
        ]},
        "/api/firewall/source_nat/search_rule": {"status": "ERROR", "message": "denied"},
        "/api/firewall/one_to_one/search_rule": {"rows": []},
    })
    res = _run(eng.get_nat_policies())
    assert res["status"] == "SUCCESS"
    assert len(res["data"]) == 1
    assert res["data"][0]["internal_ip"] == "10.0.0.5"
    assert res["data"][0]["type"] == "Destination NAT"
    assert "warnings" in res
    assert any("Outbound NAT" in w and "denied" in w for w in res["warnings"])


def test_dict_keyed_rules_are_flattened():
    """OPNsense sometimes returns rules keyed by uuid (a dict, not a list)."""
    eng, _ = _make_engine({
        "/api/firewall/d_nat/search_rule": {"rows": {
            "u1": {"protocol": "TCP", "target": "10.0.0.5",
                   "destination.network": "203.0.113.1", "destination.port": "443",
                   "local-port": "8443", "descr": "fwd"},
        }},
        "/api/firewall/source_nat/search_rule": {"rows": []},
        "/api/firewall/one_to_one/search_rule": {"rows": []},
    })
    res = _run(eng.get_nat_policies())
    assert res["status"] == "SUCCESS"
    assert len(res["data"]) == 1
    assert res["data"][0]["id"] == "u1"


def test_all_empty_valid_responses_stay_success():
    eng, _ = _make_engine({
        "/api/firewall/d_nat/search_rule": {"rows": []},
        "/api/firewall/source_nat/search_rule": {"rows": []},
        "/api/firewall/one_to_one/search_rule": {"rows": []},
    })
    res = _run(eng.get_nat_policies())
    assert res["status"] == "SUCCESS"
    assert res["data"] == []
    # No warnings when nothing actually errored.
    assert res.get("warnings") is None
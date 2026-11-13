"""Tests for several firewalls bound to one OPNsense spoke.

The hub names the firewall a command is for with ``firewall_id``; before this
every command (impairments included) went to the first firewall pushed.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from opn_spoke import OpnSpoke  # noqa: E402

FW1 = {"id": "fw-1", "opn_host": "10.0.0.5", "opn_port": 443, "api_key": "k1", "api_secret": "s1"}
FW2 = {"id": "fw-2", "host": "10.0.0.6", "port": 443, "api_key": "k2", "api_secret": "s2"}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _spoke():
    spoke = OpnSpoke("spoke-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {**FW1, "firewalls": [FW1, FW2]}))
    return spoke


def _record_calls(spoke):
    """Replace each engine's system-health read with one that records the host."""
    calls = []
    for fw in spoke._all_targets():
        async def health(host=fw.engine.host):
            calls.append(host)
            return {"status": "SUCCESS", "data": {"host": host}}
        fw.engine.get_system_health = health
    return calls


def test_firewall_id_selects_the_matching_firewall():
    spoke = _spoke()
    calls = _record_calls(spoke)
    res = _run(spoke.handle_command("GET_SYSTEM_HEALTH", {"firewall_id": "fw-2"}))
    assert calls == ["10.0.0.6:443"]
    assert res["data"]["host"] == "10.0.0.6:443"


def test_no_firewall_id_uses_the_default_firewall():
    spoke = _spoke()
    calls = _record_calls(spoke)
    _run(spoke.handle_command("GET_SYSTEM_HEALTH", {}))
    spoke._default.cache.clear()  # force the second read to go live
    _run(spoke.handle_command("GET_SYSTEM_HEALTH", {"firewall_id": "fw-1"}))
    assert calls == ["10.0.0.5:443", "10.0.0.5:443"]


def test_unknown_firewall_id_is_an_error_not_another_box():
    spoke = _spoke()
    calls = _record_calls(spoke)
    res = _run(spoke.handle_command("OPNSENSE_ADD_IMPAIRMENT", {"firewall_id": "fw-9", "target": "10.1.1.1"}))
    assert res["status"] == "ERROR" and "fw-9" in res["message"]
    assert calls == []


def test_each_firewall_has_its_own_cache():
    spoke = _spoke()
    _record_calls(spoke)
    _run(spoke.handle_command("GET_SYSTEM_HEALTH", {"firewall_id": "fw-1"}))
    _run(spoke.handle_command("GET_SYSTEM_HEALTH", {"firewall_id": "fw-2"}))
    assert spoke._default.cache["GET_SYSTEM_HEALTH"]["data"]["host"] == "10.0.0.5:443"
    assert spoke._targets["fw-2"].cache["GET_SYSTEM_HEALTH"]["data"]["host"] == "10.0.0.6:443"


def test_firewall_list_update_keeps_unchanged_targets_and_drops_removed_ones():
    spoke = _spoke()
    target = spoke._targets["fw-2"]
    # A partial update without the list leaves the targets alone.
    _run(spoke.handle_command("UPDATE_CONFIG", {"refresh_interval": 60}))
    assert spoke._targets["fw-2"] is target
    # Same address and credentials: the target (and its cache) is kept.
    _run(spoke.handle_command("UPDATE_CONFIG", {**FW1, "firewalls": [FW1, FW2]}))
    assert spoke._targets["fw-2"] is target
    # New credentials: a fresh target.
    _run(spoke.handle_command("UPDATE_CONFIG", {**FW1, "firewalls": [FW1, {**FW2, "api_key": "k3"}]}))
    assert spoke._targets["fw-2"] is not target
    assert spoke._targets["fw-2"].engine.api_key == "k3"
    # Removed from the hub: commands for it now fail.
    _run(spoke.handle_command("UPDATE_CONFIG", {**FW1, "firewalls": [FW1]}))
    assert spoke._targets == {}
    res = _run(spoke.handle_command("GET_SYSTEM_HEALTH", {"firewall_id": "fw-2"}))
    assert res["status"] == "ERROR"


def test_default_cache_is_dropped_when_its_address_changes():
    spoke = _spoke()
    _record_calls(spoke)
    _run(spoke.handle_command("GET_SYSTEM_HEALTH", {}))
    assert spoke._default.cache
    _run(spoke.handle_command("UPDATE_CONFIG", {"opn_host": "10.0.0.7"}))
    assert spoke._default.cache == {}


def test_empty_list_without_a_default_clears_every_firewall():
    """The hub unbound the last firewall: the spoke forgets every box and its
    credentials instead of keeping the old connection."""
    spoke = _spoke()
    _run(spoke.handle_command("UPDATE_CONFIG", {"firewalls": []}))
    assert spoke._targets == {} and spoke._default.id is None
    assert (spoke.engine.host, spoke.engine.api_key, spoke.engine.api_secret) == (None, None, None)
    assert _run(spoke.handle_command("GET_SYSTEM_HEALTH", {"firewall_id": "fw-2"}))["status"] == "ERROR"

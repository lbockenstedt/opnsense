"""Tests for OpnsenseEngine alias category handling.

Locks in the fix for the empty Category column: OPNsense tags aliases with
category *UUIDs* (the alias model field ``categories`` + an injected
``categories_uuid`` array) and exposes no ``category`` name field. The old
``get_all_aliases`` read ``row.get("category")`` — a key the API never returns —
so every alias rendered an empty Category. The fix resolves the UUIDs to names
via ``/api/firewall/alias/listCategories``. The write path (add/edit) is also
fixed to send ``categories`` (UUIDs) instead of ``category`` (a name string the
API silently ignored).

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
    """``responses`` maps the endpoint URL (no query) → returned dict. Captures
    every URL + body the engine calls so a wrong field/key fails the test."""
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")
    calls = []

    async def fake_request(method, endpoint, data=None):
        base = endpoint.split("?", 1)[0]
        calls.append({"method": method, "endpoint": base, "data": data})
        return responses.get(base, {"status": "ERROR", "message": "not found"})

    eng._request = fake_request
    return eng, calls


def test_get_aliases_resolves_category_uuids_to_names():
    eng, calls = _make_engine({
        "/api/firewall/alias/listCategories": {"rows": [
            {"uuid": "cat-1", "name": "Servers"},
            {"uuid": "cat-2", "name": "Guests"},
        ]},
        "/api/firewall/alias/searchItem": {"rows": [
            {"uuid": "a1", "name": "srv_net", "type": "network",
             "content": "10.0.0.0/24", "categories_uuid": ["cat-1"]},
            {"uuid": "a2", "name": "guest_hosts", "type": "host",
             "content": "192.168.5.5", "categories": "cat-2,cat-1"},
            {"uuid": "a3", "name": "untagged", "type": "host",
             "content": "1.2.3.4"},
        ]},
    })
    res = _run(eng.get_all_aliases())
    assert res["status"] == "SUCCESS"
    by_id = {r["id"]: r["category"] for r in res["data"]}
    assert by_id["a1"] == "Servers"
    # comma-separated UUID string resolves, order preserved
    assert by_id["a2"] == "Guests, Servers"
    # no categories → empty (not 'None' or 'unknown')
    assert by_id["a3"] == ""
    # listCategories is fetched before searchItem
    endpoints = [c["endpoint"] for c in calls]
    assert endpoints.index("/api/firewall/alias/listCategories") < \
           endpoints.index("/api/firewall/alias/searchItem")


def test_get_aliases_empty_category_map_is_safe():
    """If listCategories fails, categories just render empty — no crash."""
    eng, _ = _make_engine({
        "/api/firewall/alias/listCategories": {"status": "ERROR", "message": "denied"},
        "/api/firewall/alias/searchItem": {"rows": [
            {"uuid": "a1", "name": "x", "type": "host", "content": "1.1.1.1",
             "categories_uuid": ["cat-1"]}]},
    })
    res = _run(eng.get_all_aliases())
    assert res["status"] == "SUCCESS"
    assert res["data"][0]["category"] == ""


def test_add_alias_sends_categories_uuids_not_category_name():
    eng, calls = _make_engine({
        "/api/firewall/alias/listCategories": {"rows": [
            {"uuid": "cat-1", "name": "Servers"}]},
        "/api/firewall/alias/addItem": {"status": "success"},
        "/api/firewall/alias/reconfigure": {"status": "success"},
    })
    _run(eng.add_alias("srv_net", "network", "10.0.0.0/24", "d", "Servers"))
    add_call = next(c for c in calls if c["endpoint"].endswith("/addItem"))
    alias = add_call["data"]["alias"]
    # The model field is `categories` (UUID CSV), not `category` (name).
    assert "category" not in alias
    assert alias["categories"] == "cat-1"
    assert alias["name"] == "srv_net"


def test_add_alias_unknown_category_name_is_dropped():
    """A name that isn't an existing OPNsense category can't be assigned (UUID-
    referenced) — drop it rather than sending a name the API ignores."""
    eng, calls = _make_engine({
        "/api/firewall/alias/listCategories": {"rows": [
            {"uuid": "cat-1", "name": "Servers"}]},
        "/api/firewall/alias/addItem": {"status": "success"},
        "/api/firewall/alias/reconfigure": {"status": "success"},
    })
    _run(eng.add_alias("x", "host", "1.1.1.1", "", "Nonexistent, Servers"))
    add_call = next(c for c in calls if c["endpoint"].endswith("/addItem"))
    # Nonexistent dropped, Servers kept.
    assert add_call["data"]["alias"]["categories"] == "cat-1"


def test_edit_alias_empty_category_clears():
    eng, calls = _make_engine({
        "/api/firewall/alias/listCategories": {"rows": []},
        "/api/firewall/alias/setItem/abc": {"status": "success"},
        "/api/firewall/alias/reconfigure": {"status": "success"},
    })
    _run(eng.edit_alias("abc", "x", "host", "1.1.1.1", "", ""))
    set_call = next(c for c in calls if c["endpoint"].endswith("/setItem/abc"))
    assert set_call["data"]["alias"]["categories"] == ""
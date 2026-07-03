"""Tests for OpnsenseEngine.import_cert — the v1 INSTALL_CERT target.

The hub brokers cert material from the le (Let's Encrypt) spoke to each target
spoke; the opnsense spoke applies it to its firewall via the Trust→cert API.
Payload is nested under ``"cert"``, raw PEM (not base64): ``action:"import"``,
``descr``, ``cert_type:"usr_cert"``, ``private_key_location:"firewall"``,
``crt_payload`` (the leaf — first BEGIN/END block of the fullchain),
``prv_payload`` (the key), ``csr_payload:""``. A renewal (an existing cert with
``descr == domain``) updates the same cert object in place via ``/set/<uuid>``
instead of re-adding — idempotent distribution.

Self-contained: inserts src/ on sys.path and uses the flat imports the spoke
uses itself, so it runs without a package install. Mirrors tests/test_aliases.py.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from opnsense_engine import OpnsenseEngine  # noqa: E402


_LEAF = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
_INTER = "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n"
_FULLCHAIN = _LEAF + _INTER
_KEY = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"


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


def test_import_cert_fresh_adds_leaf_and_key():
    eng, calls = _make_engine({
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    add = next(c for c in calls if c["endpoint"].endswith("/add"))
    cert = add["data"]["cert"]
    assert cert["action"] == "import"
    assert cert["descr"] == "example.com"
    assert cert["cert_type"] == "usr_cert"
    assert cert["private_key_location"] == "firewall"
    assert cert["csr_payload"] == ""
    # Only the leaf is sent as crt_payload — the intermediate stays in the chain.
    assert cert["crt_payload"] == _LEAF
    assert cert["prv_payload"] == _KEY


def test_import_cert_existing_updates_in_place():
    """A renewal (search finds the same descr) hits /set/<uuid>, not /add — so
    the cert object is refreshed rather than duplicated."""
    eng, calls = _make_engine({
        "/api/trust/cert/search": {"rows": [
            {"uuid": "cert-uuid-1", "descr": "example.com"}]},
        "/api/trust/cert/set/cert-uuid-1": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    assert res["message"] == "cert 'example.com' updated"
    # No add call happened.
    assert not [c for c in calls if c["endpoint"].endswith("/add")]
    set_call = next(c for c in calls if c["endpoint"].endswith("/set/cert-uuid-1"))
    assert set_call["data"]["cert"]["crt_payload"] == _LEAF


def test_import_cert_search_descr_mismatch_falls_to_add():
    """A different descr in search results must not match — fresh add instead."""
    eng, calls = _make_engine({
        "/api/trust/cert/search": {"rows": [
            {"uuid": "other", "descr": "other.example.com"}]},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    assert res["message"] == "cert 'example.com' added"
    assert next((c for c in calls if c["endpoint"].endswith("/add")), None) is not None


def test_import_cert_missing_material_errors():
    eng, _ = _make_engine({"/api/trust/cert/add": {"status": "saved"}})
    res = _run(eng.import_cert("example.com", "", _KEY))
    assert res["status"] == "ERROR"
    res = _run(eng.import_cert("example.com", "not a cert", _KEY))
    assert res["status"] == "ERROR"


def test_import_cert_propagates_add_error():
    eng, _ = _make_engine({
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "ERROR", "message": "missing CA key"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "ERROR"
    assert "missing CA key" in res["message"]


def test_split_leaf_cert_returns_only_first_block():
    assert OpnsenseEngine._split_leaf_cert(_FULLCHAIN) == _LEAF
    assert OpnsenseEngine._split_leaf_cert(_LEAF) == _LEAF
    assert OpnsenseEngine._split_leaf_cert("") == ""
    assert OpnsenseEngine._split_leaf_cert("no pem here") == ""
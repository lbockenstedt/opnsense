"""Tests for OpnsenseEngine.import_cert — the v1 INSTALL_CERT target.

The hub brokers cert material from the le (Let's Encrypt) spoke to each target
spoke; the opnsense spoke applies it to its firewall via the Trust API. The
fullchain is split: the leaf goes to Trust→cert (payload nested under ``"cert"``,
raw PEM not base64: ``action:"import"``, ``descr``, ``cert_type:"usr_cert"``,
``private_key_location:"firewall"``, ``crt_payload`` leaf, ``prv_payload`` key,
``csr_payload:""``) and the intermediates/root are imported into
Trust→Authorities FIRST as CAs (payload under ``"ca"``, ``crt_payload`` the CA
PEM) so the leaf import doesn't error "missing CA key". A renewal (an existing
cert/CA with matching ``descr``) updates the same object in place via
``/set/<uuid>`` instead of re-adding — idempotent distribution. CA import is
best-effort: a benign duplicate-root error must not abort the leaf.

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
_ROOT = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n"
_FULLCHAIN = _LEAF + _INTER  # leaf + one intermediate
_FULLCHAIN_3 = _LEAF + _INTER + _ROOT  # leaf + intermediate + root
_KEY = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_engine(responses):
    """``responses`` maps the endpoint URL (no query) → returned dict. Captures
    every URL + body the engine calls so a wrong field/key fails the test."""
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")
    calls = []

    async def fake_request(method, endpoint, data=None, timeout=15):
        base = endpoint.split("?", 1)[0]
        calls.append({"method": method, "endpoint": base, "data": data, "timeout": timeout})
        return responses.get(base, {"status": "ERROR", "message": "not found"})

    eng._request = fake_request
    return eng, calls


def _cert_call(calls, suffix):
    """Find the call whose endpoint ends with the given cert endpoint suffix
    (e.g. '/api/trust/cert/add'), distinguishing it from the CA /add."""
    return next((c for c in calls if c["endpoint"].endswith(suffix)), None)


# Default happy-path CA responses so CA import (best-effort, runs first) doesn't
# noise up the cert-focused assertions. Tests that care about CA import override.
_CA_OK = {
    "/api/trust/ca/search": {"rows": []},
    "/api/trust/ca/add": {"status": "saved"},
}


def test_import_cert_fresh_adds_leaf_and_key():
    eng, calls = _make_engine({
        **_CA_OK,
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    add = _cert_call(calls, "/api/trust/cert/add")
    assert add is not None
    cert = add["data"]["cert"]
    assert cert["action"] == "import"
    assert cert["descr"] == "example.com"
    assert cert["cert_type"] == "usr_cert"
    assert cert["private_key_location"] == "firewall"
    assert cert["csr_payload"] == ""
    # Only the leaf is sent as crt_payload — the intermediate goes to Authorities.
    assert cert["crt_payload"] == _LEAF
    assert cert["prv_payload"] == _KEY


def test_import_cert_imports_intermediate_as_ca_first():
    """The intermediate (the leaf's signing CA) is imported into
    Trust→Authorities BEFORE the leaf, so the leaf import doesn't error
    'missing CA key'. The CA call precedes the cert call."""
    eng, calls = _make_engine({
        **_CA_OK,
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    # CA search → CA add (no existing CA) → cert search → cert add.
    ca_add = next((c for c in calls if c["endpoint"] == "/api/trust/ca/add"), None)
    assert ca_add is not None
    ca = ca_add["data"]["ca"]
    assert ca["action"] == "import"
    assert ca["descr"] == "lm-le-example.com-ca"  # single intermediate → no index
    assert ca["crt_payload"] == _INTER
    # CA add happens before the cert add.
    ca_idx = calls.index(ca_add)
    cert_idx = calls.index(_cert_call(calls, "/api/trust/cert/add"))
    assert ca_idx < cert_idx
    assert res["ca_imports"] == [{"descr": "lm-le-example.com-ca",
                                  "status": "SUCCESS", "message": "ca 'lm-le-example.com-ca' added"}]


def test_import_cert_multiple_cas_get_indexed_descr():
    """Leaf + intermediate + root: two CA blocks → descrs lm-le-<dom>-ca1 / -ca2."""
    eng, calls = _make_engine({
        "/api/trust/ca/search": {"rows": []},
        "/api/trust/ca/add": {"status": "saved"},
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN_3, _KEY))
    assert res["status"] == "SUCCESS"
    ca_descrs = [c["data"]["ca"]["descr"] for c in calls
                 if c["endpoint"] == "/api/trust/ca/add"]
    assert ca_descrs == ["lm-le-example.com-ca1", "lm-le-example.com-ca2"]


def test_import_cert_existing_ca_updates_in_place():
    """A renewal where the CA already exists hits /api/trust/ca/set/<uuid>."""
    eng, calls = _make_engine({
        "/api/trust/ca/search": {"rows": [
            {"uuid": "ca-uuid-1", "descr": "lm-le-example.com-ca"}]},
        "/api/trust/ca/set/ca-uuid-1": {"status": "saved"},
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    assert not [c for c in calls if c["endpoint"] == "/api/trust/ca/add"]
    assert next((c for c in calls if c["endpoint"].endswith("/ca/set/ca-uuid-1")), None) is not None


def test_import_cert_ca_error_does_not_abort_leaf():
    """A benign CA import error (e.g. a public root already trusted) must NOT
    block the leaf import — CA import is best-effort."""
    eng, calls = _make_engine({
        "/api/trust/ca/search": {"rows": []},
        "/api/trust/ca/add": {"status": "ERROR", "message": "certificate already exists"},
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"  # leaf still imported
    assert res["ca_imports"][0]["status"] == "ERROR"
    assert "already exists" in res["ca_imports"][0]["message"]


def test_import_cert_existing_updates_in_place():
    """A renewal (cert search finds the same descr) hits /set/<uuid>, not /add —
    so the cert object is refreshed rather than duplicated."""
    eng, calls = _make_engine({
        **_CA_OK,
        "/api/trust/cert/search": {"rows": [
            {"uuid": "cert-uuid-1", "descr": "example.com"}]},
        "/api/trust/cert/set/cert-uuid-1": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    assert res["message"] == "cert 'example.com' updated"
    # No cert add call happened (CA add still happens, best-effort).
    assert _cert_call(calls, "/api/trust/cert/add") is None
    set_call = next((c for c in calls if c["endpoint"].endswith("/cert/set/cert-uuid-1")), None)
    assert set_call is not None
    assert set_call["data"]["cert"]["crt_payload"] == _LEAF


def test_import_cert_search_descr_mismatch_falls_to_add():
    """A different descr in cert search results must not match — fresh add."""
    eng, calls = _make_engine({
        **_CA_OK,
        "/api/trust/cert/search": {"rows": [
            {"uuid": "other", "descr": "other.example.com"}]},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    assert res["message"] == "cert 'example.com' added"
    assert _cert_call(calls, "/api/trust/cert/add") is not None


def test_import_cert_missing_material_errors():
    eng, _ = _make_engine({"/api/trust/cert/add": {"status": "saved"}})
    res = _run(eng.import_cert("example.com", "", _KEY))
    assert res["status"] == "ERROR"
    res = _run(eng.import_cert("example.com", "not a cert", _KEY))
    assert res["status"] == "ERROR"


def test_import_cert_propagates_add_error_with_ca_context():
    """If the leaf import still errors (e.g. 'missing CA key' because the CA
    import also failed), the ERROR carries the CA import results for diagnosis."""
    eng, _ = _make_engine({
        "/api/trust/ca/search": {"rows": []},
        "/api/trust/ca/add": {"status": "ERROR", "message": "ca import failed"},
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "ERROR", "message": "missing CA key"},
    })
    res = _run(eng.import_cert("example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "ERROR"
    assert "missing CA key" in res["message"]
    assert res["ca_imports"][0]["status"] == "ERROR"


def test_split_chain_leaf_and_cas():
    leaf, cas = OpnsenseEngine._split_chain(_FULLCHAIN_3)
    assert leaf == _LEAF
    assert cas == [_INTER, _ROOT]
    # Leaf-only chain → no CA blocks.
    assert OpnsenseEngine._split_chain(_LEAF) == (_LEAF, [])
    assert OpnsenseEngine._split_chain("") == ("", [])
    assert OpnsenseEngine._split_chain("no pem") == ("", [])


def test_split_leaf_cert_returns_only_first_block():
    assert OpnsenseEngine._split_leaf_cert(_FULLCHAIN) == _LEAF
    assert OpnsenseEngine._split_leaf_cert(_LEAF) == _LEAF
    assert OpnsenseEngine._split_leaf_cert("") == ""
    assert OpnsenseEngine._split_leaf_cert("no pem here") == ""

def test_import_cert_uses_extended_timeout_for_writes():
    """Cert + CA import POST large PEM payloads and the firewall persists them
    slowly, so those write calls must pass the longer curl --max-time
    (_CERT_IMPORT_TIMEOUT), not the 15s default — otherwise a slow-but-
    succeeding import is cut off as curl exit 28."""
    eng, calls = _make_engine({
        "/api/trust/ca/search": {"rows": []},
        "/api/trust/ca/add": {"status": "saved"},
        "/api/trust/cert/search": {"rows": []},
        "/api/trust/cert/add": {"status": "saved"},
    })
    res = _run(eng.import_cert("fw.example.com", _FULLCHAIN, _KEY))
    assert res["status"] == "SUCCESS"
    for suffix in ("/api/trust/ca/add", "/api/trust/cert/add"):
        c = _cert_call(calls, suffix)
        assert c is not None, f"{suffix} not called"
        assert c["timeout"] == OpnsenseEngine._CERT_IMPORT_TIMEOUT


def test_request_timeout_reports_clear_message(monkeypatch):
    """A curl exit 28 (operation timed out) with empty stderr must surface an
    explicit timeout message including the budget — not a bare 'Curl failed with
    code 28' — so a slow firewall is diagnosable."""
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")

    class _FakeProc:
        returncode = 28

        async def communicate(self):
            return (b"", b"")

    async def fake_exec(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    res = _run(eng._request("POST", "/api/trust/cert/add", data={"cert": {}}, timeout=60))
    assert res["status"] == "ERROR"
    assert "timed out" in res["message"].lower()
    assert "60" in res["message"]


def test_request_keeps_credentials_out_of_curl_argv_by_default(monkeypatch):
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")
    seen = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self):
            return (b'{"status":"ok"}', b"")

    async def fake_exec(*args, **kwargs):
        seen["args"] = args
        cfg_path = args[args.index("--config") + 1]
        seen["cfg_path"] = cfg_path
        seen["cfg_mode"] = os.stat(cfg_path).st_mode & 0o777
        with open(cfg_path, "r") as f:
            seen["cfg_text"] = f.read()
        return _FakeProc()

    monkeypatch.delenv("LM_OPNSENSE_VERIFY_TLS", raising=False)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    res = _run(eng._request("GET", "/api/test"))

    assert res == {"status": "ok"}
    assert "-u" not in seen["args"]
    assert "k:s" not in " ".join(seen["args"])
    assert "-k" not in seen["args"]
    assert seen["cfg_mode"] == 0o600
    assert seen["cfg_text"] == 'user = "k:s"\n'
    assert not os.path.exists(seen["cfg_path"])

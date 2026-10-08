"""Tests for OpnSpoke.handle_command("UPDATE_CONFIG", ...).

Guards against a regression where a payload carrying a falsy/explicit-null
api_key or api_secret (alongside other fields like opn_port) silently wiped
already-configured credentials, making the engine report "no firewall
configured" again after a previously-successful UPDATE_CONFIG.

Self-contained: inserts src/ on sys.path and uses the flat imports the spoke
uses itself, so it runs without a package install.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from opn_spoke import OpnSpoke  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_spoke(**config):
    return OpnSpoke("spoke-1", config)


def test_update_config_sets_credentials_initially():
    spoke = _make_spoke()
    res = _run(spoke.handle_command("UPDATE_CONFIG", {
        "opn_host": "172.21.2.5", "opn_port": 443,
        "api_key": "key1", "api_secret": "secret1",
    }))
    assert res["status"] == "SUCCESS"
    assert spoke.engine.host == "172.21.2.5:443"
    assert spoke.engine.api_key == "key1"
    assert spoke.engine.api_secret == "secret1"
    assert spoke.engine.is_configured()


def test_update_config_does_not_wipe_credentials_on_partial_update():
    spoke = _make_spoke()
    _run(spoke.handle_command("UPDATE_CONFIG", {
        "opn_host": "172.21.2.5", "opn_port": 443,
        "api_key": "key1", "api_secret": "secret1",
    }))

    # A follow-up update that only touches host/port, but re-sends the
    # full config object with api_key/api_secret present as None (as a hub
    # resend of a config dict that didn't have the secrets loaded) must not
    # clear the previously-configured credentials.
    res = _run(spoke.handle_command("UPDATE_CONFIG", {
        "opn_host": "172.21.2.5", "opn_port": 443,
        "api_key": None, "api_secret": None,
    }))

    assert res["status"] == "SUCCESS"
    assert spoke.engine.api_key == "key1"
    assert spoke.engine.api_secret == "secret1"
    assert spoke.engine.is_configured()


def test_update_config_still_applies_a_real_credential_rotation():
    spoke = _make_spoke()
    _run(spoke.handle_command("UPDATE_CONFIG", {
        "opn_host": "172.21.2.5", "opn_port": 443,
        "api_key": "key1", "api_secret": "secret1",
    }))

    res = _run(spoke.handle_command("UPDATE_CONFIG", {
        "api_key": "key2", "api_secret": "secret2",
    }))

    assert res["status"] == "SUCCESS"
    assert spoke.engine.api_key == "key2"
    assert spoke.engine.api_secret == "secret2"

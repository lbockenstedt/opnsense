"""Tests for OpnsenseEngine.get_all_firewall_rules source mapping.

OPNsense search_rule rows carry the source as ``source_net``/``source_port``
(mirroring ``destination_net``/``destination_port``). Reading a ``source`` key
reported every rule as ``any``, so tenant filtering hid source-only rules.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from opnsense_engine import OpnsenseEngine  # noqa: E402


def _rules(rows):
    eng = OpnsenseEngine(host="fw:8443", api_key="k", api_secret="s")

    async def fake_request(method, endpoint, data=None):
        return {"rows": rows}

    eng._request = fake_request
    return asyncio.get_event_loop().run_until_complete(eng.get_all_firewall_rules())["data"]


def test_source_comes_from_source_net():
    rules = _rules([{"uuid": "a", "source_net": "172.21.1.0/24", "destination_net": "any"}])
    assert rules[0]["source"] == "172.21.1.0/24"


def test_source_port_is_appended_like_destination():
    rules = _rules([{"uuid": "a", "source_net": "lan", "source_port": "53"}])
    assert rules[0]["source"] == "lan:53"


def test_missing_source_is_any():
    assert _rules([{"uuid": "a"}])[0]["source"] == "any"

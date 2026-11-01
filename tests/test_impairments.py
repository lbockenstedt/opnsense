"""Tests for LM network impairments (src/impairments.py).

A fake OPNsense API keeps the Traffic Shaper pipes/rules and os-netimpair
entries in memory, so the tests check the objects really created/removed —
including the rollback when a step fails and the plugin-missing message.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import impairments  # noqa: E402


class FakeOpnsense:
    def __init__(self, plugin=True, fail_on=None):
        self.plugin = plugin
        self.fail_on = fail_on
        self.objects = {"pipe": {}, "rule": {}, "impairment": {}}
        self.applied = []
        self.n = 0

    async def _request(self, method, endpoint, data=None):
        parts = endpoint.strip("/").split("/")  # api, module, controller, action[, uuid]
        module, action = parts[1], parts[3]
        if module == "netimpair" and not self.plugin:
            return {"errorMessage": "Endpoint not found"}
        if action == "reconfigure":
            self.applied.append(module)
            return {"status": "ok"}
        kind = action.split("_", 1)[1].rstrip("s")
        store = self.objects[kind]
        if action.startswith("search"):
            return {"rows": [{"uuid": u, **o} for u, o in store.items()]}
        if action.startswith("add"):
            if action == self.fail_on:
                return {"result": "failed", "validations": {f"{kind}.x": "bad value"}}
            self.n += 1
            uuid = f"{kind}-{self.n}"
            store[uuid] = dict(data[kind])
            return {"result": "saved", "uuid": uuid}
        if action.startswith("del"):
            store.pop(parts[4], None)
            return {"result": "deleted"}
        if action == "get_rule":
            rule = dict(store[parts[4]])
            rule["interface"] = {"lan": {"value": "LAN", "selected": 1 if rule["interface"] == "lan" else 0},
                                 "opt1": {"value": "OPT1", "selected": 1 if rule["interface"] == "opt1" else 0}}
            return {"rule": rule}
        raise AssertionError(endpoint)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


SPEC = {"target": "10.0.0.5", "interface": "lan", "direction": "both",
        "delay": 100, "loss": 2.5, "description": "lab  wan sim"}


def test_add_both_directions_builds_pipes_rules_and_impairments():
    fw = FakeOpnsense()
    res = _run(impairments.add_impairment(fw, SPEC))
    assert res["status"] == "SUCCESS"
    assert [len(fw.objects[k]) for k in ("pipe", "rule", "impairment")] == [2, 2, 2]
    rules = sorted(fw.objects["rule"].values(), key=lambda r: r["direction"])
    assert (rules[0]["direction"], rules[0]["source"], rules[0]["destination"]) == ("in", "10.0.0.5", "any")
    assert (rules[1]["direction"], rules[1]["source"], rules[1]["destination"]) == ("out", "any", "10.0.0.5")
    for imp in fw.objects["impairment"].values():
        assert imp["pipe"] in fw.objects["pipe"]
        assert (imp["delay"], imp["loss"]) == ("100", "2.5")
    assert fw.applied == ["trafficshaper", "netimpair"]

    listed = _run(impairments.list_impairments(fw))["data"]
    assert listed == [{"uuid": res["uuid"], "target": "10.0.0.5", "interface": "lan",
                       "delay": 100, "loss": 2.5, "description": "lab wan sim",
                       "enabled": True, "direction": "both", "complete": True}]


def test_failed_step_rolls_back_everything():
    fw = FakeOpnsense(fail_on="add_impairment")
    res = _run(impairments.add_impairment(fw, SPEC))
    assert res["status"] == "ERROR" and "bad value" in res["message"]
    assert all(not store for store in fw.objects.values())
    assert fw.applied == []


def test_edit_replaces_and_failed_edit_keeps_original():
    fw = FakeOpnsense()
    iid = _run(impairments.add_impairment(fw, SPEC))["uuid"]
    res = _run(impairments.edit_impairment(fw, iid, {**SPEC, "target": "10.0.1.0/24",
                                                     "interface": "opt1", "direction": "upload"}))
    assert res["status"] == "SUCCESS"
    listed = _run(impairments.list_impairments(fw))["data"]
    assert [(i["uuid"], i["target"], i["interface"], i["direction"]) for i in listed] == \
        [(res["uuid"], "10.0.1.0/24", "opt1", "upload")]

    fw.fail_on = "add_rule"
    bad = _run(impairments.edit_impairment(fw, res["uuid"], SPEC))
    assert bad["status"] == "ERROR"
    assert [i["uuid"] for i in _run(impairments.list_impairments(fw))["data"]] == [res["uuid"]]
    assert len(fw.objects["pipe"]) == 1


def test_delete_removes_only_lm_objects():
    fw = FakeOpnsense()
    fw.objects["pipe"]["user"] = {"description": "my own pipe"}
    iid = _run(impairments.add_impairment(fw, SPEC))["uuid"]
    assert _run(impairments.delete_impairment(fw, iid))["status"] == "SUCCESS"
    assert list(fw.objects["pipe"]) == ["user"]
    assert not fw.objects["rule"] and not fw.objects["impairment"]
    assert _run(impairments.delete_impairment(fw, iid))["status"] == "ERROR"


def test_missing_plugin_and_bad_input_are_reported():
    res = _run(impairments.list_impairments(FakeOpnsense(plugin=False)))
    assert res["status"] == "ERROR" and "os-netimpair" in res["message"]
    for bad in ({"target": "nope"}, {"interface": "lan; rm"}, {"delay": 0, "loss": 0},
                {"loss": 101}, {"direction": "sideways"}):
        assert _run(impairments.add_impairment(FakeOpnsense(), {**SPEC, **bad}))["status"] == "ERROR"
    assert impairments.validate({**SPEC, "target": "10.0.0.9/24"})["target"] == "10.0.0.0/24"

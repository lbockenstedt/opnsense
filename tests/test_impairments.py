"""Tests for LM network impairments (src/impairments.py).

A fake OPNsense API keeps the Traffic Shaper pipes/rules and os-netimpair
entries in memory, so the tests check the objects really created/removed —
including the rollback when a step fails and the plugin-missing message.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest  # noqa: E402

import impairments  # noqa: E402


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    """Every test gets its own impairments.json."""
    store = impairments.ImpairmentStore(str(tmp_path / "impairments.json"))
    monkeypatch.setattr(impairments, "STORE", store)
    return store


class FakeOpnsense:
    def __init__(self, plugin=True, fail_on=None, aliases=None):
        self.plugin = plugin
        self.fail_on = fail_on
        self.aliases = aliases or []
        self.objects = {"pipe": {}, "rule": {}, "impairment": {}}
        self.applied = []
        self.calls = []
        self.n = 0

    async def get_all_aliases(self):
        return {"status": "SUCCESS", "data": self.aliases}

    async def _request(self, method, endpoint, data=None):
        self.calls.append(endpoint)
        parts = endpoint.strip("/").split("/")  # api, module, controller, action[, uuid]
        module, action = parts[1], parts[3]
        if module == "netimpair" and not self.plugin:
            return {"errorMessage": "Endpoint not found"}
        if action == "reconfigure":
            if self.fail_on == "reconfigure" and module == "trafficshaper":
                return {"status": "failed"}
            self.applied.append(module)
            return {"status": "ok"}
        if action == "toggle_rule":
            if self.fail_on == "toggle_rule" and parts[5] == "1":
                return {"result": "failed"}
            self.objects["rule"][parts[4]]["enabled"] = parts[5]
            return {"result": "Enabled" if parts[5] == "1" else "Disabled", "changed": True}
        kind = action.split("_", 1)[1].rstrip("s")
        store = self.objects[kind]
        if action.startswith("search"):
            return {"rows": [{"uuid": u, **o} for u, o in store.items()]}
        if action.startswith("add"):
            if action == self.fail_on:
                return {"result": "failed", "validations": {f"{kind}.x": "bad value"}}
            if kind == "pipe":
                # OPNsense refuses pipes faster than 2**32-1 bit/s (dummynet limit).
                pipe = data["pipe"]
                factor = {"Kbit": 10**3, "Mbit": 10**6, "Gbit": 10**9}.get(pipe["bandwidthMetric"], 1)
                if int(pipe["bandwidth"]) * factor > 4294967295:
                    return {"result": "failed", "validations": {
                        "pipe.bandwidth": "exceeds the maximum bandwidth of 4 Gbit/s."}}
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
                       "delay": 100, "loss": 2.5, "bandwidth": 0, "bandwidth_unit": "",
                       "description": "lab wan sim",
                       "enabled": True, "direction": "both", "complete": True,
                       "active": True, "target_type": "ip", "targets": ["10.0.0.5"], "labels": [],
                       "alias_members": False, "active_target": "10.0.0.5", "schedule": None,
                       "error": "", "error_at": None, "next_on": None, "next_off": None,
                       "next_target": None}]


def test_failed_step_rolls_back_everything(caplog):
    fw = FakeOpnsense(fail_on="add_impairment")
    with caplog.at_level("WARNING", logger="OpnSpoke.impairments"):
        res = _run(impairments.add_impairment(fw, SPEC))
    # The log names the failing endpoint and the full OPNsense reply.
    assert "netimpair/settings/add_impairment" in caplog.text and "bad value" in caplog.text
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


def test_unlimited_pipe_is_4_gbit_and_limit_is_checked_in_bits_per_second():
    # No limit asked for: the pipe runs at 4 Gbit/s, the most OPNsense accepts.
    fw = FakeOpnsense()
    assert _run(impairments.add_impairment(fw, SPEC))["status"] == "SUCCESS"
    assert {(p["bandwidth"], p["bandwidthMetric"]) for p in fw.objects["pipe"].values()} == {("4", "Gbit")}

    # A limit is kept as given and listed back; units are compared in bits/s.
    fw = FakeOpnsense()
    res = _run(impairments.add_impairment(fw, {**SPEC, "bandwidth": "4000", "bandwidth_unit": "Mbit"}))
    assert res["status"] == "SUCCESS"
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["bandwidth"], item["bandwidth_unit"]) == (0, "")  # 4000 Mbit/s = no limit
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "bandwidth": "50", "bandwidth_unit": "Mbit"}))
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["bandwidth"], item["bandwidth_unit"]) == (50, "Mbit")

    # Over 4 Gbit/s in any unit is refused before anything is created.
    for value, unit in (("5", "Gbit"), ("4001", "Mbit"), ("4000001", "Kbit")):
        fw = FakeOpnsense()
        res = _run(impairments.add_impairment(fw, {**SPEC, "bandwidth": value, "bandwidth_unit": unit}))
        assert res["status"] == "ERROR" and "limited to 4 Gbit/s" in res["message"]
        assert not fw.objects["pipe"]
    for bad in ({"bandwidth": "1.5"}, {"bandwidth": "-1"}, {"bandwidth": "10", "bandwidth_unit": "Tbit"}):
        assert _run(impairments.add_impairment(FakeOpnsense(), {**SPEC, **bad}))["status"] == "ERROR"


def test_bandwidth_only_impairment_and_legacy_10_gbit_pipe_lists_as_unlimited():
    fw = FakeOpnsense()
    res = _run(impairments.add_impairment(fw, {**SPEC, "delay": 0, "loss": 0, "bandwidth": "20"}))
    assert res["status"] == "SUCCESS"
    # A pipe made before the cap (10 Gbit/s, label form) reads as "no limit".
    for pipe in fw.objects["pipe"].values():
        pipe.update(bandwidth="10", bandwidthMetric="Gbit/s")
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["bandwidth"], item["bandwidth_unit"], item["complete"]) == (0, "", True)


def test_pipes_with_different_limits_list_as_incomplete():
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "bandwidth": "20"}))
    next(iter(fw.objects["pipe"].values()))["bandwidth"] = "30"
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert item["complete"] is False


def test_unreadable_pipe_lists_as_incomplete_not_unlimited():
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "target": "192.0.2.5"}))
    next(iter(fw.objects["pipe"].values())).update(bandwidth="", bandwidthMetric="bit/s")
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["bandwidth"], item["complete"]) == (0, False)


# --- Targets (address, alias, device) and rotating schedules -----------------

ALIASES = [{"name": "LAB_HOSTS", "type": "host", "content": "192.0.2.10,192.0.2.11"},
           {"name": "LAB_NETS", "type": "network", "content": "198.51.100.0/25\nLAB_HOSTS"},
           {"name": "BY_NAME", "type": "host", "content": "www.example.com"}]


def _rules(fw):
    """(direction, source, destination, enabled) of every rule, sorted."""
    return sorted((r["direction"], r["source"], r["destination"], r["enabled"])
                  for r in fw.objects["rule"].values())


def test_rule_payloads_for_each_target_type(_store):
    # Address and subnet: one rule per direction and target, all on.
    fw = FakeOpnsense()
    res = _run(impairments.add_impairment(fw, {**SPEC, "direction": "download",
                                                "targets": ["192.0.2.5", "198.51.100.9/24"]}))
    assert res["status"] == "SUCCESS"
    assert _rules(fw) == [("out", "any", "192.0.2.5", "1"), ("out", "any", "198.51.100.0/24", "1")]
    # Several targets keep their count, so a lost target lists as incomplete.
    assert [m["slots"] for m in _store.all("?").values()] == [2]

    # Device: its address goes in the rule, its name is kept for the list.
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "direction": "upload", "target_type": "device",
                                         "targets": ["192.0.2.20"], "labels": ["LAB-PC-1"]}))
    assert _rules(fw) == [("in", "192.0.2.20", "any", "1")]
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["target_type"], item["target"], item["targets"]) == ("device", "LAB-PC-1", ["192.0.2.20"])

    # Alias: shaper rules take no alias names, so its members (nested ones
    # followed) go in as an address list; the list shows the alias name.
    fw = FakeOpnsense(aliases=ALIASES)
    _run(impairments.add_impairment(fw, {**SPEC, "direction": "download", "target_type": "alias",
                                         "targets": ["LAB_NETS"]}))
    assert _rules(fw) == [("out", "any", "198.51.100.0/25,192.0.2.10,192.0.2.11", "1")]
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["target"], item["complete"]) == ("LAB_NETS", True)

    # One member at a time: a rule per member.
    fw = FakeOpnsense(aliases=ALIASES)
    _run(impairments.add_impairment(fw, {**SPEC, "direction": "download", "target_type": "alias",
                                         "targets": ["LAB_HOSTS"], "alias_members": True}))
    assert _rules(fw) == [("out", "any", "192.0.2.10", "1"), ("out", "any", "192.0.2.11", "1")]


def test_invalid_address_and_unknown_alias_are_refused():
    for bad, message in (({"targets": ["192.0.2.300"]}, "not an IP address"),
                         ({"target_type": "device", "targets": ["LAB-PC-1"]}, "not an IP address"),
                         ({"target_type": "alias", "targets": ["NOPE"]}, "does not exist"),
                         ({"target_type": "alias", "targets": ["BY_NAME"]}, "not an address"),
                         ({"target_type": "alias", "targets": ["bad name"]}, "not an alias name"),
                         ({"targets": ["192.0.2.5", "192.0.2.5"]}, "only once"),
                         ({"alias_members": True}, "exactly one alias"),
                         ({"schedule": {"every_hours": 3, "for_minutes": 180}}, "shorter than")):
        fw = FakeOpnsense(aliases=ALIASES)
        res = _run(impairments.add_impairment(fw, {**SPEC, **bad}))
        assert res["status"] == "ERROR" and message in res["message"], (bad, res)
        assert not any(fw.objects.values())


def test_schedule_windows_and_rotation_order():
    sched = {"every_hours": 3, "for_minutes": 15, "start": 100_000}
    state = lambda now: impairments.schedule_state(sched, 3, now)
    assert state(99_999) == {"on": False, "slot": 0, "next_on": 100_000, "next_off": None}
    assert state(100_000) == {"on": True, "slot": 0, "next_on": 110_800, "next_off": 100_900}
    assert state(100_899)["on"] is True
    assert state(100_900) == {"on": False, "slot": 1, "next_on": 110_800, "next_off": None}
    # Each window impairs the next target, wrapping round.
    assert [state(100_000 + k * 10_800 + 60)["slot"] for k in range(5)] == [0, 1, 2, 0, 1]


def test_scheduled_rotation_survives_restart_and_switches_at_boundaries(_store):
    import time
    now = time.time()
    # Started 3h05m ago with 3h windows of 15 min: window 1 (target 2) is on now.
    sched = {"every_hours": 3, "for_minutes": 15, "start": int(now - 3 * 3600 - 300)}
    fw = FakeOpnsense()
    iid = _run(impairments.add_impairment(fw, {**SPEC, "direction": "download", "schedule": sched,
                                                "targets": ["192.0.2.5", "192.0.2.6"]}))["uuid"]
    assert _rules(fw) == [("out", "any", "192.0.2.5", "0"), ("out", "any", "192.0.2.6", "1")]
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["active_target"], item["next_off"]) == ("192.0.2.6", sched["start"] + 3 * 3600 + 900)

    # A restarted spoke (empty memory) finds the wrong rule on and fixes it.
    for r in fw.objects["rule"].values():
        r["enabled"] = "1" if r["destination"] == "192.0.2.5" else "0"
    state = {}
    _run(impairments.run_schedules(fw, state, now))
    assert _rules(fw) == [("out", "any", "192.0.2.5", "0"), ("out", "any", "192.0.2.6", "1")]
    assert state["applied"] == {iid: 1}

    # Nothing due: no API call at all.
    fw.calls.clear()
    _run(impairments.run_schedules(fw, state, now + 60))
    assert fw.calls == []

    # Window ends: everything off. Next window: back to the first target.
    _run(impairments.run_schedules(fw, state, sched["start"] + 3 * 3600 + 900))
    assert [r[3] for r in _rules(fw)] == ["0", "0"]
    _run(impairments.run_schedules(fw, state, sched["start"] + 6 * 3600))
    assert _rules(fw) == [("out", "any", "192.0.2.5", "1"), ("out", "any", "192.0.2.6", "0")]


def test_schedule_switch_failure_turns_the_impairment_off_and_reports_it(_store):
    import time
    now = time.time()
    sched = {"every_hours": 3, "for_minutes": 15, "start": int(now + 60)}
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "schedule": sched, "targets": ["192.0.2.5", "192.0.2.6"]}))
    # Simulate a half-switched state, then make every "switch on" fail.
    next(iter(fw.objects["rule"].values()))["enabled"] = "1"
    fw.fail_on = "toggle_rule"
    _run(impairments.run_schedules(fw, {}, sched["start"] + 10))
    assert {r["enabled"] for r in fw.objects["rule"].values()} == {"0"}
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert "toggle_rule" in item["error"] and item["active"] is False


def test_scheduled_rules_without_a_schedule_are_switched_off(_store):
    import time
    sched = {"every_hours": 1, "for_minutes": 30, "start": int(time.time() - 60)}
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "schedule": sched}))
    assert {r["enabled"] for r in fw.objects["rule"].values()} == {"1"}
    # The spoke lost its impairments.json: the first pass switches them off.
    _store._data = {}
    _run(impairments.run_schedules(fw, {}, time.time()))
    assert {r["enabled"] for r in fw.objects["rule"].values()} == {"0"}


def test_schedule_that_cannot_be_saved_adds_nothing(_store, monkeypatch):
    monkeypatch.setattr(_store, "_save", lambda data: False)
    fw = FakeOpnsense(aliases=[{"name": "lab", "content": "192.0.2.5"}])
    res = _run(impairments.add_impairment(fw, {**SPEC, "schedule": {"every_hours": 3, "for_minutes": 15}}))
    assert res["status"] == "ERROR" and "schedule" in res["message"]
    # Alias names would be lost too: refused the same way.
    res = _run(impairments.add_impairment(fw, {**SPEC, "target_type": "alias", "targets": ["lab"]}))
    assert res["status"] == "ERROR"
    assert not any(fw.objects.values())
    # Nothing unsaved is kept in memory either.
    assert _store.all(impairments._host(fw)) == {}


def test_switch_failure_after_a_rule_went_on_still_turns_everything_off(_store):
    """Rotation switches the next target's rule on, then applying fails: the
    fail-safe must switch that freshly enabled rule off too."""
    import time
    sched = {"every_hours": 1, "for_minutes": 30, "start": int(time.time() - 60)}
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "schedule": sched, "targets": ["192.0.2.5", "192.0.2.6"]}))
    fw.fail_on = "reconfigure"
    _run(impairments.run_schedules(fw, {}, sched["start"] + 3600 + 10))
    assert {r["enabled"] for r in fw.objects["rule"].values()} == {"0"}
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert "reconfigure failed" in item["error"] and "also failed" in item["error"]


def test_failed_shaper_reload_is_retried_until_it_works(_store):
    """Toggles change the config only; when the reload fails the running
    shaper still impairs, so the next pass must reload even though every
    rule already reads off."""
    import time
    sched = {"every_hours": 1, "for_minutes": 30, "start": int(time.time() - 60)}
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "schedule": sched}))
    state, off_time = {}, sched["start"] + 31 * 60
    fw.fail_on = "reconfigure"
    _run(impairments.run_schedules(fw, state, off_time))
    assert {r["enabled"] for r in fw.objects["rule"].values()} == {"0"}
    fw.fail_on = None
    reloads = fw.applied.count("trafficshaper")
    _run(impairments.run_schedules(fw, state, off_time))
    assert fw.applied.count("trafficshaper") == reloads + 1
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert item["error"] == ""
    # Nothing left to do: a further pass makes no call.
    calls = len(fw.calls)
    _run(impairments.run_schedules(fw, state, off_time))
    assert len(fw.calls) == calls


def test_next_target_during_a_window_is_the_following_one(_store):
    import time
    sched = {"every_hours": 1, "for_minutes": 30, "start": int(time.time() - 60)}
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "schedule": sched, "targets": ["192.0.2.5", "192.0.2.6"]}))
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert (item["active_target"], item["next_target"]) == ("192.0.2.5", "192.0.2.6")


def test_toggle_answer_must_match_the_requested_state(_store):
    import time
    sched = {"every_hours": 1, "for_minutes": 30, "start": int(time.time() + 60)}
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "schedule": sched}))
    real = fw._request

    async def wrong(method, endpoint, data=None):
        if "/toggle_rule/" in endpoint and endpoint.endswith("/1"):
            return {"result": "Disabled"}
        return await real(method, endpoint, data)
    fw._request = wrong
    _run(impairments.run_schedules(fw, {}, sched["start"] + 10))
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert "toggle_rule" in item["error"] and item["active"] is False


def test_alias_members_are_limited_like_targets():
    members = ",".join(f"192.0.2.{i}" for i in range(1, 34))
    fw = FakeOpnsense(aliases=[{"name": "big", "content": members}])
    res = _run(impairments.add_impairment(
        fw, {**SPEC, "target_type": "alias", "targets": ["big"], "alias_members": True}))
    assert res["status"] == "ERROR" and "at most 32" in res["message"]
    assert not any(fw.objects.values())


def test_missing_target_rules_list_as_incomplete_and_name_the_right_target(_store):
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "direction": "download",
                                         "targets": ["192.0.2.5", "198.51.100.5"], "labels": ["a", "b"]}))
    first = [u for u, r in fw.objects["rule"].items() if r["destination"] == "192.0.2.5"]
    for u in first:
        del fw.objects["rule"][u]
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert item["complete"] is False and item["active_target"] == "b"


def test_completeness_counts_each_object_per_direction():
    fw = FakeOpnsense()
    _run(impairments.add_impairment(fw, {**SPEC, "target": "192.0.2.5", "direction": "download"}))
    # Swap the rule for a second pipe: the same number of objects, but not whole.
    rule_uuid = next(iter(fw.objects["rule"]))
    pipe = dict(next(iter(fw.objects["pipe"].values())))
    del fw.objects["rule"][rule_uuid]
    fw.objects["pipe"]["pipe-extra"] = pipe
    [item] = _run(impairments.list_impairments(fw))["data"]
    assert item["complete"] is False

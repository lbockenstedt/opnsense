"""LM network impairments: latency / packet loss for one host or subnet.

One LM impairment is built from plain OPNsense objects, all tagged in their
description with ``lm-impair:<id>:<down|up>``:

* a Traffic Shaper pipe per direction (10 Gbit/s, so it only delays/drops),
* a Traffic Shaper rule per direction sending the host/subnet's traffic into
  that pipe on the chosen interface (download = to the target, ``out`` on the
  interface; upload = from the target, ``in``),
* an ``os-netimpair`` plugin entry per pipe holding the delay and loss.

The tag is how list/edit/delete find the pieces again, so nothing has to be
stored on the LM side.
"""
import ipaddress
import re
import uuid as uuidlib
from typing import Any, Dict, List

TAG = "lm-impair"
DIRECTIONS = {"both": ("down", "up"), "download": ("down",), "upload": ("up",)}
PLUGIN_MISSING = ("The os-netimpair plugin is not installed on this firewall "
                  "(System > Firmware > Plugins)")

TS = "/api/trafficshaper"
NI = "/api/netimpair"


def _error(message: str) -> Dict[str, Any]:
    return {"status": "ERROR", "message": message}


def _tag(iid: str, way: str) -> str:
    return f"{TAG}:{iid}:{way}"


def _parse_tag(description: str):
    """``(id, way, user_description)`` for an LM-tagged description, else None."""
    head, _, rest = (description or "").partition(" ")
    parts = head.split(":")
    if len(parts) != 3 or parts[0] != TAG or parts[2] not in ("down", "up"):
        return None
    return parts[1], parts[2], rest


def validate(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a UI/hub spec or raise ValueError with a readable message."""
    try:
        net = ipaddress.ip_network(str(spec.get("target", "")).strip(), strict=False)
    except ValueError:
        raise ValueError("Target must be an IP address or subnet (e.g. 10.0.0.5 or 10.0.0.0/24)")
    target = str(net.network_address) if net.num_addresses == 1 else str(net)

    interface = str(spec.get("interface", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_]+", interface):
        raise ValueError("Interface must be an OPNsense interface name (e.g. lan, opt1)")

    direction = spec.get("direction") or "both"
    if direction not in DIRECTIONS:
        raise ValueError("Direction must be both, download or upload")

    try:
        delay = int(spec.get("delay") or 0)
        loss = float(spec.get("loss") or 0)
    except (TypeError, ValueError):
        raise ValueError("Latency and loss must be numbers")
    if not 0 <= delay <= 10000:
        raise ValueError("Latency must be between 0 and 10000 ms")
    if not 0 <= loss <= 100:
        raise ValueError("Packet loss must be between 0 and 100 %")
    if delay == 0 and loss == 0:
        raise ValueError("Set a latency or a packet loss")

    description = " ".join(str(spec.get("description") or "").split())[:200]
    return {"target": target, "interface": interface, "direction": direction,
            "delay": delay, "loss": loss, "description": description,
            "enabled": str(spec.get("enabled", "1")) not in ("0", "false", "False")}


def _selected(value) -> str:
    """Raw value of an OPNsense option field from a ``get_*`` response
    (``{"lan": {"selected": 1, ...}, ...}``) or a plain string."""
    if isinstance(value, dict):
        return next((k for k, v in value.items()
                     if isinstance(v, dict) and str(v.get("selected")) == "1"), "")
    return str(value or "")


async def _rows(engine, endpoint: str):
    res = await engine._request("POST", endpoint, data={"current": 1, "rowCount": -1, "searchPhrase": ""})
    if isinstance(res, dict) and isinstance(res.get("rows"), list):
        return res["rows"]
    return None


async def _tagged(engine):
    """``(pipes, rules, impairments)`` LM-tagged rows, or an error dict."""
    impairments = await _rows(engine, f"{NI}/settings/search_impairment")
    if impairments is None:
        return _error(PLUGIN_MISSING)
    pipes = await _rows(engine, f"{TS}/settings/search_pipes")
    rules = await _rows(engine, f"{TS}/settings/search_rules")
    if pipes is None or rules is None:
        return _error("Could not read the Traffic Shaper (does the API key have the Firewall: Shaper privilege?)")
    keep = lambda rows: [r for r in rows if _parse_tag(r.get("description", ""))]
    return keep(pipes), keep(rules), keep(impairments)


async def _apply(engine) -> Dict[str, Any]:
    for endpoint in (f"{TS}/service/reconfigure", f"{NI}/service/reconfigure"):
        res = await engine._request("POST", endpoint, data={})
        if not (isinstance(res, dict) and res.get("status") == "ok"):
            return _error(f"Apply failed at {endpoint}: {res}")
    return {"status": "SUCCESS"}


async def _add(engine, endpoint: str, body: Dict[str, Any]):
    res = await engine._request("POST", endpoint, data=body)
    if isinstance(res, dict) and res.get("result") == "saved" and res.get("uuid"):
        return res["uuid"], None
    if isinstance(res, dict) and res.get("validations"):
        return None, "; ".join(f"{k}: {v}" for k, v in res["validations"].items())
    return None, (res.get("message") if isinstance(res, dict) else None) or str(res)


async def _create(engine, iid: str, spec: Dict[str, Any]):
    """Create every object for ``spec`` under id ``iid``. On any failure the
    objects already created are deleted again. Returns an error string or None."""
    created: List[str] = []
    enabled = "1" if spec["enabled"] else "0"
    error = None
    for way in DIRECTIONS[spec["direction"]]:
        description = _tag(iid, way) + (f" {spec['description']}" if spec["description"] else "")
        pipe_uuid, error = await _add(engine, f"{TS}/settings/add_pipe", {"pipe": {
            "enabled": "1", "bandwidth": "10", "bandwidthMetric": "Gbit",
            "mask": "none", "scheduler": "", "description": description}})
        if error:
            break
        created.append(f"{TS}/settings/del_pipe/{pipe_uuid}")
        rule_uuid, error = await _add(engine, f"{TS}/settings/add_rule", {"rule": {
            "enabled": enabled, "sequence": "1", "interface": spec["interface"],
            "proto": "ip",
            "source": spec["target"] if way == "up" else "any",
            "destination": spec["target"] if way == "down" else "any",
            "direction": "in" if way == "up" else "out",
            "target": pipe_uuid, "description": description}})
        if error:
            break
        created.append(f"{TS}/settings/del_rule/{rule_uuid}")
        imp_uuid, error = await _add(engine, f"{NI}/settings/add_impairment", {"impairment": {
            "enabled": enabled, "pipe": pipe_uuid, "delay": str(spec["delay"]),
            "loss": str(spec["loss"]), "description": description}})
        if error:
            break
        created.append(f"{NI}/settings/del_impairment/{imp_uuid}")
    if error:
        for endpoint in reversed(created):
            await engine._request("POST", endpoint, data={})
    return error


async def _remove(engine, iid: str, tagged) -> None:
    """Delete every object tagged with ``iid``: impairments and rules before
    the pipes they reference."""
    pipes, rules, impairments = tagged
    mine = lambda rows: [r["uuid"] for r in rows if _parse_tag(r.get("description", ""))[0] == iid]
    for uuid in mine(impairments):
        await engine._request("POST", f"{NI}/settings/del_impairment/{uuid}", data={})
    for uuid in mine(rules):
        await engine._request("POST", f"{TS}/settings/del_rule/{uuid}", data={})
    for uuid in mine(pipes):
        await engine._request("POST", f"{TS}/settings/del_pipe/{uuid}", data={})


async def list_impairments(engine) -> Dict[str, Any]:
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    pipes, rules, impairments = tagged
    items: Dict[str, Dict[str, Any]] = {}

    def item(iid):
        return items.setdefault(iid, {"uuid": iid, "target": "", "interface": "",
                                      "ways": set(), "delay": 0, "loss": 0.0,
                                      "description": "", "enabled": False, "parts": 0})

    for row in impairments:
        iid, way, desc = _parse_tag(row["description"])
        it = item(iid)
        it["ways"].add(way)
        it["description"] = desc
        it["delay"] = int(row.get("delay") or 0)
        it["loss"] = float(row.get("loss") or 0)
        it["enabled"] = it["enabled"] or str(row.get("enabled")) == "1"
        it["parts"] += 1
    for row in rules:
        iid, way, _ = _parse_tag(row["description"])
        it = item(iid)
        it["parts"] += 1
        # search rows may show option fields by their display name; get_rule
        # returns the raw interface and addresses.
        res = await engine._request("GET", f"{TS}/settings/get_rule/{row['uuid']}")
        rule = res.get("rule", {}) if isinstance(res, dict) else {}
        it["interface"] = _selected(rule.get("interface")) or it["interface"]
        it["target"] = (rule.get("source") if way == "up" else rule.get("destination")) or it["target"]
    for row in pipes:
        item(_parse_tag(row["description"])[0])["parts"] += 1

    out = []
    for it in items.values():
        ways = it.pop("ways")
        it["direction"] = "both" if ways == {"down", "up"} else ("upload" if ways == {"up"} else "download")
        # 3 objects per direction; anything else is a half-built leftover.
        it["complete"] = it.pop("parts") == 3 * max(len(ways), 1)
        out.append(it)
    out.sort(key=lambda i: (i["target"], i["uuid"]))
    return {"status": "SUCCESS", "data": out}


async def add_impairment(engine, spec: Dict[str, Any]) -> Dict[str, Any]:
    try:
        spec = validate(spec)
    except ValueError as e:
        return _error(str(e))
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    iid = uuidlib.uuid4().hex[:12]
    error = await _create(engine, iid, spec)
    if error:
        return _error(f"Could not create the impairment: {error}")
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    return {"status": "SUCCESS", "message": f"Impairment added for {spec['target']}", "uuid": iid}


async def edit_impairment(engine, iid: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    """Build the new version first, then remove the old one, so a failed edit
    leaves the existing impairment untouched."""
    try:
        spec = validate(spec)
    except ValueError as e:
        return _error(str(e))
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    if not any(_parse_tag(r["description"])[0] == iid for rows in tagged for r in rows):
        return _error(f"Impairment {iid} not found")
    new_id = uuidlib.uuid4().hex[:12]
    error = await _create(engine, new_id, spec)
    if error:
        return _error(f"Could not update the impairment: {error}")
    await _remove(engine, iid, tagged)
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    return {"status": "SUCCESS", "message": f"Impairment updated for {spec['target']}", "uuid": new_id}


async def delete_impairment(engine, iid: str) -> Dict[str, Any]:
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    if not any(_parse_tag(r["description"])[0] == iid for rows in tagged for r in rows):
        return _error(f"Impairment {iid} not found")
    await _remove(engine, iid, tagged)
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    return {"status": "SUCCESS", "message": f"Impairment {iid} deleted"}

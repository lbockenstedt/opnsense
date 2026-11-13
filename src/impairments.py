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
# ipaddress validates and normalises the target host/subnet.
import ipaddress
# logging records why a change failed (the spoke logs commands only at DEBUG).
import logging
# re checks that the interface name is a plain OPNsense identifier.
import re
# uuid generates short random ids for new impairments.
import uuid as uuidlib
# Type hints for spec/result dictionaries.
from typing import Any, Dict, List

# Module logger.
logger = logging.getLogger("OpnSpoke.impairments")


def _host(engine) -> str:
    """The firewall address for log lines ("?" when the engine has none)."""
    return getattr(engine, "host", None) or "?"


# Prefix written into every description so LM can find its own objects later.
TAG = "lm-impair"
# Which pipe directions ("down" = to target, "up" = from target) each UI choice creates.
DIRECTIONS = {"both": ("down", "up"), "download": ("down",), "upload": ("up",)}
# Error shown when the netimpair API is missing (plugin not installed).
PLUGIN_MISSING = ("The os-netimpair plugin is not installed on this firewall "
                  "(System > Firmware > Plugins)")

# Base REST paths of the Traffic Shaper and os-netimpair plugin APIs.
TS = "/api/trafficshaper"
NI = "/api/netimpair"


def _error(message: str) -> Dict[str, Any]:
    """Build the standard error result dict returned to the Hub/UI."""
    return {"status": "ERROR", "message": message}


def _tag(iid: str, way: str) -> str:
    """Build the description tag that marks one direction of impairment ``iid``."""
    return f"{TAG}:{iid}:{way}"


def _parse_tag(description: str):
    """``(id, way, user_description)`` for an LM-tagged description, else None."""
    # The tag is the first word; anything after the first space is the user's text.
    head, _, rest = (description or "").partition(" ")
    parts = head.split(":")
    # Must be exactly "lm-impair:<id>:<down|up>"; otherwise it is not ours.
    if len(parts) != 3 or parts[0] != TAG or parts[2] not in ("down", "up"):
        return None
    return parts[1], parts[2], rest


def validate(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a UI/hub spec or raise ValueError with a readable message."""
    # Parse the target; strict=False accepts host bits set (e.g. 10.0.0.5/24).
    try:
        net = ipaddress.ip_network(str(spec.get("target", "")).strip(), strict=False)
    # Not an IP or network at all.
    except ValueError:
        raise ValueError("Target must be an IP address or subnet (e.g. 10.0.0.5 or 10.0.0.0/24)")
    # A single address is stored without "/32", a real subnet keeps its prefix.
    target = str(net.network_address) if net.num_addresses == 1 else str(net)

    # Interface must be an OPNsense interface key such as "lan" or "opt1".
    interface = str(spec.get("interface", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_]+", interface):
        raise ValueError("Interface must be an OPNsense interface name (e.g. lan, opt1)")

    # Direction defaults to both ways and must be one of the known choices.
    direction = spec.get("direction") or "both"
    if direction not in DIRECTIONS:
        raise ValueError("Direction must be both, download or upload")

    # Latency (ms) and loss (%) must be numeric; blank means 0.
    try:
        delay = int(spec.get("delay") or 0)
        loss = float(spec.get("loss") or 0)
    except (TypeError, ValueError):
        # Non-numeric latency or loss.
        raise ValueError("Latency and loss must be numbers")
    # Range checks: up to 10 s latency, loss is a percentage.
    if not 0 <= delay <= 10000:
        raise ValueError("Latency must be between 0 and 10000 ms")
    if not 0 <= loss <= 100:
        raise ValueError("Packet loss must be between 0 and 100 %")
    # An impairment that neither delays nor drops would do nothing.
    if delay == 0 and loss == 0:
        raise ValueError("Set a latency or a packet loss")

    # Collapse whitespace in the user description and cap its length.
    description = " ".join(str(spec.get("description") or "").split())[:200]
    # Normalised spec; "enabled" accepts the usual false-y strings.
    return {"target": target, "interface": interface, "direction": direction,
            "delay": delay, "loss": loss, "description": description,
            "enabled": str(spec.get("enabled", "1")) not in ("0", "false", "False")}


def _selected(value) -> str:
    """Raw value of an OPNsense option field from a ``get_*`` response
    (``{"lan": {"selected": 1, ...}, ...}``) or a plain string."""
    # Option fields come back as a dict of choices; return the key marked selected.
    if isinstance(value, dict):
        return next((k for k, v in value.items()
                     if isinstance(v, dict) and str(v.get("selected")) == "1"), "")
    # Already a plain value.
    return str(value or "")


async def _rows(engine, endpoint: str):
    """Return all rows of an OPNsense search endpoint, or None if the call failed."""
    # rowCount -1 asks OPNsense for every row in one page.
    res = await engine._request("POST", endpoint, data={"current": 1, "rowCount": -1, "searchPhrase": ""})
    # A valid search response is a dict with a "rows" list.
    if isinstance(res, dict) and isinstance(res.get("rows"), list):
        return res["rows"]
    # Error or unexpected answer (e.g. endpoint missing).
    logger.warning("impairment read failed at %s on %s: %s", endpoint, _host(engine), res)
    return None


async def _tagged(engine):
    """``(pipes, rules, impairments)`` LM-tagged rows, or an error dict."""
    # Query the plugin first: no answer means the plugin is not installed.
    impairments = await _rows(engine, f"{NI}/settings/search_impairment")
    if impairments is None:
        return _error(PLUGIN_MISSING)
    # Read the shaper pipes and rules.
    pipes = await _rows(engine, f"{TS}/settings/search_pipes")
    rules = await _rows(engine, f"{TS}/settings/search_rules")
    # The shaper is always installed, so a failure here is a permissions problem.
    if pipes is None or rules is None:
        return _error("Could not read the Traffic Shaper (does the API key have the Firewall: Shaper privilege?)")
    # Keep only rows carrying an LM impairment tag.
    keep = lambda rows: [r for r in rows if _parse_tag(r.get("description", ""))]
    return keep(pipes), keep(rules), keep(impairments)


async def _apply(engine) -> Dict[str, Any]:
    """Apply pending shaper and netimpair changes; return SUCCESS or an error dict."""
    # Reconfigure the shaper first (pipes/rules), then the impairment plugin.
    for endpoint in (f"{TS}/service/reconfigure", f"{NI}/service/reconfigure"):
        res = await engine._request("POST", endpoint, data={})
        # Anything other than {"status": "ok"} means the change was not applied.
        if not (isinstance(res, dict) and res.get("status") == "ok"):
            logger.warning("impairment apply failed at %s on %s: %s", endpoint, _host(engine), res)
            return _error(f"Apply failed at {endpoint}: {res}")
    # Both services reloaded.
    return {"status": "SUCCESS"}


async def _add(engine, endpoint: str, body: Dict[str, Any]):
    """POST an add_* call; return (uuid, None) on success or (None, error text)."""
    res = await engine._request("POST", endpoint, data=body)
    # OPNsense signals success with result "saved" plus the new object's uuid.
    if isinstance(res, dict) and res.get("result") == "saved" and res.get("uuid"):
        return res["uuid"], None
    # Log the endpoint and the full reply; the UI only gets the message.
    logger.warning("impairment add failed at %s on %s: %s", endpoint, _host(engine), res)
    # Field validation errors: join them into one readable message.
    if isinstance(res, dict) and res.get("validations"):
        return None, "; ".join(f"{k}: {v}" for k, v in res["validations"].items())
    # Any other failure: use the API's message, or the raw response.
    return None, (res.get("message") if isinstance(res, dict) else None) or str(res)


async def _delete(engine, endpoint: str) -> None:
    """POST a del_* call; log it when OPNsense does not confirm the delete."""
    res = await engine._request("POST", endpoint, data={})
    if not (isinstance(res, dict) and res.get("result") == "deleted"):
        logger.warning("impairment delete failed at %s on %s: %s", endpoint, _host(engine), res)


async def _create(engine, iid: str, spec: Dict[str, Any]):
    """Create every object for ``spec`` under id ``iid``. On any failure the
    objects already created are deleted again. Returns an error string or None."""
    # Delete URLs of objects created so far (for rollback), and shared enabled flag.
    created: List[str] = []
    enabled = "1" if spec["enabled"] else "0"
    error = None
    # Build pipe, rule and impairment entry for each requested direction.
    for way in DIRECTIONS[spec["direction"]]:
        # Tag every object for this direction, keeping the user's description after it.
        description = _tag(iid, way) + (f" {spec['description']}" if spec["description"] else "")
        # 10 Gbit/s pipe: fast enough that it only delays/drops, never limits bandwidth.
        pipe_uuid, error = await _add(engine, f"{TS}/settings/add_pipe", {"pipe": {
            "enabled": "1", "bandwidth": "10", "bandwidthMetric": "Gbit",
            "mask": "none", "scheduler": "", "description": description}})
        # Stop at the first failure; rollback happens after the loop.
        if error:
            break
        # Remember how to delete the pipe in case a later step fails.
        created.append(f"{TS}/settings/del_pipe/{pipe_uuid}")
        # Rule steering the target's traffic into the pipe on the chosen interface:
        # download matches destination=target outbound, upload matches source=target inbound.
        rule_uuid, error = await _add(engine, f"{TS}/settings/add_rule", {"rule": {
            "enabled": enabled, "sequence": "1", "interface": spec["interface"],
            "proto": "ip",
            "source": spec["target"] if way == "up" else "any",
            "destination": spec["target"] if way == "down" else "any",
            "direction": "in" if way == "up" else "out",
            "target": pipe_uuid, "description": description}})
        if error:
            break
        # Remember how to delete the rule in case a later step fails.
        created.append(f"{TS}/settings/del_rule/{rule_uuid}")
        # netimpair entry holding the actual delay and loss for this pipe.
        imp_uuid, error = await _add(engine, f"{NI}/settings/add_impairment", {"impairment": {
            "enabled": enabled, "pipe": pipe_uuid, "delay": str(spec["delay"]),
            "loss": str(spec["loss"]), "description": description}})
        if error:
            break
        # Remember how to delete the impairment entry as well.
        created.append(f"{NI}/settings/del_impairment/{imp_uuid}")
    # Roll back: delete created objects in reverse order (dependents before pipes).
    if error:
        logger.warning("impairment %s on %s failed (%s); rolling back %d object(s)",
                       iid, _host(engine), error, len(created))
        for endpoint in reversed(created):
            await _delete(engine, endpoint)
    # None on success, otherwise the first error message.
    return error


async def _remove(engine, iid: str, tagged) -> None:
    """Delete every object tagged with ``iid``: impairments and rules before
    the pipes they reference."""
    # Unpack the tagged rows and pick the uuids belonging to impairment ``iid``.
    pipes, rules, impairments = tagged
    mine = lambda rows: [r["uuid"] for r in rows if _parse_tag(r.get("description", ""))[0] == iid]
    # Delete in dependency order: impairments, then rules, then pipes.
    for uuid in mine(impairments):
        await _delete(engine, f"{NI}/settings/del_impairment/{uuid}")
    for uuid in mine(rules):
        await _delete(engine, f"{TS}/settings/del_rule/{uuid}")
    for uuid in mine(pipes):
        await _delete(engine, f"{TS}/settings/del_pipe/{uuid}")


async def list_impairments(engine) -> Dict[str, Any]:
    """Return all LM impairments, rebuilt from their tagged OPNsense objects."""
    # Fetch tagged rows; an error dict is passed straight back.
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    # One summary item per impairment id, filled from the three object types.
    pipes, rules, impairments = tagged
    items: Dict[str, Dict[str, Any]] = {}

    def item(iid):
        """Return (creating if needed) the summary item for impairment ``iid``."""
        return items.setdefault(iid, {"uuid": iid, "target": "", "interface": "",
                                      "ways": set(), "delay": 0, "loss": 0.0,
                                      "description": "", "enabled": False, "parts": 0})

    # Plugin entries hold delay, loss, enabled state and the user description.
    for row in impairments:
        iid, way, desc = _parse_tag(row["description"])
        it = item(iid)
        it["ways"].add(way)
        it["description"] = desc
        it["delay"] = int(row.get("delay") or 0)
        it["loss"] = float(row.get("loss") or 0)
        it["enabled"] = it["enabled"] or str(row.get("enabled")) == "1"
        it["parts"] += 1
    # Rules hold the interface and target; also count them as parts.
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
    # Pipes only count towards completeness.
    for row in pipes:
        item(_parse_tag(row["description"])[0])["parts"] += 1

    # Turn each item into the API shape.
    out = []
    for it in items.values():
        # Translate the set of directions back to the UI's direction name.
        ways = it.pop("ways")
        it["direction"] = "both" if ways == {"down", "up"} else ("upload" if ways == {"up"} else "download")
        # 3 objects per direction; anything else is a half-built leftover.
        it["complete"] = it.pop("parts") == 3 * max(len(ways), 1)
        out.append(it)
    # Stable order: by target, then id.
    out.sort(key=lambda i: (i["target"], i["uuid"]))
    # Hand back the list.
    return {"status": "SUCCESS", "data": out}


async def add_impairment(engine, spec: Dict[str, Any]) -> Dict[str, Any]:
    """Validate ``spec``, create its OPNsense objects and apply them."""
    # Validate first so nothing is created for a bad spec.
    try:
        spec = validate(spec)
    except ValueError as e:
        # Return the validation message to the UI.
        return _error(str(e))
    # Reading tagged rows also confirms the plugin and shaper APIs are reachable.
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    # New short id for this impairment.
    iid = uuidlib.uuid4().hex[:12]
    # Create pipes/rules/impairments (rolled back internally on failure).
    error = await _create(engine, iid, spec)
    if error:
        return _error(f"Could not create the impairment: {error}")
    # Activate the new configuration on the firewall.
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    # Report success with the new id.
    logger.info("impairment %s added on %s: %s %s, %s ms, %s %% loss", iid, _host(engine),
                spec["target"], spec["direction"], spec["delay"], spec["loss"])
    return {"status": "SUCCESS", "message": f"Impairment added for {spec['target']}", "uuid": iid}


async def edit_impairment(engine, iid: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    """Build the new version first, then remove the old one, so a failed edit
    leaves the existing impairment untouched."""
    # Validate the new spec before touching anything.
    try:
        spec = validate(spec)
    except ValueError as e:
        # Return the validation message to the UI.
        return _error(str(e))
    # Read existing tagged rows (or return the API error).
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    # The impairment being edited must exist.
    if not any(_parse_tag(r["description"])[0] == iid for rows in tagged for r in rows):
        return _error(f"Impairment {iid} not found")
    # Create the replacement under a new id; stop if that fails.
    new_id = uuidlib.uuid4().hex[:12]
    error = await _create(engine, new_id, spec)
    if error:
        logger.warning("impairment %s edit on %s failed: %s", iid, _host(engine), error)
        return _error(f"Could not update the impairment: {error}")
    # Replacement exists: now remove the old objects and apply.
    await _remove(engine, iid, tagged)
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    # Report success with the replacement's new id.
    logger.info("impairment %s on %s replaced by %s", iid, _host(engine), new_id)
    return {"status": "SUCCESS", "message": f"Impairment updated for {spec['target']}", "uuid": new_id}


async def delete_impairment(engine, iid: str) -> Dict[str, Any]:
    """Delete every object of impairment ``iid`` and apply the change."""
    # Read existing tagged rows (or return the API error).
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    # Refuse unknown ids.
    if not any(_parse_tag(r["description"])[0] == iid for rows in tagged for r in rows):
        return _error(f"Impairment {iid} not found")
    # Remove the objects and activate the change.
    await _remove(engine, iid, tagged)
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    logger.info("impairment %s deleted on %s", iid, _host(engine))
    return {"status": "SUCCESS", "message": f"Impairment {iid} deleted"}

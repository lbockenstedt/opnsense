"""LM network impairments: latency / packet loss / a bandwidth limit for
hosts, subnets, firewall aliases or LM devices, always on or on a rotating
schedule.

One LM impairment is built from plain OPNsense objects, all tagged in their
description with ``lm-impair:<id>:<down|up>``. With several targets each
rule also names its target slot (``…:<slot>``; ``…:s<slot>`` when scheduled):

* a Traffic Shaper pipe per direction, at the optional bandwidth limit or
  else at 4 Gbit/s (the fastest pipe OPNsense accepts, so it only delays/drops),
* a Traffic Shaper rule per direction and target sending that target's
  traffic into the pipe on the chosen interface (download = to the target,
  ``out`` on the interface; upload = from the target, ``in``),
* an ``os-netimpair`` plugin entry per pipe holding the delay and loss.

The tag is how list/edit/delete find the pieces again. What the firewall
cannot hold (the alias or device names the user picked, the schedule and the
scheduler's last error) is kept by the spoke in ``impairments.json``
(:class:`ImpairmentStore`); a plain always-on IP impairment stores nothing.

Shaper rules only take addresses and networks (OPNsense ``NetworkField``),
not alias names, so an alias target is copied into the rule as its member
addresses when the impairment is saved.

A scheduled impairment is on for ``for_minutes`` every ``every_hours`` from
``start``. Its targets rotate: slot *k* (the *k*-th window since ``start``)
impairs target ``k % len(targets)``. :func:`run_schedules` (called by the
spoke every 30 s) enables only that target's rules during a window and
disables them all outside it.
"""
# asyncio runs the JSON store's file I/O off the event loop.
import asyncio
# ipaddress validates and normalises the target host/subnet.
import ipaddress
# json/os persist impairment targets and schedules on the spoke.
import json
import os
# logging records why a change failed (the spoke logs commands only at DEBUG).
import logging
# re checks that the interface name is a plain OPNsense identifier.
import re
# time stamps scheduler errors and fills a schedule's default start.
import threading
import time
# uuid generates short random ids for new impairments.
import uuid as uuidlib
# Type hints for spec/result dictionaries.
from typing import Any, Dict, List, Optional
# Same data directory as the performance store.
from opn_perf_store import DATA_DIR

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

# Pipe bandwidth units (OPNsense ``bandwidthMetric`` values) in bits per second.
UNITS = {"Kbit": 1_000, "Mbit": 1_000_000, "Gbit": 1_000_000_000}
# dummynet keeps a pipe's bits/s in 32 bits, so OPNsense rejects anything faster
# than ~4.29 Gbit/s. LM uses 4 Gbit/s as both the cap and the "no limit" pipe.
MAX_BPS = 4 * UNITS["Gbit"]
BANDWIDTH_LIMIT = "OPNsense pipes are limited to 4 Gbit/s"

# What a target entry is: an address/subnet, a firewall alias name, or an LM
# device (the hub UI resolves the device to its address and sends its name as
# the label).
TARGET_TYPES = ("ip", "alias", "device")
# Most targets one impairment may rotate through (each adds a rule per direction).
MAX_TARGETS = 32
# OPNsense alias names: letters, digits and underscores, at most 32 characters.
ALIAS_NAME = re.compile(r"[A-Za-z0-9_]{1,32}")


def _error(message: str) -> Dict[str, Any]:
    """Build the standard error result dict returned to the Hub/UI."""
    return {"status": "ERROR", "message": message}


def _tag(iid: str, way: str, slot: Optional[int] = None, scheduled: bool = False) -> str:
    """Build the description tag that marks one direction of impairment ``iid``
    (and, on a rule of a multi-target or scheduled impairment, which target
    slot it serves; "s" marks a scheduled one)."""
    if slot is None:
        return f"{TAG}:{iid}:{way}"
    return f"{TAG}:{iid}:{way}:{'s' if scheduled else ''}{slot}"


def _parse_tag(description: str):
    """``(id, way, user_description)`` for an LM-tagged description, else None."""
    # The tag is the first word; anything after the first space is the user's text.
    head, _, rest = (description or "").partition(" ")
    parts = head.split(":")
    # "lm-impair:<id>:<down|up>", optionally ":<slot>"; otherwise it is not ours.
    if len(parts) not in (3, 4) or parts[0] != TAG or parts[2] not in ("down", "up"):
        return None
    if len(parts) == 4 and not re.fullmatch(r"s?\d+", parts[3]):
        return None
    return parts[1], parts[2], rest


def _rule_slot(description: str) -> Optional[int]:
    """The target slot a rule serves; None for a single-target always-on rule."""
    parts = (description or "").partition(" ")[0].split(":")
    return int(parts[3].lstrip("s")) if len(parts) == 4 else None


def _scheduled_rule(description: str) -> bool:
    """True for a rule the scheduler switches (its slot tag starts with "s")."""
    parts = (description or "").partition(" ")[0].split(":")
    return len(parts) == 4 and parts[3].startswith("s")


def _address(text: str) -> str:
    """Normalise one IP address or subnet, or raise ValueError.
    A single address is kept without "/32"; a subnet keeps its prefix."""
    # strict=False accepts host bits set (e.g. 192.0.2.5/24 -> 192.0.2.0/24).
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        raise ValueError(f"{text or 'Target'} is not an IP address or subnet "
                         "(e.g. 192.0.2.5 or 192.0.2.0/24)")
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def validate(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a UI/hub spec or raise ValueError with a readable message.
    Alias names are only checked for shape here; :func:`_slots` checks they
    exist on the firewall."""
    # Targets: an ordered list, or the single "target" an older hub sends.
    target_type, targets, labels = _targets(spec)

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
    # Optional bandwidth limit: a whole number in Kbit/Mbit/Gbit per second.
    bandwidth, unit = _bandwidth(spec)
    # An impairment that neither delays, drops nor limits would do nothing.
    if delay == 0 and loss == 0 and bandwidth == 0:
        raise ValueError("Set a latency, a packet loss or a bandwidth limit")

    # "One member at a time" expands a single alias into one target per member.
    alias_members = _flag(spec.get("alias_members"), False)
    if alias_members and (target_type != "alias" or len(targets) != 1):
        raise ValueError("One member at a time needs exactly one alias target")

    # Collapse whitespace in the user description and cap its length.
    description = " ".join(str(spec.get("description") or "").split())[:200]
    # Normalised spec; "enabled" accepts the usual false-y strings.
    return {"target": ", ".join(targets), "targets": targets, "target_type": target_type,
            "labels": labels, "alias_members": alias_members,
            "schedule": _schedule(spec.get("schedule")),
            "interface": interface, "direction": direction,
            "delay": delay, "loss": loss, "bandwidth": bandwidth, "bandwidth_unit": unit,
            "description": description, "enabled": _flag(spec.get("enabled"), True)}


def _flag(value, default: bool) -> bool:
    """A UI/hub boolean ("1", "0", "true", "false", True, ...); None means ``default``."""
    if value is None or value == "":
        return default
    return str(value) not in ("0", "false", "False")


def _targets(spec: Dict[str, Any]):
    """``(target_type, targets, labels)`` of a spec, or raise ValueError.
    Addresses are normalised; alias names only checked for shape."""
    # The target kind; an older hub sends none (a plain address).
    target_type = spec.get("target_type") or "ip"
    if target_type not in TARGET_TYPES:
        raise ValueError("Target type must be ip, alias or device")
    # The ordered list, or the single "target" an older hub sends.
    raw = spec.get("targets")
    if not isinstance(raw, list):
        raw = [spec.get("target", "")]
    entries = [str(t).strip() for t in raw if str(t or "").strip()]
    if not entries:
        raise ValueError("Pick at least one target")
    if len(entries) > MAX_TARGETS:
        raise ValueError(f"At most {MAX_TARGETS} targets per impairment")
    # Aliases are matched by name; addresses (also a device's) are normalised.
    if target_type == "alias":
        bad = [t for t in entries if not ALIAS_NAME.fullmatch(t)]
        if bad:
            raise ValueError(f"{bad[0]} is not an alias name")
        targets = entries
    else:
        targets = [_address(t) for t in entries]
    if len(set(targets)) != len(targets):
        raise ValueError("Each target may be listed only once")
    # Optional display names (device names), one per target; anything else is dropped.
    labels = spec.get("labels")
    labels = ([" ".join(str(x or "").split())[:64] for x in labels]
              if isinstance(labels, list) and len(labels) == len(targets) else [])
    return target_type, targets, labels if any(labels) else []


def _schedule(raw) -> Optional[Dict[str, int]]:
    """Normalise a schedule ``{"every_hours", "for_minutes", "start"}`` or raise
    ValueError. None/empty means always on. ``start`` is epoch seconds; 0 means
    "from when it is saved" (filled in by add/edit)."""
    if not raw:
        return None
    if not isinstance(raw, dict):
        raise ValueError("Schedule must be an object")
    # Whole hours and minutes keep the windows easy to read and compare.
    try:
        every = int(raw.get("every_hours"))
        length = int(raw.get("for_minutes"))
        start = int(raw.get("start") or 0)
    except (TypeError, ValueError):
        raise ValueError("Schedule interval, duration and start must be whole numbers")
    if not 1 <= every <= 720:
        raise ValueError("Schedule interval must be 1 to 720 hours")
    # The window must end before the next one starts, or it is just always on.
    if not 1 <= length < every * 60:
        raise ValueError(f"Schedule duration must be 1 to {every * 60 - 1} minutes "
                         f"(shorter than the {every} h interval)")
    if start < 0:
        raise ValueError("Schedule start must be a time")
    return {"every_hours": every, "for_minutes": length, "start": start}


def schedule_state(schedule: Dict[str, int], slots: int, now: float) -> Dict[str, Any]:
    """Where a schedule is at ``now``: ``on`` (inside a window), ``slot`` (the
    target index impaired in the current window, or in the next one when
    off), ``next_on`` and ``next_off`` (epoch seconds; ``next_off`` is None
    when off).

    Window *k* runs from ``start + k*every`` for ``for_minutes``; it impairs
    target ``k % slots``. Pure arithmetic on the clock, so a restarted spoke
    gets the same answer as one that ran all along."""
    period = schedule["every_hours"] * 3600
    length = schedule["for_minutes"] * 60
    start = schedule["start"]
    slots = max(int(slots), 1)
    # Before the first window: off, the first window impairs target 0.
    if now < start:
        return {"on": False, "slot": 0, "next_on": start, "next_off": None}
    # Which window we are in (or just after) and how far into it.
    k, into = divmod(int(now - start), period)
    if into < length:
        return {"on": True, "slot": k % slots, "next_on": start + (k + 1) * period,
                "next_off": start + k * period + length}
    return {"on": False, "slot": (k + 1) % slots, "next_on": start + (k + 1) * period,
            "next_off": None}


class ImpairmentStore:
    """Targets and schedules of LM impairments, per firewall, in one JSON file
    (``$LM_OPNSENSE_DATA_DIR/impairments.json``).

    The tagged OPNsense objects stay the truth for what exists; this only adds
    what the firewall cannot hold: the alias or device names picked, the
    schedule, and the scheduler's last error. The file is read once and kept
    in memory; it is written only when something changes. Methods are
    blocking; async callers run them with ``asyncio.to_thread``."""

    def __init__(self, path: str = None):
        """Use ``path`` or the default file; read lazily."""
        self.path = path or os.path.join(DATA_DIR, "impairments.json")
        self._data = None
        # Commands and the scheduler call in from worker threads.
        self._lock = threading.Lock()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        """The ``{firewall: {impairment id: meta}}`` map, read on first use.
        An unreadable file starts empty (logged): the scheduler then turns
        every scheduled rule off instead of guessing."""
        if self._data is None:
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._data = json.load(f)
            except FileNotFoundError:
                self._data = {}
            except (OSError, ValueError) as e:
                logger.warning("impairment store %s unreadable (%s); starting empty", self.path, e)
                self._data = {}
        return self._data

    def _save(self, data) -> bool:
        """Write ``data`` to the file atomically; False (logged) when it cannot
        be written."""
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
            return True
        except (OSError, TypeError, ValueError) as e:
            logger.warning("impairment store %s not saved: %s", self.path, e)
            return False

    def all(self, host: str) -> Dict[str, Dict[str, Any]]:
        """Copy of every impairment's meta on firewall ``host``."""
        with self._lock:
            return {k: dict(v) for k, v in self._load().get(host, {}).items()}

    def _write(self, host: str, iid: str, meta: Optional[Dict[str, Any]]) -> bool:
        """Store (or with None, drop) ``meta``; the memory copy changes only
        once the file is written. Call with the lock held."""
        data = self._load()
        if data.get(host, {}).get(iid) == meta:
            return True
        new = {h: dict(items) for h, items in data.items()}
        if meta is None:
            new.get(host, {}).pop(iid, None)
            if host in new and not new[host]:
                new.pop(host)
        else:
            new.setdefault(host, {})[iid] = meta
        if not self._save(new):
            return False
        self._data = new
        return True

    def put(self, host: str, iid: str, meta: Optional[Dict[str, Any]]) -> bool:
        """Store (or with None, drop) the meta of ``iid``. No write when nothing
        changed. False when the file could not be written (nothing changed)."""
        with self._lock:
            return self._write(host, iid, meta)

    def update(self, host: str, iid: str, changes: Dict[str, Any]) -> bool:
        """Merge ``changes`` into the stored meta of ``iid`` (a None value
        removes that key). Does nothing for an impairment that is no longer
        stored, so a scheduler pass cannot bring back a deleted one."""
        with self._lock:
            current = self._load().get(host, {}).get(iid)
            if current is None:
                return True
            meta = {k: v for k, v in {**current, **changes}.items() if v is not None}
            return self._write(host, iid, meta)


# The spoke's store (tests swap in their own).
STORE = ImpairmentStore()


def _meta(spec: Dict[str, Any], slots: int) -> Optional[Dict[str, Any]]:
    """What :class:`ImpairmentStore` keeps for a validated spec, or None when
    the firewall objects already say it all (always-on plain addresses)."""
    if (spec["target_type"] == "ip" and not spec["schedule"] and not spec["labels"]
            and len(spec["targets"]) == 1):
        return None
    return {"target_type": spec["target_type"], "targets": spec["targets"],
            "labels": spec["labels"], "alias_members": spec["alias_members"],
            "schedule": spec["schedule"], "slots": slots, "enabled": spec["enabled"]}


async def _slots(engine, spec: Dict[str, Any]) -> List[List[str]]:
    """The addresses each target slot puts in its rules, or raise ValueError.

    Addresses map to themselves. An alias is looked up in the firewall's
    alias list and replaced by its member addresses (nested aliases are
    followed), because shaper rules do not accept alias names. With
    ``alias_members`` each member becomes its own slot."""
    if spec["target_type"] != "alias":
        return [[t] for t in spec["targets"]]
    # Read the alias list once; an unreadable list is an error, never "no members".
    res = await engine.get_all_aliases()
    if not (isinstance(res, dict) and res.get("status") == "SUCCESS"):
        raise ValueError(f"Could not read the firewall aliases: {res.get('message') if isinstance(res, dict) else res}")
    aliases = {a.get("name"): a for a in res.get("data") or [] if isinstance(a, dict)}
    slots = []
    for name in spec["targets"]:
        if name not in aliases:
            raise ValueError(f"Alias {name} does not exist on this firewall")
        slots.append(_alias_addresses(name, aliases, set()))
    # One member at a time: every member is its own slot, within the same
    # limit as a list of targets (each slot is a rule per direction).
    if spec["alias_members"]:
        if len(slots[0]) > MAX_TARGETS:
            raise ValueError(f"Alias {spec['targets'][0]} has {len(slots[0])} addresses; one member "
                             f"at a time allows at most {MAX_TARGETS}")
        return [[a] for a in slots[0]]
    return slots


def _alias_addresses(name: str, aliases: Dict[str, Any], seen: set) -> List[str]:
    """Member addresses of alias ``name`` (nested aliases followed once), or
    raise ValueError for an empty alias or a member that is not an address
    (a hostname, URL table or port)."""
    seen.add(name)
    out: List[str] = []
    # OPNsense lists members separated by commas or newlines.
    for member in re.split(r"[\s,]+", str(aliases[name].get("content") or "")):
        if not member:
            continue
        if member in aliases:
            if member not in seen:
                out += [a for a in _alias_addresses(member, aliases, seen) if a not in out]
            continue
        try:
            address = _address(member)
        except ValueError:
            raise ValueError(f"Alias {name} has a member that is not an address ({member}); "
                             "only host and network aliases can be impaired")
        if address not in out:
            out.append(address)
    if not out:
        raise ValueError(f"Alias {name} has no addresses")
    return out


def _bandwidth(spec: Dict[str, Any]):
    """``(value, unit)`` of the spec's bandwidth limit, ``(0, "")`` for none.
    Raises ValueError for a bad value or one above 4 Gbit/s."""
    raw = str(spec.get("bandwidth") or "").strip()
    # Blank or 0 means no limit.
    if raw in ("", "0"):
        return 0, ""
    unit = spec.get("bandwidth_unit") or "Mbit"
    if unit not in UNITS:
        raise ValueError("Bandwidth unit must be Kbit, Mbit or Gbit")
    try:
        value = int(raw)
    except ValueError:
        raise ValueError("Bandwidth must be a whole number")
    if value < 0:
        raise ValueError("Bandwidth must be a whole number")
    # Compare in bits/s so 5000 Mbit and 5 Gbit are both refused.
    if value * UNITS[unit] > MAX_BPS:
        raise ValueError(f"Bandwidth {value} {unit}/s is too high: {BANDWIDTH_LIMIT}")
    return value, unit


def _pipe_bandwidth(row: Dict[str, Any]):
    """``(value, unit)`` limit of an LM pipe row, ``(0, "")`` when it does not limit
    (4 Gbit/s or more, which includes pipes made before the 4 Gbit/s cap), and
    None when the bandwidth or unit cannot be read (a pipe damaged by hand)."""
    # Search rows may show the unit by its label ("Mbit/s"); get_* rows by key.
    label = _selected(row.get("bandwidthMetric")).split("/")[0].lower()
    unit = next((u for u in UNITS if u.lower() == label), "")
    try:
        value = int(row.get("bandwidth"))
    except (TypeError, ValueError):
        value = 0
    # Unreadable: kept apart from "no limit" so the impairment lists as incomplete.
    if not unit or value <= 0:
        return None
    if value * UNITS[unit] >= MAX_BPS:
        return 0, ""
    return value, unit


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


async def _create(engine, iid: str, spec: Dict[str, Any], slots: List[List[str]]):
    """Create every object for ``spec`` under id ``iid``, with one rule per
    direction and target slot. On any failure the objects already created are
    deleted again. Returns an error string or None."""
    # Delete URLs of objects created so far (for rollback), and shared enabled flag.
    created: List[str] = []
    enabled = "1" if spec["enabled"] else "0"
    # A scheduled impairment starts with only the current window's slot on
    # (none outside a window); run_schedules keeps it that way afterwards.
    schedule = spec["schedule"]
    live = schedule_state(schedule, len(slots), time.time()) if schedule else None
    error = None
    # Build pipe, rule and impairment entry for each requested direction.
    for way in DIRECTIONS[spec["direction"]]:
        # Tag every object for this direction, keeping the user's description after it.
        description = _tag(iid, way) + (f" {spec['description']}" if spec["description"] else "")
        # Pipe at the user's limit, or at 4 Gbit/s (the OPNsense maximum) so it
        # only delays/drops; 10 Gbit/s is refused by OPNsense.
        bandwidth, unit = (spec["bandwidth"], spec["bandwidth_unit"]) if spec["bandwidth"] else (4, "Gbit")
        pipe_uuid, error = await _add(engine, f"{TS}/settings/add_pipe", {"pipe": {
            "enabled": "1", "bandwidth": str(bandwidth), "bandwidthMetric": unit,
            "mask": "none", "scheduler": "", "description": description}})
        # Stop at the first failure; rollback happens after the loop.
        if error:
            break
        # Remember how to delete the pipe in case a later step fails.
        created.append(f"{TS}/settings/del_pipe/{pipe_uuid}")
        # One rule per target slot steering its traffic into the pipe on the chosen
        # interface: download matches destination=target outbound, upload matches
        # source=target inbound. Several addresses (an alias) go in as a list.
        for slot, addresses in enumerate(slots):
            on = enabled if not live else ("1" if spec["enabled"] and live["on"] and live["slot"] == slot else "0")
            tag = _tag(iid, way, slot, bool(schedule)) if schedule or len(slots) > 1 else _tag(iid, way)
            rule_desc = tag + description[len(_tag(iid, way)):]
            rule_uuid, error = await _add(engine, f"{TS}/settings/add_rule", {"rule": {
                "enabled": on, "sequence": "1", "interface": spec["interface"],
                "proto": "ip",
                "source": ",".join(addresses) if way == "up" else "any",
                "destination": ",".join(addresses) if way == "down" else "any",
                "direction": "in" if way == "up" else "out",
                "target": pipe_uuid, "description": rule_desc}})
            if error:
                break
            # Remember how to delete the rule in case a later step fails.
            created.append(f"{TS}/settings/del_rule/{rule_uuid}")
        if error:
            break
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


async def list_impairments(engine, store: ImpairmentStore = None) -> Dict[str, Any]:
    """Return all LM impairments, rebuilt from their tagged OPNsense objects
    plus the spoke's stored targets/schedule, with the schedule's next on/off
    times."""
    store = store or STORE
    # Fetch tagged rows; an error dict is passed straight back.
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    metas = await asyncio.to_thread(store.all, _host(engine))
    # One summary item per impairment id, filled from the three object types.
    pipes, rules, impairments = tagged
    items: Dict[str, Dict[str, Any]] = {}

    def item(iid):
        """Return (creating if needed) the summary item for impairment ``iid``."""
        return items.setdefault(iid, {"uuid": iid, "target": "", "interface": "",
                                      "ways": set(), "delay": 0, "loss": 0.0,
                                      "limits": set(), "slots": {}, "counts": {},
                                      "description": "", "enabled": False})

    def count(it, kind, way):
        """Count one object of ``kind`` for direction ``way`` (completeness check)."""
        it["counts"][(kind, way)] = it["counts"].get((kind, way), 0) + 1

    # Plugin entries hold delay, loss, enabled state and the user description.
    for row in impairments:
        iid, way, desc = _parse_tag(row["description"])
        it = item(iid)
        it["ways"].add(way)
        it["description"] = desc
        it["delay"] = int(row.get("delay") or 0)
        it["loss"] = float(row.get("loss") or 0)
        it["enabled"] = it["enabled"] or str(row.get("enabled")) == "1"
        count(it, "impairment", way)
    # Rules hold the interface, the addresses of each slot and whether it is
    # impairing right now; also count them as parts.
    for row in rules:
        iid, way, _ = _parse_tag(row["description"])
        it = item(iid)
        count(it, "rule", way)
        # search rows may show option fields by their display name; get_rule
        # returns the raw interface and addresses.
        res = await engine._request("GET", f"{TS}/settings/get_rule/{row['uuid']}")
        rule = res.get("rule", {}) if isinstance(res, dict) else {}
        it["interface"] = _selected(rule.get("interface")) or it["interface"]
        slot = it["slots"].setdefault(_rule_slot(row["description"]) or 0, {"addresses": "", "on": False})
        slot["addresses"] = (rule.get("source") if way == "up" else rule.get("destination")) or slot["addresses"]
        slot["on"] = slot["on"] or str(row.get("enabled")) == "1"
    # Pipes hold the bandwidth limit and count towards completeness.
    for row in pipes:
        iid, way, _ = _parse_tag(row["description"])
        it = item(iid)
        count(it, "pipe", way)
        it["limits"].add(_pipe_bandwidth(row))

    # Turn each item into the API shape.
    out = []
    now = time.time()
    for it in items.values():
        # Translate the set of directions back to the UI's direction name.
        ways = it.pop("ways")
        it["direction"] = "both" if ways == {"down", "up"} else ("upload" if ways == {"up"} else "download")
        # LM gives both pipes the same limit; differing pipes (edited by hand)
        # count as incomplete, like a half-built leftover. An unreadable pipe
        # (None) also makes it incomplete.
        limits = it.pop("limits")
        readable = limits - {None}
        it["bandwidth"], it["bandwidth_unit"] = min(readable) if readable else (0, "")
        # Exactly one pipe and one netimpair entry per direction, plus one rule
        # per direction and target slot; anything else is a half-built leftover.
        slots = it.pop("slots")
        counts = it.pop("counts")
        # The slot count is the stored one, else the highest slot seen, so a
        # missing target's rules count as incomplete too.
        meta = metas.get(it["uuid"])
        n_slots = (meta or {}).get("slots") or (max(slots) + 1 if slots else 1)
        expected = {(kind, way): 1 for way in ways for kind in ("pipe", "impairment")}
        expected.update({("rule", way): n_slots for way in ways})
        it["complete"] = (bool(ways) and counts == expected and set(slots) == set(range(n_slots))
                          and len(limits) <= 1 and None not in limits)
        # Is any rule impairing right now, and which target (by slot number).
        live = sorted(k for k, slot in slots.items() if slot["on"])
        it["active"] = bool(live)
        addresses = [slots[k]["addresses"] if k in slots else "" for k in range(n_slots)]
        _describe(it, meta, addresses, live, now)
        out.append(it)
    # Stable order: by target, then id.
    out.sort(key=lambda i: (i["target"], i["uuid"]))
    # Hand back the list.
    return {"status": "SUCCESS", "data": out}


def _describe(it: Dict[str, Any], meta: Optional[Dict[str, Any]], addresses: List[str],
              live: List[int], now: float) -> None:
    """Fill a listed impairment's target and schedule fields: from the stored
    meta when there is one, else from the rules' addresses (a plain address
    impairment, or one made before targets were stored)."""
    meta = meta or {}
    it["target_type"] = meta.get("target_type", "ip")
    it["targets"] = meta.get("targets") or addresses
    it["labels"] = meta.get("labels") or []
    it["alias_members"] = bool(meta.get("alias_members"))
    it["target"] = ", ".join(it["labels"][i] or t if it["labels"] else t
                             for i, t in enumerate(it["targets"]))
    # The slot names shown for "impairing now": a member address when an alias
    # is expanded one member at a time, else the picked target.
    names = addresses if it["alias_members"] else [
        (it["labels"][i] if it["labels"] and it["labels"][i] else t) for i, t in enumerate(it["targets"])]
    it["active_target"] = ", ".join(names[k] for k in live if k < len(names))
    it["schedule"] = meta.get("schedule")
    it["error"] = meta.get("error", "")
    it["error_at"] = meta.get("error_at")
    it["next_on"] = it["next_off"] = it["next_target"] = None
    if it["schedule"] and it["enabled"]:
        state = schedule_state(it["schedule"], len(addresses), now)
        it["next_on"], it["next_off"] = state["next_on"], state["next_off"]
        # Inside a window the next one impairs the following target.
        upcoming = (state["slot"] + 1) % len(addresses) if state["on"] else state["slot"]
        it["next_target"] = names[upcoming] if upcoming < len(names) else ""


async def _prepare(engine, spec: Dict[str, Any]):
    """Validate a spec and work out its target slots. Returns
    ``(spec, slots, None)`` or ``(None, None, error dict)``."""
    try:
        spec = validate(spec)
        slots = await _slots(engine, spec)
        await _check_interface(engine, spec["interface"])
    except ValueError as e:
        # Return the validation message to the UI.
        return None, None, _error(str(e))
    # A schedule without a start runs from now.
    if spec["schedule"] and not spec["schedule"]["start"]:
        spec["schedule"]["start"] = int(time.time())
    return spec, slots, None


async def interface_options(engine) -> Optional[List[Dict[str, str]]]:
    """The interfaces OPNsense accepts on a shaper rule, as
    ``[{"key": "lan", "description": "LAN"}, ...]``, or None when unreadable.

    ``get_rule`` without a uuid returns a new rule's defaults, with
    ``interface`` as ``{key: {"value": description, "selected": 0|1}}``: the
    keys are exactly the values add_rule accepts (assigned, enabled
    interfaces). Anything else is refused by OPNsense with "Option [] not in
    list" (its message leaves the value out)."""
    res = await engine._request("GET", f"{TS}/settings/get_rule")
    rule = res.get("rule") if isinstance(res, dict) else None
    field = rule.get("interface") if isinstance(rule, dict) else None
    if not isinstance(field, dict):
        logger.warning("impairment interface list unreadable on %s: %s", _host(engine), res)
        return None
    out = []
    for key, option in field.items():
        if not str(key):
            continue
        text = option.get("value") if isinstance(option, dict) else option
        out.append({"key": str(key), "description": str(text or key)})
    return out


async def _check_interface(engine, interface: str) -> None:
    """Raise ValueError unless ``interface`` is one the firewall offers for
    shaper rules, so a bad choice is refused before anything is created."""
    options = await interface_options(engine)
    if options is None:
        raise ValueError("Could not read the firewall's interfaces (trafficshaper get_rule); nothing was changed")
    if interface not in [o["key"] for o in options]:
        choices = ", ".join(f"{o['key']} ({o['description']})" for o in options) or "none"
        raise ValueError(f"Interface '{interface}' is not an enabled interface on this firewall; "
                         f"choose one of: {choices}")


async def get_impairment_options(engine) -> Dict[str, Any]:
    """OPNSENSE_GET_IMPAIRMENT_OPTIONS: the interfaces the form may offer."""
    options = await interface_options(engine)
    if options is None:
        return _error("Could not read the firewall's interfaces (trafficshaper get_rule)")
    return {"status": "SUCCESS", "interfaces": options}


async def add_impairment(engine, spec: Dict[str, Any], store: ImpairmentStore = None) -> Dict[str, Any]:
    """Validate ``spec``, create its OPNsense objects and apply them."""
    store = store or STORE
    # Validate first so nothing is created for a bad spec or unknown alias.
    spec, slots, error = await _prepare(engine, spec)
    if error:
        return error
    # Reading tagged rows also confirms the plugin and shaper APIs are reachable.
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    # New short id for this impairment.
    iid = uuidlib.uuid4().hex[:12]
    # Create pipes/rules/impairments (rolled back internally on failure).
    error = await _create(engine, iid, spec, slots)
    if error:
        return _error(f"Could not create the impairment: {error}")
    # Keep the names and schedule. If they cannot be saved the objects are
    # removed: a schedule would never be switched off, and alias or device
    # names would be lost.
    if not await asyncio.to_thread(store.put, _host(engine), iid, _meta(spec, len(slots))):
        await _remove(engine, iid, await _tagged(engine))
        return _error("Could not save the targets or schedule on the spoke; nothing was added")
    # Activate the new configuration on the firewall.
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    # Report success with the new id.
    logger.info("impairment %s added on %s: %s %s, %s ms, %s %% loss%s", iid, _host(engine),
                spec["target"], spec["direction"], spec["delay"], spec["loss"],
                " (scheduled)" if spec["schedule"] else "")
    return {"status": "SUCCESS", "message": f"Impairment added for {spec['target']}", "uuid": iid}


async def edit_impairment(engine, iid: str, spec: Dict[str, Any],
                          store: ImpairmentStore = None) -> Dict[str, Any]:
    """Build the new version first, then remove the old one, so a failed edit
    leaves the existing impairment untouched."""
    store = store or STORE
    # Validate the new spec before touching anything.
    spec, slots, error = await _prepare(engine, spec)
    if error:
        return error
    # Read existing tagged rows (or return the API error).
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    # The impairment being edited must exist.
    if not any(_parse_tag(r["description"])[0] == iid for rows in tagged for r in rows):
        return _error(f"Impairment {iid} not found")
    # Create the replacement under a new id; stop if that fails.
    new_id = uuidlib.uuid4().hex[:12]
    error = await _create(engine, new_id, spec, slots)
    if error:
        logger.warning("impairment %s edit on %s failed: %s", iid, _host(engine), error)
        return _error(f"Could not update the impairment: {error}")
    # Store the replacement's names/schedule; on failure drop the replacement
    # (a scheduled one could otherwise never be switched off).
    host = _host(engine)
    if not await asyncio.to_thread(store.put, host, new_id, _meta(spec, len(slots))):
        await _remove(engine, new_id, await _tagged(engine))
        return _error("Could not save the targets or schedule on the spoke; the impairment was not changed")
    # Replacement exists: now remove the old objects and meta, and apply.
    await _remove(engine, iid, tagged)
    await _forget(store, host, iid)
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    # Report success with the replacement's new id.
    logger.info("impairment %s on %s replaced by %s", iid, host, new_id)
    return {"status": "SUCCESS", "message": f"Impairment updated for {spec['target']}", "uuid": new_id}


async def delete_impairment(engine, iid: str, store: ImpairmentStore = None) -> Dict[str, Any]:
    """Delete every object of impairment ``iid`` and apply the change."""
    store = store or STORE
    # Read existing tagged rows (or return the API error).
    tagged = await _tagged(engine)
    if isinstance(tagged, dict):
        return tagged
    # Refuse unknown ids.
    if not any(_parse_tag(r["description"])[0] == iid for rows in tagged for r in rows):
        return _error(f"Impairment {iid} not found")
    # Remove the objects and the stored names/schedule, then activate the change.
    await _remove(engine, iid, tagged)
    await _forget(store, _host(engine), iid)
    applied = await _apply(engine)
    if applied["status"] != "SUCCESS":
        return applied
    logger.info("impairment %s deleted on %s", iid, _host(engine))
    return {"status": "SUCCESS", "message": f"Impairment {iid} deleted"}


async def _forget(store: ImpairmentStore, host: str, iid: str) -> None:
    """Drop a removed impairment's stored names/schedule. If the file cannot
    be written the entry stays, has no rules, and the scheduler drops it on a
    later pass; the firewall objects are already gone, so nothing impairs."""
    if not await asyncio.to_thread(store.put, host, iid, None):
        logger.warning("impairment %s on %s: stored schedule not removed yet", iid, host)


async def _toggle_rules(engine, rows, want, state: Dict[str, Any]) -> Optional[str]:
    """Set each rule row's enabled flag to ``want(row)`` ("1"/"0"), touching
    only rules that differ, then reload the shaper if anything changed or an
    earlier reload failed (``state["dirty"]``: toggles change the config only,
    the running shaper follows on a reload). Returns an error string or None."""
    changed = bool(state.get("dirty"))
    for row in rows:
        target = want(row)
        if str(row.get("enabled")) == target:
            continue
        res = await engine._request("POST", f"{TS}/settings/toggle_rule/{row['uuid']}/{target}", data={})
        # OPNsense answers {"result": "Enabled"|"Disabled"} for an explicit 1/0.
        expected = "Enabled" if target == "1" else "Disabled"
        if not (isinstance(res, dict) and res.get("result") == expected):
            return f"toggle_rule {row['uuid']} failed: {res}"
        # Keep the row current, so a fail-safe pass over the same rows sees it on,
        # and mark the shaper stale at once: if a later toggle fails, the
        # fail-safe pass must still reload what this one changed.
        row["enabled"] = target
        state["dirty"] = changed = True
    if changed:
        res = await engine._request("POST", f"{TS}/service/reconfigure", data={})
        state["dirty"] = not (isinstance(res, dict) and res.get("status") == "ok")
        if state["dirty"]:
            return f"shaper reconfigure failed: {res}"
    return None


async def run_schedules(engine, state: Dict[str, Any], now: float,
                        store: ImpairmentStore = None) -> None:
    """One scheduler pass for one firewall: put every scheduled impairment's
    rules in the state its schedule wants at ``now``.

    ``state`` is the caller's memory for this firewall: ``applied`` (impairment
    id -> slot switched on, or None for off) and ``swept``. It starts empty
    after a spoke restart, so each impairment is checked against the firewall
    once, and the first pass also switches off scheduled rules whose schedule
    is gone. Only rules that differ are toggled; a pass with nothing due makes
    no API call. A failed shaper reload is retried on every pass until it
    works (``dirty``). A stored impairment whose rules are gone (deleted, or
    a leftover) is dropped from the store whenever the rules are read (each
    window boundary, and the first pass after a restart).

    Fail-safe: when switching fails, every rule of that impairment is switched
    off (best effort) and the error is stored for the list to show; the next
    pass tries again. An impairment is never left on because of an error."""
    store = store or STORE
    host = _host(engine)
    applied = state.setdefault("applied", {})
    metas = {iid: m for iid, m in (await asyncio.to_thread(store.all, host)).items() if m.get("schedule")}
    # Which slot each scheduled impairment wants on now (None = all off).
    wanted = {}
    for iid, meta in metas.items():
        live = schedule_state(meta["schedule"], meta.get("slots") or 1, now)
        wanted[iid] = live["slot"] if live["on"] and meta.get("enabled", True) else None
    due = [iid for iid in wanted if iid not in applied or applied[iid] != wanted[iid]]
    # Forget impairments that were deleted or replaced.
    for iid in [i for i in applied if i not in wanted]:
        applied.pop(iid)
    if not due and state.get("swept") and not state.get("dirty"):
        return
    rules = await _rows(engine, f"{TS}/settings/search_rules")
    if rules is None:
        # Cannot even read the rules: nothing can be switched; retry next pass.
        for iid in due:
            await _record(store, host, iid, "could not read the shaper rules")
        return
    ours = [r for r in rules if _parse_tag(r.get("description", ""))]
    # First pass: scheduled rules (slot tag) without a schedule are switched off.
    if not state.get("swept"):
        orphans = [r for r in ours if _scheduled_rule(r["description"])
                   and _parse_tag(r["description"])[0] not in metas]
        error = await _toggle_rules(engine, orphans, lambda r: "0", state)
        if error:
            logger.warning("impairment scheduler on %s: could not switch off unscheduled rules: %s", host, error)
        else:
            state["swept"] = True
    # A stored schedule with nothing on the firewall is a deleted impairment's
    # leftover: forget it whenever the rules are read, due or not.
    for iid in list(metas):
        if not any(_parse_tag(r["description"])[0] == iid for r in ours):
            logger.warning("impairment %s on %s has no shaper rules; forgetting its schedule", iid, host)
            await asyncio.to_thread(store.put, host, iid, None)
            applied.pop(iid, None)
            if iid in due:
                due.remove(iid)
    for iid in due:
        mine = [r for r in ours if _parse_tag(r["description"])[0] == iid]
        slot = wanted[iid]
        error = await _toggle_rules(engine, mine, lambda r, slot=slot: "1" if _rule_slot(r["description"]) == slot else "0", state)
        if error:
            # Fail safe: switch the whole impairment off and report it.
            logger.warning("impairment %s on %s: schedule switch failed (%s); switching it off", iid, host, error)
            off_error = await _toggle_rules(engine, mine, lambda r: "0", state)
            if off_error:
                error = f"{error}; switching it off also failed: {off_error}"
            applied.pop(iid, None)
            await _record(store, host, iid, error)
            continue
        applied[iid] = slot
        logger.info("impairment %s on %s: %s", iid, host, "off" if slot is None else f"on (target {slot + 1})")
        await _record(store, host, iid, "")
    # Nothing was due but an earlier reload failed: retry it.
    if state.get("dirty"):
        error = await _toggle_rules(engine, [], None, state)
        if error:
            logger.warning("impairment scheduler on %s: %s", host, error)


async def _record(store: ImpairmentStore, host: str, iid: str, error: str) -> None:
    """Store (or clear, with "") the scheduler's last error for ``iid``; no
    write when it is unchanged."""
    meta = (await asyncio.to_thread(store.all, host)).get(iid)
    if meta is None or meta.get("error", "") == error:
        return
    changes = {"error": error, "error_at": int(time.time())} if error else {"error": None, "error_at": None}
    if not await asyncio.to_thread(store.update, host, iid, changes):
        logger.warning("impairment %s on %s: scheduler error not stored: %s", iid, host, error or "(cleared)")

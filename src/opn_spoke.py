"""OPNsense spoke: runs on the firewall host and turns hub commands into OPNsense API calls.

It caches read-heavy API responses, refreshes them in the background, and
handles certificate installs and network impairment commands.
"""
# Standard library, the shared base spoke, the engine and impairments.
import asyncio
import logging
import subprocess
import time
from typing import Dict, Any
from core.src.base_spoke import BaseSpoke
from opnsense_engine import OpnsenseEngine
from opn_perf_store import PerfAverager, PerfStore, counter_rates
import impairments

# Module logger.
logger = logging.getLogger("OpnSpoke")

# Hub-level system commands handled by BaseControlPlane.handle_system_command
# (shared /opt/lm/core). A spoke running a STALE core (older than the build that
# added one of these handlers — e.g. CLEAR_LOGS, added cf37058) returns None from
# handle_system_command for that command, so dispatch falls through to the
# module's handle_command. Rather than WARN + ERROR (which cascades to a FAILED
# mailbox ack → "unknown message ID" noise on the hub), degrade gracefully: the
# spoke clearly can't honour it until its core updates, so ack success and let
# the next SPOKE_UPDATE pull current core. Only system commands are muted here;
# genuinely-unknown MODULE commands still WARN + ERROR (so typos surface).
# System commands the base control plane handles; acked quietly if an old core misses one.
_SYSTEM_COMMANDS = frozenset({
    "HUB_PING", "RUN_COMMAND", "GET_AGENTS",
    "SPOKE_SET_LOG_LEVEL", "SET_LOG_LEVEL", "CLEAR_LOGS",
    "SPOKE_GET_STATUS", "SPOKE_UPDATE",
    "SPOKE_SET_HUB_SECRET", "SPOKE_UPDATE_SESSION_KEY", "SPOKE_SET_HOSTNAME",
})


class FirewallTarget:
    """One firewall this spoke manages: its API client, its read cache and its
    last performance counters.

    The hub can bind several firewalls (e.g. both boxes of an HA pair) to one
    spoke and names the one a command is for with ``firewall_id``. Each gets
    its own target, so one box's data is never served for, or written to,
    another (before this every command went to the first firewall)."""

    def __init__(self, fw_id, engine: OpnsenseEngine, cache_ttl):
        """Wrap ``engine`` for the hub firewall ``fw_id`` with an empty cache."""
        self.id = fw_id
        self.engine = engine
        self.cache_ttl = cache_ttl
        # Cached read responses and the time each was stored.
        self.cache = {}
        self.cache_ts = {}
        # Previous counter sample, for per-second rates.
        self.perf_prev = None

    def get_fresh(self, key: str):
        """The cached value for ``key`` if younger than ``cache_ttl``, else None
        (the caller fetches live). Bounds how stale a read can be."""
        if key in self.cache and (time.time() - self.cache_ts.get(key, 0)) < self.cache_ttl:
            return self.cache[key]
        return None

    def store(self, key: str, res: Dict[str, Any]) -> Dict[str, Any]:
        """Cache a successful read result; return ``res`` unchanged."""
        if isinstance(res, dict) and res.get("status") == "SUCCESS":
            self.cache[key] = res
            self.cache_ts[key] = time.time()
        return res

    def invalidate(self, res: Dict[str, Any], keys) -> Dict[str, Any]:
        """After a successful write, drop the cached reads it changes so the
        next read is live. Returns ``res`` unchanged."""
        if isinstance(res, dict) and res.get("status") == "SUCCESS":
            for k in keys:
                self.cache.pop(k, None)
                self.cache_ts.pop(k, None)
        return res


def _engine_for(fw: Dict[str, Any]) -> OpnsenseEngine:
    """API client for a hub firewall record (``host``/``port`` or the
    ``opn_*`` names). No host means unconfigured — never a localhost default."""
    host = fw.get("opn_host") or fw.get("host")
    port = fw.get("opn_port") or fw.get("port") or 8443
    return OpnsenseEngine(host=f"{host}:{port}" if host else None,
                          api_key=fw.get("api_key"), api_secret=fw.get("api_secret"))


class OpnSpoke(BaseSpoke):
    """
    OPNsense Management Spoke for Lab Manager.
    Translates Hub commands into OPNsense API actions.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        # Initialize critical components before calling super().__init__.
        # If BaseSpoke starts background threads (like updater_worker), they must be able 
        # to access the engine and cache immediately.
        # No hard-coded connection default: a firewall must be supplied via a
        # configuration object (the hub pushes opn_host/opn_port/api_key/
        # api_secret through UPDATE_CONFIG). Until a host is configured the
        # engine is UNCONFIGURED and every API call short-circuits with
        # "no firewall configured" instead of connecting to localhost:8443.
        """Build the firewall targets from config, then start the base spoke."""
        # Read cache: filled by the 1h refresh loop and by every live read.
        # Reads are capped at _cache_ttl so a write is visible right away
        # (write handlers also drop the reads they change).
        self._cache_ttl = config.get("cache_ttl", 60)  # seconds; cap read staleness
        # The default firewall (the top-level config fields): what a command
        # with no ``firewall_id`` (an older hub, or a spoke-wide read) talks to.
        self.engine = _engine_for(config)
        self._default = FirewallTarget(config.get("id"), self.engine, self._cache_ttl)
        # The other firewalls bound to this spoke, by hub firewall id.
        self._targets: Dict[str, FirewallTarget] = {}
        self._set_firewalls(config.get("firewalls"))

        # Refresh scheduling.
        self._refresh_interval = config.get("refresh_interval", 3600) # seconds, default 1h
        self._refresh_task = None

        # Performance history: the hub link (set by the control plane), the
        # 5-minute averager and the 7-day store.
        self.control_plane = None
        self.perf = PerfAverager()
        self.perf_store = PerfStore()
        self._bg_tasks = []

        # Start the base spoke, then the refresh loop.
        super().__init__(spoke_id, config)
        self._start_refresh_loop()

    def _all_targets(self):
        """The default firewall followed by the others."""
        return [self._default, *self._targets.values()]

    def _set_firewalls(self, firewalls) -> None:
        """Build a target for every firewall the hub bound to this spoke other
        than the default one. A target whose address and credentials did not
        change keeps its cache."""
        targets = {}
        for fw in firewalls or []:
            # Skip malformed entries and the default firewall (handled by UPDATE_CONFIG).
            if not isinstance(fw, dict) or not fw.get("id") or fw["id"] == self._default.id:
                continue
            engine = _engine_for(fw)
            old = self._targets.get(fw["id"])
            same = old and ((old.engine.host, old.engine.api_key, old.engine.api_secret)
                            == (engine.host, engine.api_key, engine.api_secret))
            targets[fw["id"]] = old if same else FirewallTarget(fw["id"], engine, self._cache_ttl)
        self._targets = targets

    def _target_for(self, data) -> "FirewallTarget | None":
        """The firewall a command is for: ``data["firewall_id"]`` when the hub
        names one, else the default firewall (older hubs send no id). None for
        an id this spoke does not manage, so the command fails instead of
        silently running on another box."""
        fw_id = data.get("firewall_id") if isinstance(data, dict) else None
        if not fw_id or fw_id == self._default.id:
            return self._default
        return self._targets.get(fw_id)

    def _start_refresh_loop(self):
        """Starts the background cache refresh task."""
        # Cancel any running loop.
        if self._refresh_task:
            self._refresh_task.cancel()
        # Start a new loop task if an event loop is running.
        import asyncio
        try:
            self._refresh_task = asyncio.create_task(self._cache_refresh_loop())
        except RuntimeError:
            # Fallback if the loop isn't running yet during initialization
            # No loop yet.
            logger.warning("Event loop not running; refresh loop will be started manually or on first request")

    # Performance is sampled this often and averaged into 5-minute buckets.
    _PERF_SAMPLE_S = 60

    def start_background_loops(self) -> None:
        """Start the performance sampling loop once. Called by the standalone
        control plane and by the generic agent's role hook."""
        if self._bg_tasks:
            return
        self._bg_tasks = [asyncio.create_task(self._perf_sample_loop()),
                          asyncio.create_task(self._impair_schedule_loop())]
        logger.info("opnsense performance sampling and impairment schedule loops started")

    # Scheduled impairments are checked this often, so a window opens or
    # closes at most this late.
    _IMPAIR_TICK_S = 30

    async def _impair_schedule_loop(self):
        """Switch scheduled impairments on and off at their window boundaries.
        The per-firewall state lives in memory only: after a restart the first
        pass re-checks every scheduled impairment against its schedule."""
        state: Dict[str, Dict[str, Any]] = {}
        while True:
            await self._impair_schedule_tick(state, time.time())
            await asyncio.sleep(self._IMPAIR_TICK_S)

    async def _impair_schedule_tick(self, state, now: float):
        """One scheduler pass over every configured firewall; one firewall's
        error never stops the others."""
        for fw in self._all_targets():
            if not fw.engine.is_configured():
                continue
            try:
                await impairments.run_schedules(fw.engine, state.setdefault(fw.engine.host, {}), now)
            except Exception as e:  # noqa: BLE001 - loop must never die
                logger.warning("impairment schedule pass on %s failed: %s", fw.engine.host, e)

    async def _perf_sample_loop(self):
        """Sample the firewall every minute and push 5-minute averages."""
        while True:
            await asyncio.sleep(self._PERF_SAMPLE_S)
            try:
                await self._perf_sample_tick(time.time())
            except Exception as e:  # noqa: BLE001 - loop must never die
                logger.debug("opnsense perf sample tick error: %s", e)

    async def _perf_sample_tick(self, now: float):
        """Take one sample, close ended buckets, store them and push the
        buckets the hub hasn't received yet."""
        # Sample every configured firewall; the hub's firewall id names its series.
        for fw in self._all_targets():
            if not (fw.id and fw.engine.is_configured()):
                continue
            res = await fw.engine.get_perf_sample()
            if res.get("status") == "SUCCESS":
                sample = res["data"]
                # Rates need the previous counters; gauges are used as they are.
                metrics = dict(sample["metrics"])
                metrics.update(counter_rates(fw.perf_prev, sample))
                # A sample without counters must not replace good ones.
                if sample.get("interfaces"):
                    fw.perf_prev = sample
                if metrics:
                    self.perf.add(fw.id, metrics, now)
        closed = self.perf.close_finished(now)
        if closed:
            await asyncio.to_thread(self.perf_store.add, closed, now)
        # Send what the hub hasn't received; unsent buckets wait on disk.
        cp = self.control_plane
        if cp is None or getattr(cp, "_hub_ws", None) is None:
            return
        batch = await asyncio.to_thread(self.perf_store.unsent)
        if not batch:
            return
        # STORAGE_PERF_SAMPLE is the hub's generic perf message; a hub too
        # old to know module "opnsense" ignores it.
        sent = await cp.send_to_hub("STORAGE_PERF_SAMPLE",
                                    {"module": "opnsense", "samples": batch})
        # lm core's send_to_hub (core/src/messaging/control_plane.py) returns
        # True once the frame is written and False otherwise, never None. Only
        # a confirmed send counts; anything else is retried next minute.
        if sent is True:
            await asyncio.to_thread(self.perf_store.mark_sent, batch)

    async def _cache_refresh_loop(self):
        """Background loop to refresh the cache periodically.

        Primes the cache once immediately on startup (before the first sleep)
        so a freshly-(re)started spoke doesn't serve a cold cache for the whole
        interval — that left every cacheable read (notably NAT policies, whose
        live fetch probes 3 endpoints sequentially) to a slow live round-trip
        that blew the hub's request_response budget and rendered the tab empty.
        """
        # Prime the cache once at startup.
        try:
            logger.info("Priming OPNsense cache on startup")
            await self.refresh_cache()
        except Exception as e:
            # Priming failed.
            logger.error(f"Initial OPNsense cache refresh failed: {e}")
        # Then refresh every interval until cancelled.
        while True:
            try:
                # Sleep, then refresh.
                await asyncio.sleep(self._refresh_interval)
                logger.debug(f"Performing scheduled OPNsense cache refresh (interval: {self._refresh_interval}s)")
                await self.refresh_cache()
            except asyncio.CancelledError:
                # Stopped.
                break
            except Exception as e:
                # Log and wait a minute before retrying.
                logger.error(f"Error in OPNsense cache refresh loop: {e}")
                await asyncio.sleep(60) # Wait before retry on error

    async def refresh_cache(self) -> Dict[str, Any]:
        """Triggers a full update of all cacheable API responses."""
        # Refresh every configured firewall; the default one's results keep
        # their old place, the others are listed by firewall id.
        if not any(fw.engine.is_configured() for fw in self._all_targets()):
            # No firewall configured: skip the sweep so an unconfigured spoke
            # logs one throttled "no firewall configured" line, not one per endpoint.
            self.engine._log_unconfigured()
            return {}
        results = {"status": "SUCCESS", "refreshed": await self._refresh_target(self._default)}
        others = {fw.id: await self._refresh_target(fw) for fw in self._targets.values()}
        if others:
            results["firewalls"] = others
        return results

    async def _refresh_target(self, fw: FirewallTarget) -> Dict[str, str]:
        """Re-read every cacheable endpoint of one firewall into its cache.
        Returns the per-command outcome."""
        if not fw.engine.is_configured():
            return {}
        # Commands to cache and the engine method for each.
        engine = fw.engine
        cache_map = {
            "GET_INTERFACE_STATUS": engine.get_interface_status,
            "GET_SYSTEM_HEALTH": engine.get_system_health,
            # OPNSENSE_GET_DHCP_LEASES is intentionally NOT in the refresh sweep:
            # handle_command's cache_map excludes it (leases are volatile and a
            # 1h-cached empty list rendered the DHCP tab empty; see the comment
            # in handle_command).
            "OPNSENSE_GET_ARP_TABLE": engine.get_arp_table,
            "OPNSENSE_GET_ALL_RULES": engine.get_all_firewall_rules,
            "OPNSENSE_GET_FIREWALL_STATS": engine.get_firewall_stats,
            "OPNSENSE_GET_NAT_POLICIES": engine.get_nat_policies,
            "OPNSENSE_GET_DNS_RECORDS": engine.get_dns_records,
            "OPNSENSE_GET_ALIASES": engine.get_all_aliases,
        }

        # Refresh each; one failure does not stop the rest.
        results = {}
        for cmd, method in cache_map.items():
            try:
                res = fw.store(cmd, await method())
                # Only successes are cached; note the error otherwise.
                if isinstance(res, dict) and res.get("status") == "SUCCESS":
                    results[cmd] = "OK"
                else:
                    results[cmd] = f"Error: {res.get('message') if isinstance(res, dict) else res}"
            except Exception as e:
                # Method raised.
                logger.error(f"Failed to refresh cache for {cmd} on firewall {fw.id}: {e}")
                results[cmd] = f"Exception: {str(e)}"
        return results

    async def _install_cert_on_devices(self, data: Dict[str, Any], devices: list) -> Dict[str, Any]:
        """Import a certificate on each listed firewall in parallel and summarise the results."""
        # asyncio for gather.
        import asyncio

        async def one(d):
            """Install the certificate on one firewall and return its result row."""
            # Name and host:port.
            name = d.get("name") or d.get("host")
            host = f"{d['host']}:{d.get('port') or 8443}"
            # Credentials are required.
            if not (d.get("api_key") and d.get("api_secret")):
                return {"device_id": name, "name": name, "ip": host, "cert_capable": True,
                        "status": "ERROR", "message": "missing API key/secret"}
            # A client for this firewall.
            eng = OpnsenseEngine(host=host, api_key=d["api_key"], api_secret=d["api_secret"])
            # Import; an error becomes an ERROR row.
            try:
                r = await eng.import_cert(data.get("domain", ""), data.get("fullchain", ""),
                                          data.get("privkey", ""))
            except Exception as e:  # noqa: BLE001 — one box must not sink the others
                # Import failed.
                r = {"status": "ERROR", "message": str(e)}
            # Result row.
            return {"device_id": name, "name": name, "ip": host, "cert_capable": True,
                    "status": r.get("status"), "message": r.get("message")}

        # Run all in parallel.
        results = await asyncio.gather(*(one(d) for d in devices))
        # Successes.
        ok = [r for r in results if r["status"] == "SUCCESS"]
        # Log each result.
        for r in results:
            logger.info("[cert] %s on %s (%s): %s — %s", data.get("domain"), r["name"],
                        r["ip"], r["status"], r["message"])
        # Summary across all firewalls.
        summary = "; ".join(f"{r['name']}: {r['message']}" for r in results)
        return {"status": "SUCCESS" if len(ok) == len(results) else "ERROR",
                "message": f"{len(ok)}/{len(results)} firewall(s) — {summary}",
                "devices": results}

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a hub command to the matching OPNsense engine action.

        Routes ``OPNSENSE_*`` / ``GET_*`` commands (sent hub → spoke over the
        WebSocket) to ``OpnsenseEngine`` methods against the firewall named by
        ``data["firewall_id"]`` (the default firewall when there is none).
        Read-heavy commands are served from the in-memory cache primed by
        ``_cache_refresh_loop`` (DHCP leases are the deliberate uncached
        exception); writes go straight to the live API. Sensitive fields
        (``api_key``/``api_secret``/``password``/``privkey``/``private_key``)
        are full-masked in the debug log line. Unknown commands return an
        ``ERROR`` envelope.
        """
        # Normalize command type to uppercase for case-insensitive matching
        normalized_cmd = command_type.upper()

        # Mask sensitive data for logging — FULL mask. The previous
        # "{v[:4]}...{v[-4:]}" leaked both ends of the credential (8+ chars of
        # an api_key/api_secret exposed in telemetry/SPOKE_LOG relayed to the
        # hub), which is a meaningful fraction of a typical OPNsense API secret.
        _SENSITIVE = {"api_key", "api_secret", "password", "privkey", "private_key"}
        def _mask(v):
            """Return a copy of ``v`` with sensitive dict values masked."""
            # Dict: mask sensitive keys, recurse into the rest.
            if isinstance(v, dict):
                return {k: ("********" if k in _SENSITIVE else _mask(x)) for k, x in v.items()}
            # List: recurse.
            if isinstance(v, list):
                return [_mask(x) for x in v]
            # Anything else as-is.
            return v
        # Masked copy for logging.
        log_data = _mask(data)

        # Log the command.
        logger.debug(f"Handling Opn Command: {command_type} with data {log_data}")

        if normalized_cmd == "UPDATE_CONFIG":
            # Store the new config.
            logger.info(f"Updating OPNsense configuration: {log_data}")
            self.config = data
            # A list with no default id: the hub has no firewall bound to this
            # spoke any more (the last one was deleted or moved). Forget every
            # firewall and its credentials. Older hubs never send `firewalls`.
            if "firewalls" in data and not data.get("id") and not data.get("firewalls"):
                self.engine.host = self.engine.api_key = self.engine.api_secret = None
                self._default = FirewallTarget(None, self.engine, self._cache_ttl)
                self._targets = {}
                logger.info("OPNsense spoke has no firewall bound; cleared")
                return {"status": "SUCCESS", "message": "OPNsense configuration cleared by Hub"}
            # Update engine credentials if they are provided
            # Connection fields given: update the engine.
            if any(k in data for k in ["opn_host", "host", "opn_port", "port", "api_key", "api_secret"]):
                # Current host and port.
                cur_host = self.engine.host or ""
                cur_h = cur_host.split(':')[0] if ':' in cur_host else (cur_host or None)
                cur_p = cur_host.split(':')[1] if ':' in cur_host else "8443"
                # New host and port, falling back to current values.
                host = data.get("opn_host") or data.get("host") or cur_h
                port = str(data.get("opn_port") or data.get("port") or cur_p)
                # Stay unconfigured (host=None) until a real host is supplied —
                # never fall back to a localhost default.
                new_host = f"{host}:{port}" if host else None
                # A different box: its cached reads belong to the old one.
                if new_host != self.engine.host:
                    self._default.cache.clear()
                    self._default.cache_ts.clear()
                self.engine.host = new_host
                # Use `or` (not dict.get(key, default)) so a falsy/explicit-null
                # api_key/api_secret in the payload can't silently wipe
                # already-configured credentials — the spoke would then
                # report "no firewall configured" again despite a prior
                # successful UPDATE_CONFIG.
                self.engine.api_key = data.get("api_key") or self.engine.api_key
                self.engine.api_secret = data.get("api_secret") or self.engine.api_secret
            # The default firewall's hub id (kept when a partial update omits it).
            self._default.id = data.get("id") or self._default.id
            # Every firewall bound to this spoke (newer hubs); older hubs send
            # only the default one, which leaves the list untouched.
            if "firewalls" in data:
                self._set_firewalls(data.get("firewalls"))
                logger.info("OPNsense spoke manages %d firewall(s)", len(self._all_targets()))

            # Update refresh interval and restart loop if provided
            # New refresh interval: apply and restart the loop.
            if "refresh_interval" in data:
                # Only numbers.
                new_interval = data.get("refresh_interval")
                if isinstance(new_interval, (int, float)):
                    self._refresh_interval = new_interval
                    logger.info(f"Updating OPNsense refresh interval to {new_interval}s")
                    self._start_refresh_loop()

            # Done.
            return {"status": "SUCCESS", "message": "OPNsense configuration updated from Hub"}

        # The firewall this command is for; an id we don't manage is an error,
        # never a silent fallback to another box.
        fw = self._target_for(data)
        if fw is None:
            logger.warning("%s for unknown firewall %s", normalized_cmd, data.get("firewall_id"))
            return {"status": "ERROR",
                    "message": f"Firewall {data.get('firewall_id')} is not configured on this "
                               "spoke yet (re-save it in Setup → Firewalls)"}
        engine = fw.engine

        # Performance history (5-minute averages) for a start/end range.
        if normalized_cmd == "OPNSENSE_GET_PERF_HISTORY":
            rng = data or {}
            try:
                end = float(rng.get("end") or time.time())
                start = float(rng.get("start") or end - 86400)
            except (TypeError, ValueError):
                return {"status": "ERROR", "message": "start/end must be epoch seconds"}
            device_id = fw.id or ""
            rows = await asyncio.to_thread(self.perf_store.history, device_id, start, end)
            return {"status": "SUCCESS", "interval": 300, "data": rows,
                    "message": f"{len(rows)} 5-minute average(s)"}

        # Spoke version.
        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # Manual cache refresh.
        if normalized_cmd == "OPNSENSE_REFRESH_CACHE":
            logger.info("Manual OPNsense cache refresh triggered")
            return await self.refresh_cache()

        # Sync path: an explicit ``limit`` on DHCP leases bypasses the
        # (200-capped) cache so the firewall→NetBox discovery sync gets the full
        # lease set. The interactive path sends no limit and gets the capped
        # cached value (LLM payload guard preserved).
        if (normalized_cmd == "OPNSENSE_GET_DHCP_LEASES"
                and isinstance(data, dict) and data.get("limit") is not None):
            # Parse the limit; default 200.
            try:
                limit = int(data.get("limit", 200))
            except (TypeError, ValueError):
                # Bad limit.
                limit = 200
            # Live, full lease list.
            return await engine.get_dhcp_leases(limit=limit)

        # Check if command is cacheable and has a cached value
        cache_map = {
            "GET_INTERFACE_STATUS": "interface_status",
            "GET_SYSTEM_HEALTH": "system_health",
            # DHCP leases are NOT served from this cache. Leases are volatile
            # (clients get/release constantly) and the Kea leases4/search
            # endpoint is a single fast GET — unlike NAT's 3-endpoint probe,
            # there is no slow-live-fetch timeout to avoid. Caching them for
            # the 1h refresh interval served a stale-empty list (a refresh that
            # momentarily saw no leases, or a startup prime before Kea was
            # ready) for up to an hour, rendering the DHCP Leases tab empty
            # even though a live fetch would return rows. Interactive reads
            # always go live below; the sync path's limit-bypass above is
            # already live.
            "OPNSENSE_GET_ARP_TABLE": "arp_table",
            "OPNSENSE_GET_ALL_RULES": "all_rules",
            "OPNSENSE_GET_FIREWALL_STATS": "firewall_stats",
            "OPNSENSE_GET_NAT_POLICIES": "nat_policies",
            "OPNSENSE_GET_DNS_RECORDS": "dns_records",
            "OPNSENSE_GET_ALIASES": "aliases",
        }

        if normalized_cmd in cache_map:
            # Serve a fresh cached copy if there is one.
            fresh = fw.get_fresh(normalized_cmd)
            if fresh is not None:
                logger.debug(f"Returning cached data for {normalized_cmd}")
                return fresh
            # Stale or cold → fall through to the live fetch below (which
            # re-caches via fw.store). Nothing older than _cache_ttl is served.

        if normalized_cmd == "PROBE_API":
            # Raw GET of a given API path.
            path = data.get("path")
            if not path:
                return {"status": "ERROR", "message": "Missing path for PROBE_API"}
            return await engine._request("GET", path)

        if normalized_cmd == "OPNSENSE_UPDATE_ALIAS":
            # Data expected: {"name": "web_servers", "hosts": ["1.1.1.1", "2.2.2.2"]}
            # Replace an alias's hosts, then drop the cached alias list.
            return fw.invalidate(
                await engine.manage_alias(data.get("name"), data.get("hosts"), action="update"),
                ["OPNSENSE_GET_ALIASES"])

        elif normalized_cmd == "GET_INTERFACE_STATUS":
            # Live interface status, cached.
            return fw.store(normalized_cmd, await engine.get_interface_status())

        elif normalized_cmd == "GET_SYSTEM_HEALTH":
            # Live system health, cached.
            return fw.store(normalized_cmd, await engine.get_system_health())

        elif normalized_cmd == "OPNSENSE_GET_OVERVIEW":
            # Live dashboard stats; the hub cache already bounds how often this runs.
            return await engine.get_overview()

        elif normalized_cmd == "OPNSENSE_GET_RULES_BY_IP":
            # Reuse the cached OPNSENSE_GET_ALL_RULES result when present
            # instead of re-fetching the whole ruleset (a fresh curl) per
            # IP query — the all-rules fetch already runs on the 1h refresh
            # loop, so a per-IP lookup was paying a full ruleset round-trip
            # for nothing. Fall back to a live fetch if the cache is cold.
            # Filter the cached ruleset by IP.
            ip = data.get("ip", "")
            cached_rules = fw.get_fresh("OPNSENSE_GET_ALL_RULES")
            if cached_rules and cached_rules.get("status") == "SUCCESS":
                rules = cached_rules.get("data", [])
                # Guard against a non-list.
                if not isinstance(rules, list):
                    rules = []
                # Rules whose source or destination mentions the IP.
                filtered = [
                    r for r in rules
                    if ip in str(r.get("source", "")) or ip in str(r.get("destination", ""))
                ]
                return {"status": "SUCCESS", "ip": ip, "rules": filtered,
                        "source": "cache"}
            # Cache cold: live lookup.
            return await engine.get_rules_for_ip(ip)

        elif normalized_cmd == "OPNSENSE_CURL_TEST":
            try:
                # Run curl against the OPNsense host
                cmd = ["curl", "-k", f"https://{engine.host}/"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return {
                    "status": "SUCCESS",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.returncode
                }
            except Exception as e:
                # curl failed.
                return {"status": "ERROR", "message": f"Curl test failed: {str(e)}"}
        elif normalized_cmd == "OPNSENSE_GET_DHCP_LEASES":
            # Live DHCP leases.
            return await engine.get_dhcp_leases()

        elif normalized_cmd == "OPNSENSE_GET_ARP_TABLE":
            # Live reads, cached for next time.
            return fw.store(normalized_cmd, await engine.get_arp_table())

        elif normalized_cmd == "OPNSENSE_GET_ALL_RULES":
            return fw.store(normalized_cmd, await engine.get_all_firewall_rules())

        elif normalized_cmd == "OPNSENSE_GET_FIREWALL_STATS":
            return fw.store(normalized_cmd, await engine.get_firewall_stats())

        elif normalized_cmd == "OPNSENSE_GET_NAT_POLICIES":
            return fw.store(normalized_cmd, await engine.get_nat_policies())

        elif normalized_cmd == "OPNSENSE_GET_DNS_RECORDS":
            return fw.store(normalized_cmd, await engine.get_dns_records())

        elif normalized_cmd == "OPNSENSE_GET_ALIASES":
            return fw.store(normalized_cmd, await engine.get_all_aliases())

        elif normalized_cmd == "OPNSENSE_ADD_ALIAS":
            # Writes: run, then drop the cached lists they change.
            return fw.invalidate(await engine.add_alias(
                data.get("name", ""),
                data.get("type", "host"),
                data.get("content", ""),
                data.get("description", ""),
                data.get("category", "")
            ), ["OPNSENSE_GET_ALIASES"])

        elif normalized_cmd == "OPNSENSE_DEL_ALIAS":
            return fw.invalidate(
                await engine.delete_alias(data.get("uuid", "")),
                ["OPNSENSE_GET_ALIASES"])

        elif normalized_cmd == "OPNSENSE_ADD_RULE":
            return fw.invalidate(
                await engine.add_firewall_rule_and_apply(data.get("rule", {})),
                ["OPNSENSE_GET_ALL_RULES", "OPNSENSE_GET_RULES_BY_IP"])

        elif normalized_cmd == "OPNSENSE_DEL_RULE":
            return fw.invalidate(
                await engine.delete_firewall_rule_and_apply(data.get("rule_id", "")),
                ["OPNSENSE_GET_ALL_RULES", "OPNSENSE_GET_RULES_BY_IP"])

        elif normalized_cmd == "OPNSENSE_ADD_NAT_RULE":
            return fw.invalidate(await engine.add_nat_rule(
                data.get("nat_type", "d_nat"),
                data.get("rule", {})
            ), ["OPNSENSE_GET_NAT_POLICIES"])

        elif normalized_cmd == "OPNSENSE_DEL_NAT_RULE":
            return fw.invalidate(await engine.delete_nat_rule(
                data.get("nat_type", "d_nat"),
                data.get("uuid", "")
            ), ["OPNSENSE_GET_NAT_POLICIES"])

        elif normalized_cmd == "OPNSENSE_ADD_DNS_RECORD":
            return fw.invalidate(await engine.add_dns_record(
                data.get("hostname", ""),
                data.get("domain", ""),
                data.get("ip", ""),
                data.get("description", "")
            ), ["OPNSENSE_GET_DNS_RECORDS"])

        elif normalized_cmd == "OPNSENSE_DEL_DNS_RECORD":
            return fw.invalidate(
                await engine.delete_dns_record(data.get("uuid", "")),
                ["OPNSENSE_GET_DNS_RECORDS"])

        elif normalized_cmd == "OPNSENSE_EDIT_RULE":
            return fw.invalidate(await engine.edit_firewall_rule(
                data.get("uuid", ""),
                data.get("rule", {})
            ), ["OPNSENSE_GET_ALL_RULES", "OPNSENSE_GET_RULES_BY_IP"])

        elif normalized_cmd == "OPNSENSE_EDIT_ALIAS":
            return fw.invalidate(await engine.edit_alias(
                data.get("uuid", ""),
                data.get("name", ""),
                data.get("type", "host"),
                data.get("content", ""),
                data.get("description", ""),
                data.get("category", "")
            ), ["OPNSENSE_GET_ALIASES"])

        elif normalized_cmd == "OPNSENSE_EDIT_NAT_RULE":
            return fw.invalidate(await engine.edit_nat_rule(
                data.get("nat_type", "d_nat"),
                data.get("uuid", ""),
                data.get("rule", {})
            ), ["OPNSENSE_GET_NAT_POLICIES"])

        elif normalized_cmd == "OPNSENSE_EDIT_DNS_RECORD":
            return fw.invalidate(await engine.edit_dns_record(
                data.get("uuid", ""),
                data.get("hostname", ""),
                data.get("domain", ""),
                data.get("ip", ""),
                data.get("description", "")
            ), ["OPNSENSE_GET_DNS_RECORDS"])

        # Network impairments (latency / loss / bandwidth for addresses, aliases
        # or devices, always on or scheduled; os-netimpair plugin). Few objects
        # and always read live, so not cached.
        elif normalized_cmd == "OPNSENSE_GET_IMPAIRMENTS":
            # Impairments: list, add, edit, delete.
            return await impairments.list_impairments(engine)

        elif normalized_cmd == "OPNSENSE_GET_IMPAIRMENT_OPTIONS":
            # The interfaces a shaper rule accepts (for the form's dropdown).
            return await impairments.get_impairment_options(engine)

        elif normalized_cmd == "OPNSENSE_ADD_IMPAIRMENT":
            return await impairments.add_impairment(engine, data)

        elif normalized_cmd == "OPNSENSE_EDIT_IMPAIRMENT":
            return await impairments.edit_impairment(engine, data.get("uuid", ""), data)

        elif normalized_cmd == "OPNSENSE_DEL_IMPAIRMENT":
            return await impairments.delete_impairment(engine, data.get("uuid", ""))

        elif normalized_cmd in ("INSTALL_CERT", "OPNSENSE_INSTALL_CERT"):
            # NOTE: the hub (cert_distribution.py) pushes a BARE ``INSTALL_CERT``
            # to every cert-capable target (firewall/hypervisor/directory) — the
            # same command pxmx/ldap receive. This branch previously matched only
            # the OPNSENSE_-prefixed alias, so the hub's INSTALL_CERT fell through
            # to unknown and certs never installed on OPNsense. Accept both.
            # Hub-brokered cert distribution: the hub pulls cert material from the
            # le (Let's Encrypt) spoke and pushes INSTALL_CERT here; this spoke
            # applies it to the firewall it's in the vicinity of. ``privkey`` is a
            # secret — masked in the log line above (see _SENSITIVE) and never
            # persisted beyond the import call.
            # ``devices`` (hub-supplied, vault-resolved) = EVERY firewall bound
            # to this spoke (e.g. an HA pair). Each gets the cert + WebGUI
            # activation directly instead of relying on HA config sync.
            # Firewalls listed by the hub.
            devices = [d for d in (data.get("devices") or []) if isinstance(d, dict) and d.get("host")]
            # None listed: import on this spoke's own firewall.
            if not devices:
                return await engine.import_cert(
                    data.get("domain", ""),
                    data.get("fullchain", ""),
                    data.get("privkey", ""),
                )
            # Import on each listed firewall.
            return await self._install_cert_on_devices(data, devices)

        elif normalized_cmd == "SEARCH_DHCP":
            # Tenant-scoped DHCP search across dynamic leases AND static
            # reservations. The hub normalizes ``q`` (MAC → lower-colon) and
            # sends ``prefixes`` + ``is_admin``; scoping is enforced
            # engine-side (see OpnsenseEngine.search_dhcp). We only forward
            # the contract fields — never filter spoke-side, never trust the
            # hub to have pre-filtered.
            # Search term; scoping is done in the engine.
            q = data.get("q", "").strip()
            return await engine.search_dhcp(
                q,
                prefixes=data.get("prefixes") or [],
                is_admin=bool(data.get("is_admin")),
            )

        else:
            # Known system command on a stale core: ack quietly.
            if command_type in _SYSTEM_COMMANDS:
                # Stale /opt/lm/core: this system command should have been
                # intercepted by handle_system_command but wasn't (core predates
                # its handler). Don't WARN+ERROR (FAILED ack cascade); the next
                # SPOKE_UPDATE pulls current core. See _SYSTEM_COMMANDS above.
                logger.info("Stale-core fallthrough for system command %s "
                            "(handle_system_command returned None); update spoke "
                            "to clear.", command_type)
                return {"status": "SUCCESS",
                        "message": f"{command_type} not applied — spoke core stale, update needed"}
            # Unknown command.
            logger.warning(f"Unknown Opn command type: {command_type}")
            return {"status": "ERROR", "message": f"Command {command_type} not supported by opnsense module"}

    async def get_status(self) -> Dict[str, Any]:
        """Native LM status report for the OPNsense instance.

        Serves the cached ``GET_SYSTEM_HEALTH`` entry when the refresh loop
        has primed it (avoids a fresh curl on every hub heartbeat/status poll)
        and falls back to a live fetch when the cache is cold or stale."""
        # Cached health if primed, else a live fetch.
        cached = self._default.cache.get("GET_SYSTEM_HEALTH")
        if cached and cached.get("status") == "SUCCESS":
            health = cached
        else:
            health = self._default.store(
                "GET_SYSTEM_HEALTH", await self.engine.get_system_health())
        # Status report.
        return {
            "spoke_id": self.spoke_id,
            "module": "opnsense-mgmt",
            "system_health": health,
            "connection": "CONNECTED" if health.get("status") == "SUCCESS" else "DISCONNECTED"
        }

    def get_version(self) -> str:
        """Returns the current version of the OPNsense module (from the VERSION file)."""
        # Read the VERSION file.
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            # No VERSION file.
            return "unknown"
import logging
import subprocess
from typing import Dict, Any
from core.src.base_spoke import BaseSpoke
from opnsense_engine import OpnsenseEngine

logger = logging.getLogger("OpnSpoke")

class OpnSpoke(BaseSpoke):
    """
    OPNsense Management Spoke for Lab Manager.
    Translates Hub commands into OPNsense API actions.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        # Initialize critical components before calling super().__init__.
        # If BaseSpoke starts background threads (like updater_worker), they must be able 
        # to access the engine and cache immediately.
        host = config.get("opn_host") or config.get("host") or "localhost"
        port = str(config.get("opn_port") or config.get("port") or "8443")
        combined_host = f"{host}:{port}"

        self.engine = OpnsenseEngine(
            host=combined_host,
            api_key=config.get("api_key"),
            api_secret=config.get("api_secret")
        )

        # Caching and Scheduling
        self._cache = {}
        self._refresh_interval = config.get("refresh_interval", 3600) # seconds, default 1h
        self._refresh_task = None

        super().__init__(spoke_id, config)
        self._start_refresh_loop()

    def _start_refresh_loop(self):
        """Starts the background cache refresh task."""
        if self._refresh_task:
            self._refresh_task.cancel()
        import asyncio
        try:
            self._refresh_task = asyncio.create_task(self._cache_refresh_loop())
        except RuntimeError:
            # Fallback if the loop isn't running yet during initialization
            logger.warning("Event loop not running; refresh loop will be started manually or on first request")

    async def _cache_refresh_loop(self):
        """Background loop to refresh the cache periodically.

        Primes the cache once immediately on startup (before the first sleep)
        so a freshly-(re)started spoke doesn't serve a cold cache for the whole
        interval — that left every cacheable read (notably NAT policies, whose
        live fetch probes 3 endpoints sequentially) to a slow live round-trip
        that blew the hub's request_response budget and rendered the tab empty.
        """
        try:
            logger.info("Priming OPNsense cache on startup")
            await self.refresh_cache()
        except Exception as e:
            logger.error(f"Initial OPNsense cache refresh failed: {e}")
        while True:
            try:
                await asyncio.sleep(self._refresh_interval)
                logger.info(f"Performing scheduled OPNsense cache refresh (interval: {self._refresh_interval}s)")
                await self.refresh_cache()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in OPNsense cache refresh loop: {e}")
                await asyncio.sleep(60) # Wait before retry on error

    async def refresh_cache(self) -> Dict[str, Any]:
        """Triggers a full update of all cacheable API responses."""
        cache_map = {
            "GET_INTERFACE_STATUS": self.engine.get_interface_status,
            "GET_SYSTEM_HEALTH": self.engine.get_system_health,
            "OPNSENSE_GET_DHCP_LEASES": self.engine.get_dhcp_leases,
            "OPNSENSE_GET_ARP_TABLE": self.engine.get_arp_table,
            "OPNSENSE_GET_ALL_RULES": self.engine.get_all_firewall_rules,
            "OPNSENSE_GET_FIREWALL_STATS": self.engine.get_firewall_stats,
            "OPNSENSE_GET_NAT_POLICIES": self.engine.get_nat_policies,
            "OPNSENSE_GET_DNS_RECORDS": self.engine.get_dns_records,
            "OPNSENSE_GET_ALIASES": self.engine.get_all_aliases,
        }

        results = {}
        for cmd, method in cache_map.items():
            try:
                res = await method()
                # Only cache if the result was a success
                if isinstance(res, dict) and res.get("status") == "SUCCESS":
                    self._cache[cmd] = res
                    results[cmd] = "OK"
                else:
                    results[cmd] = f"Error: {res.get('message') if isinstance(res, dict) else res}"
            except Exception as e:
                logger.error(f"Failed to refresh cache for {cmd}: {e}")
                results[cmd] = f"Exception: {str(e)}"

        return {"status": "SUCCESS", "refreshed": results}

    def _cache_live(self, cmd: str, res: Dict[str, Any]) -> Dict[str, Any]:
        """Store a live-fetched cacheable result so the next call hits the cache
        instead of re-doing the slow live round-trip. Only caches SUCCESS (mirrors
        refresh_cache). Best-effort: returns ``res`` unchanged regardless."""
        if isinstance(res, dict) and res.get("status") == "SUCCESS":
            self._cache[cmd] = res
        return res

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        # Normalize command type to uppercase for case-insensitive matching
        normalized_cmd = command_type.upper()

        # Mask sensitive data for logging — FULL mask. The previous
        # "{v[:4]}...{v[-4:]}" leaked both ends of the credential (8+ chars of
        # an api_key/api_secret exposed in telemetry/SPOKE_LOG relayed to the
        # hub), which is a meaningful fraction of a typical OPNsense API secret.
        _SENSITIVE = {"api_key", "api_secret", "password"}
        log_data = {
            k: ("********" if k in _SENSITIVE else v)
            for k, v in data.items()
        } if isinstance(data, dict) else data

        logger.info(f"Handling Opn Command: {command_type} with data {log_data}")

        if normalized_cmd == "UPDATE_CONFIG":
            logger.info(f"Updating OPNsense configuration: {log_data}")
            self.config = data
            # Update engine credentials if they are provided
            if any(k in data for k in ["opn_host", "host", "opn_port", "port", "api_key", "api_secret"]):
                cur_h = self.engine.host.split(':')[0] if ':' in self.engine.host else self.engine.host
                cur_p = self.engine.host.split(':')[1] if ':' in self.engine.host else "8443"
                host = data.get("opn_host") or data.get("host") or cur_h
                port = str(data.get("opn_port") or data.get("port") or cur_p)
                self.engine.host = f"{host}:{port}"
                self.engine.api_key = data.get("api_key", self.engine.api_key)
                self.engine.api_secret = data.get("api_secret", self.engine.api_secret)

            # Update refresh interval and restart loop if provided
            if "refresh_interval" in data:
                new_interval = data.get("refresh_interval")
                if isinstance(new_interval, (int, float)):
                    self._refresh_interval = new_interval
                    logger.info(f"Updating OPNsense refresh interval to {new_interval}s")
                    self._start_refresh_loop()

            return {"status": "SUCCESS", "message": "OPNsense configuration updated from Hub"}

        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if normalized_cmd == "OPNSENSE_REFRESH_CACHE":
            logger.info("Manual OPNsense cache refresh triggered")
            return await self.refresh_cache()

        # Sync path: an explicit ``limit`` on DHCP leases bypasses the
        # (200-capped) cache so the firewall→NetBox discovery sync gets the full
        # lease set. The interactive path sends no limit and gets the capped
        # cached value (LLM payload guard preserved).
        if (normalized_cmd == "OPNSENSE_GET_DHCP_LEASES"
                and isinstance(data, dict) and data.get("limit") is not None):
            try:
                limit = int(data.get("limit", 200))
            except (TypeError, ValueError):
                limit = 200
            return await self.engine.get_dhcp_leases(limit=limit)

        # Check if command is cacheable and has a cached value
        cache_map = {
            "GET_INTERFACE_STATUS": "interface_status",
            "GET_SYSTEM_HEALTH": "system_health",
            "OPNSENSE_GET_DHCP_LEASES": "dhcp_leases",
            "OPNSENSE_GET_ARP_TABLE": "arp_table",
            "OPNSENSE_GET_ALL_RULES": "all_rules",
            "OPNSENSE_GET_FIREWALL_STATS": "firewall_stats",
            "OPNSENSE_GET_NAT_POLICIES": "nat_policies",
            "OPNSENSE_GET_DNS_RECORDS": "dns_records",
            "OPNSENSE_GET_ALIASES": "aliases",
        }

        if normalized_cmd in cache_map and normalized_cmd in self._cache:
            logger.info(f"Returning cached data for {normalized_cmd}")
            return self._cache[normalized_cmd]

        if normalized_cmd == "PROBE_API":
            path = data.get("path")
            if not path:
                return {"status": "ERROR", "message": "Missing path for PROBE_API"}
            return await self.engine._request("GET", path)

        if normalized_cmd == "OPNSENSE_ADD_RULE":
            # Data expected: {"rule": {...}}
            return await self.engine.add_firewall_rule(data.get("rule", {}))

        elif normalized_cmd == "OPNSENSE_DEL_RULE":
            # Data expected: {"rule_id": "123"}
            return await self.engine.delete_firewall_rule(data.get("rule_id"))

        elif normalized_cmd == "OPNSENSE_UPDATE_ALIAS":
            # Data expected: {"name": "web_servers", "hosts": ["1.1.1.1", "2.2.2.2"]}
            return await self.engine.manage_alias(data.get("name"), data.get("hosts"), action="update")

        elif normalized_cmd == "GET_INTERFACE_STATUS":
            return self._cache_live(normalized_cmd, await self.engine.get_interface_status())

        elif normalized_cmd == "GET_SYSTEM_HEALTH":
            return self._cache_live(normalized_cmd, await self.engine.get_system_health())

        elif normalized_cmd == "OPNSENSE_GET_RULES_BY_IP":
            return await self.engine.get_rules_for_ip(data.get("ip", ""))

        elif normalized_cmd == "OPNSENSE_CURL_TEST":
            try:
                # Run curl against the OPNsense host
                cmd = ["curl", "-k", f"https://{self.engine.host}/"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return {
                    "status": "SUCCESS",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.returncode
                }
            except Exception as e:
                return {"status": "ERROR", "message": f"Curl test failed: {str(e)}"}
        elif normalized_cmd == "OPNSENSE_GET_DHCP_LEASES":
            return await self.engine.get_dhcp_leases()

        elif normalized_cmd == "OPNSENSE_GET_ARP_TABLE":
            return self._cache_live(normalized_cmd, await self.engine.get_arp_table())

        elif normalized_cmd == "OPNSENSE_GET_ALL_RULES":
            return self._cache_live(normalized_cmd, await self.engine.get_all_firewall_rules())

        elif normalized_cmd == "OPNSENSE_GET_FIREWALL_STATS":
            return self._cache_live(normalized_cmd, await self.engine.get_firewall_stats())

        elif normalized_cmd == "OPNSENSE_GET_NAT_POLICIES":
            return self._cache_live(normalized_cmd, await self.engine.get_nat_policies())

        elif normalized_cmd == "OPNSENSE_GET_DNS_RECORDS":
            return self._cache_live(normalized_cmd, await self.engine.get_dns_records())

        elif normalized_cmd == "OPNSENSE_GET_ALIASES":
            return self._cache_live(normalized_cmd, await self.engine.get_all_aliases())

        elif normalized_cmd == "OPNSENSE_ADD_ALIAS":
            return await self.engine.add_alias(
                data.get("name", ""),
                data.get("type", "host"),
                data.get("content", ""),
                data.get("description", ""),
                data.get("category", "")
            )

        elif normalized_cmd == "OPNSENSE_DEL_ALIAS":
            return await self.engine.delete_alias(data.get("uuid", ""))

        elif normalized_cmd == "OPNSENSE_ADD_RULE":
            return await self.engine.add_firewall_rule_and_apply(data.get("rule", {}))

        elif normalized_cmd == "OPNSENSE_DEL_RULE":
            return await self.engine.delete_firewall_rule_and_apply(data.get("rule_id", ""))

        elif normalized_cmd == "OPNSENSE_ADD_NAT_RULE":
            return await self.engine.add_nat_rule(
                data.get("nat_type", "d_nat"),
                data.get("rule", {})
            )

        elif normalized_cmd == "OPNSENSE_DEL_NAT_RULE":
            return await self.engine.delete_nat_rule(
                data.get("nat_type", "d_nat"),
                data.get("uuid", "")
            )

        elif normalized_cmd == "OPNSENSE_ADD_DNS_RECORD":
            return await self.engine.add_dns_record(
                data.get("hostname", ""),
                data.get("domain", ""),
                data.get("ip", ""),
                data.get("description", "")
            )

        elif normalized_cmd == "OPNSENSE_DEL_DNS_RECORD":
            return await self.engine.delete_dns_record(data.get("uuid", ""))

        elif normalized_cmd == "OPNSENSE_EDIT_RULE":
            return await self.engine.edit_firewall_rule(
                data.get("uuid", ""),
                data.get("rule", {})
            )

        elif normalized_cmd == "OPNSENSE_EDIT_ALIAS":
            return await self.engine.edit_alias(
                data.get("uuid", ""),
                data.get("name", ""),
                data.get("type", "host"),
                data.get("content", ""),
                data.get("description", ""),
                data.get("category", "")
            )

        elif normalized_cmd == "OPNSENSE_EDIT_NAT_RULE":
            return await self.engine.edit_nat_rule(
                data.get("nat_type", "d_nat"),
                data.get("uuid", ""),
                data.get("rule", {})
            )

        elif normalized_cmd == "OPNSENSE_EDIT_DNS_RECORD":
            return await self.engine.edit_dns_record(
                data.get("uuid", ""),
                data.get("hostname", ""),
                data.get("domain", ""),
                data.get("ip", ""),
                data.get("description", "")
            )

        elif normalized_cmd == "SEARCH_DHCP":
            # Search DHCP leases by IP, MAC, or hostname fragment
            q = data.get("q", "").strip().lower()
            leases_r = await self.engine.get_dhcp_leases()
            if leases_r.get("status") != "SUCCESS":
                return {"status": "SUCCESS", "results": [], "count": 0}
            matches = []
            for lease in leases_r.get("data", []):
                if (q in (lease.get("ip") or "").lower() or
                        q in (lease.get("mac") or "").lower() or
                        q in (lease.get("hostname") or "").lower()):
                    matches.append({
                        "source":   "opnsense",
                        "type":     "dhcp_lease",
                        "name":     lease.get("hostname", ""),
                        "ip":       lease.get("ip", ""),
                        "mac":      lease.get("mac", ""),
                        "lease_end": lease.get("lease_end", ""),
                        "id":       lease.get("ip", ""),
                    })
            return {"status": "SUCCESS", "results": matches, "count": len(matches)}

        else:
            logger.warning(f"Unknown Opn command type: {command_type}")
            return {"status": "ERROR", "message": f"Command {command_type} not supported by opnsense module"}

    async def get_status(self) -> Dict[str, Any]:
        """Native LM status report for the OPNsense instance."""
        health = await self.engine.get_system_health()
        return {
            "spoke_id": self.spoke_id,
            "module": "opnsense-mgmt",
            "system_health": health,
            "connection": "CONNECTED" if health.get("status") == "SUCCESS" else "DISCONNECTED"
        }

    def get_version(self) -> str:
        """Returns the current version of the OPNsense module (from the VERSION file)."""
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"